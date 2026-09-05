pub(super) struct PublicTransferLease {
    lease_token: String,
    armed: bool,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    database: Database,
    client_ip: Option<String>,
}

pub(super) struct PendingReservationOwnership<T> {
    outcome: T,
    ownership_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<T: Copy> PendingReservationOwnership<T> {
    pub(super) fn outcome(&self) -> T {
        self.outcome
    }

    pub(super) fn claim(mut self) {
        if let Some(sender) = self.ownership_sender.take() {
            let _ = sender.send(());
        }
    }
}

impl PublicTransferLease {
    pub(super) fn new(
        database: Database,
        lease_token: String,
        _cookie: String,
        heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
        client_ip: Option<String>,
    ) -> Self {
        Self {
            lease_token,
            armed: true,
            heartbeat_stop,
            database,
            client_ip,
        }
    }

    /// Explicitly consumes a lease that cannot be handed to a response body.
    /// Drop remains the cancellation backstop for request cancellation.
    pub(super) async fn cancel(mut self) {
        self.heartbeat_stop.take();
        let lease_token = self.lease_token.clone();
        let cancellation_database = self.database.clone();
        if transfer_database(cancellation_database, move |database| {
            database.cancel_transfer_lease(&lease_token).map(|_| ())
        })
        .await
        .is_ok()
        {
            self.armed = false;
        }
    }

    fn into_stream_parts(
        mut self,
    ) -> (
        String,
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<String>,
    ) {
        let lease_token = std::mem::take(&mut self.lease_token);
        self.armed = false;
        let heartbeat_stop = self.heartbeat_stop.take();
        let client_ip = self.client_ip.take();
        (lease_token, heartbeat_stop, client_ip)
    }
}

impl Drop for PublicTransferLease {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if self.armed {
            self.armed = false;
            spawn_transfer_cancel(&self.database, std::mem::take(&mut self.lease_token));
        }
    }
}

pub(super) async fn begin_transfer_lease_cancellation_safe(
    database: Database,
    session_token: String,
    lease_token: String,
    share_id: i64,
    resource_key: String,
    action: &'static str,
) -> Result<PendingReservationOwnership<TransferLeaseBeginOutcome>> {
    let queue_started = std::time::Instant::now();
    let permit =
        transfer_database_runtime_permit(&database, "transfer_lease_begin", queue_started).await?;
    let (outcome_sender, outcome_receiver) = tokio::sync::oneshot::channel();
    let (ownership_sender, ownership_receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let outcome = database.begin_transfer_lease(
            &session_token,
            &lease_token,
            share_id,
            &resource_key,
            action,
        );
        let reserved = matches!(
            outcome,
            Ok(TransferLeaseBeginOutcome::NewLease) | Ok(TransferLeaseBeginOutcome::AlreadyCounted)
        );
        if outcome_sender.send(outcome).is_err() {
            if reserved {
                let _ = database.cancel_transfer_lease(&lease_token);
            }
            return;
        }
        if reserved && ownership_receiver.blocking_recv().is_err() {
            // The async receiver disappeared after SQLite committed but before
            // a PublicTransferLease could take ownership. Cancel synchronously
            // in this already-blocking worker so no detached lease survives.
            let _ = database.cancel_transfer_lease(&lease_token);
        }
    });
    let outcome = outcome_receiver
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebTransferLeaseBeginChannel,
                error,
            ))
        })?
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebTransferLeaseBeginDatabase,
                error,
            ))
        })?;
    Ok(PendingReservationOwnership {
        outcome,
        ownership_sender: Some(ownership_sender),
    })
}

pub(super) fn transfer_complete_future(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
    Box::pin(async move {
        let queue_started = std::time::Instant::now();
        let permit =
            transfer_database_runtime_permit(&database, "transfer_complete", queue_started)
                .await
                .map_err(|_| io::Error::other("database completion admission unavailable"))?;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            database.complete_transfer_lease_and_audit(
                &lease_token,
                &AuditContext::new("public", client_ip),
                action,
                share_id,
            )
        })
        .await
        .map_err(|error| {
            let _reported =
                report_internal(InternalOperation::WebTransferCompleteWorkerJoin, error);
            io::Error::other("transfer completion worker failed")
        })?;
        match result {
            Ok(TransferLeaseCompleteOutcome::Counted)
            | Ok(TransferLeaseCompleteOutcome::AlreadyCounted) => {}
            Ok(TransferLeaseCompleteOutcome::NotFound) => {
                let _reported =
                    report_invariant(InternalOperation::WebTransferCompleteLeaseInvariant);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "public transfer lease expired before completion",
                ));
            }
            Err(error) => {
                let _reported =
                    report_internal(InternalOperation::WebTransferCompleteDatabase, error);
                return Err(io::Error::other("public transfer lease completion failed"));
            }
        }
        Ok(())
    })
}

pub(super) fn spawn_transfer_cancel(database: &Database, lease_token: String) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    database.enqueue_transfer_lease_cleanup(&handle, lease_token);
}
