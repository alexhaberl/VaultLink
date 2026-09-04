use std::{future::Future, pin::Pin};

use tracing::Instrument as _;

use crate::{
    auth,
    db::{
        AuditContext, Database, Share, TransferAvailabilityOutcome, TransferLeaseBeginOutcome,
        TransferLeaseCompleteOutcome,
    },
    internal_reporting::{report_internal, report_invariant, InternalOperation},
    state::ShareActivityPermit,
};

use super::{prepare::run_database_read, PublicTransferError, PublicTransferService};

pub(crate) struct PublicTransferClient {
    pub(crate) client_key: String,
    pub(crate) session_token: Option<String>,
    pub(crate) audit_client_ip: Option<String>,
}

pub(crate) struct PublicTransferLease {
    lease_token: String,
    armed: bool,
    session_token: String,
    heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
    database: Database,
    client_ip: Option<String>,
    share_admission: Option<ShareActivityPermit>,
}

struct PendingLeaseOwnership {
    outcome: TransferLeaseBeginOutcome,
    ownership_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PendingLeaseOwnership {
    fn claim(mut self) {
        if let Some(sender) = self.ownership_sender.take() {
            let _ = sender.send(());
        }
    }
}

impl PublicTransferLease {
    pub(crate) fn new(
        database: Database,
        lease_token: String,
        session_token: String,
        heartbeat_stop: Option<tokio::sync::oneshot::Sender<()>>,
        client_ip: Option<String>,
    ) -> Self {
        Self {
            lease_token,
            armed: true,
            session_token,
            heartbeat_stop,
            database,
            client_ip,
            share_admission: None,
        }
    }

    fn with_share_admission(mut self, permit: ShareActivityPermit) -> Self {
        self.share_admission = Some(permit);
        self
    }

    pub(crate) fn session_token(&self) -> &str {
        &self.session_token
    }

    pub(crate) async fn cancel(mut self) {
        self.heartbeat_stop.take();
        let lease_token = self.lease_token.clone();
        let cancellation_database = self.database.clone();
        if run_database_read(cancellation_database, move |database| {
            database.cancel_transfer_lease(&lease_token).map(|_| ())
        })
        .await
        .is_ok()
        {
            self.armed = false;
        }
    }

    pub(super) fn into_stream_parts(
        mut self,
    ) -> (
        String,
        Option<tokio::sync::oneshot::Sender<()>>,
        Option<String>,
        Option<ShareActivityPermit>,
    ) {
        let lease_token = std::mem::take(&mut self.lease_token);
        self.armed = false;
        (
            lease_token,
            self.heartbeat_stop.take(),
            self.client_ip.take(),
            self.share_admission.take(),
        )
    }
}

impl Drop for PublicTransferLease {
    fn drop(&mut self) {
        self.heartbeat_stop.take();
        if self.armed {
            self.armed = false;
            spawn_transfer_cancel(self.database.clone(), std::mem::take(&mut self.lease_token));
        }
    }
}

impl PublicTransferService {
    pub(crate) async fn begin(
        &self,
        share: &Share,
        client: PublicTransferClient,
        resource_key: String,
        action: &'static str,
    ) -> Result<PublicTransferLease, PublicTransferError> {
        if !self
            .state()
            .public_transfer_limiter()
            .check_and_record_attempt(&format!(
                "public-transfer:{}:{}",
                share.id, client.client_key
            ))
        {
            return Err(PublicTransferError::RateLimited);
        }
        let share_admission = self
            .state()
            .try_acquire_stream_share(share.id)
            .ok_or(PublicTransferError::ConcurrentDownloads)?;
        let session_token = client
            .session_token
            .unwrap_or_else(|| auth::random_token(32));
        let lease_token = auth::random_token(32);
        let pending = begin_transfer_lease_cancellation_safe(
            self.state().db().clone(),
            session_token.clone(),
            lease_token.clone(),
            share.id,
            resource_key,
            action,
        )
        .await?;
        match pending.outcome {
            TransferLeaseBeginOutcome::NewLease | TransferLeaseBeginOutcome::AlreadyCounted => {
                let heartbeat_stop = start_transfer_heartbeat(
                    self.state().db().clone(),
                    lease_token.clone(),
                    action,
                    share.id,
                    client.audit_client_ip.clone(),
                );
                let lease = PublicTransferLease::new(
                    self.state().db().clone(),
                    lease_token,
                    session_token,
                    heartbeat_stop,
                    client.audit_client_ip,
                )
                .with_share_admission(share_admission);
                pending.claim();
                Ok(lease)
            }
            TransferLeaseBeginOutcome::LimitReached => {
                Err(PublicTransferError::TransferLimitReached)
            }
            TransferLeaseBeginOutcome::ShareUnavailable => {
                Err(PublicTransferError::TransferShareUnavailable)
            }
        }
    }

    pub(crate) async fn check_availability(
        &self,
        share: &Share,
        session_token: Option<String>,
        resource_key: String,
        action: &'static str,
    ) -> Result<(), PublicTransferError> {
        let session_token = session_token.unwrap_or_else(|| auth::random_token(32));
        let share_id = share.id;
        let outcome = run_database_read(self.state().db().clone(), move |database| {
            database.check_transfer_availability(&session_token, share_id, &resource_key, action)
        })
        .await?;
        match outcome {
            TransferAvailabilityOutcome::Available
            | TransferAvailabilityOutcome::AlreadyCounted => Ok(()),
            TransferAvailabilityOutcome::LimitReached => {
                Err(PublicTransferError::TransferLimitReached)
            }
            TransferAvailabilityOutcome::ShareUnavailable => {
                Err(PublicTransferError::TransferShareUnavailable)
            }
        }
    }
}

async fn begin_transfer_lease_cancellation_safe(
    database: Database,
    session_token: String,
    lease_token: String,
    share_id: i64,
    resource_key: String,
    action: &'static str,
) -> Result<PendingLeaseOwnership, PublicTransferError> {
    let permit = acquire_database_permit(&database).await?;
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
            Ok(TransferLeaseBeginOutcome::NewLease | TransferLeaseBeginOutcome::AlreadyCounted)
        );
        if outcome_sender.send(outcome).is_err() {
            if reserved {
                let _ = database.cancel_transfer_lease(&lease_token);
            }
            return;
        }
        if reserved && ownership_receiver.blocking_recv().is_err() {
            let _ = database.cancel_transfer_lease(&lease_token);
        }
    });
    let outcome = outcome_receiver
        .await
        .map_err(|error| {
            PublicTransferError::Internal(report_internal(
                InternalOperation::WebTransferLeaseBeginChannel,
                error,
            ))
        })?
        .map_err(database_error)?;
    Ok(PendingLeaseOwnership {
        outcome,
        ownership_sender: Some(ownership_sender),
    })
}

fn start_transfer_heartbeat(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Option<tokio::sync::oneshot::Sender<()>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let (stop_sender, mut stop_receiver) = tokio::sync::oneshot::channel();
    let request_span = tracing::Span::current();
    let heartbeat = async move {
        let interval =
            std::time::Duration::from_secs((crate::db::TRANSFER_SESSION_TTL_SECONDS / 3) as u64);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_receiver => break,
                _ = ticker.tick() => {
                    if !heartbeat_once(
                        database.clone(),
                        lease_token.clone(),
                        action,
                        share_id,
                        client_ip.clone(),
                    ).await {
                        break;
                    }
                }
            }
        }
    };
    handle.spawn(heartbeat.instrument(request_span));
    Some(stop_sender)
}

async fn heartbeat_once(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> bool {
    let Ok(permit) = acquire_database_permit(&database).await else {
        return true;
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        database.heartbeat_transfer_lease_and_audit(
            &lease_token,
            &AuditContext::new("public", client_ip),
        )
    })
    .await
    {
        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::Extended)) => true,
        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::CappedAndCounted)) => {
            tracing::warn!(
                share_id,
                action,
                "public transfer reached its absolute lifetime and was counted"
            );
            false
        }
        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::CappedAlreadyCounted)) => {
            tracing::warn!(
                share_id,
                action,
                "public transfer reached its absolute lifetime"
            );
            false
        }
        Ok(Ok(crate::db::TransferLeaseHeartbeatOutcome::NotFound)) => {
            tracing::warn!("public transfer lease disappeared while the response was active");
            false
        }
        Ok(Err(error)) => {
            let _reported = report_internal(InternalOperation::WebTransferHeartbeatDatabase, error);
            true
        }
        Err(error) => {
            let _reported = report_internal(InternalOperation::WebTransferHeartbeatTaskJoin, error);
            false
        }
    }
}

pub(super) fn transfer_complete_future(
    database: Database,
    lease_token: String,
    action: &'static str,
    share_id: i64,
    client_ip: Option<String>,
) -> Pin<
    Box<dyn Future<Output = Result<(), crate::internal_reporting::ReportedInternalError>> + Send>,
> {
    Box::pin(async move {
        let permit = acquire_database_permit(&database).await.map_err(|error| {
            report_internal(InternalOperation::WebTransferCompleteDatabase, error)
        })?;
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
            report_internal(InternalOperation::WebTransferCompleteWorkerJoin, error)
        })?;
        match result {
            Ok(
                TransferLeaseCompleteOutcome::Counted
                | TransferLeaseCompleteOutcome::AlreadyCounted,
            ) => Ok(()),
            Ok(TransferLeaseCompleteOutcome::NotFound) => Err(report_invariant(
                InternalOperation::WebTransferCompleteLeaseInvariant,
            )),
            Err(error) => Err(report_internal(
                InternalOperation::WebTransferCompleteDatabase,
                error,
            )),
        }
    })
}

pub(super) fn spawn_transfer_cancel(database: Database, lease_token: String) {
    spawn_drop_database_cleanup(database, "transfer_cancel", move |database| {
        let _ = database.cancel_transfer_lease(&lease_token);
    });
}

fn spawn_drop_database_cleanup<F>(database: Database, class: &'static str, cleanup: F)
where
    F: FnOnce(&Database) + Send + 'static,
{
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    match database.try_acquire_runtime_permit() {
        Ok(permit) => drop(handle.spawn_blocking(move || {
            let _permit = permit;
            cleanup(&database);
        })),
        Err(_) => drop(handle.spawn(async move {
            let Ok(permit) = acquire_database_permit(&database).await else {
                return;
            };
            let _ = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                cleanup(&database);
            })
            .await;
            tracing::trace!(class, "public transfer cleanup finished");
        })),
    }
}

async fn acquire_database_permit(
    database: &Database,
) -> Result<tokio::sync::OwnedSemaphorePermit, PublicTransferError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        database.acquire_runtime_permit(),
    )
    .await
    .map_err(|_| PublicTransferError::Capacity)?
    .map_err(|_| PublicTransferError::Capacity)
}

fn database_error(error: rusqlite::Error) -> PublicTransferError {
    if crate::db::is_audit_unavailable(&error) {
        PublicTransferError::AuditUnavailable
    } else if crate::db::is_sqlite_busy_or_locked(&error) {
        PublicTransferError::Capacity
    } else {
        PublicTransferError::Internal(report_internal(
            InternalOperation::WebTransferLeaseBeginDatabase,
            error,
        ))
    }
}
