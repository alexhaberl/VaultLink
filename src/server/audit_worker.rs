async fn wait_for_cleanup_shutdown(
    shutdown: impl Future<Output = Result<(), tokio::task::JoinError>>,
    timeout: Duration,
) -> io::Result<()> {
    match tokio::time::timeout(timeout, shutdown).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(io::Error::other(format!(
            "storage cleanup worker failed during shutdown: {error}"
        ))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "storage cleanup worker exceeded its shutdown deadline",
        )),
    }
}

fn start_audit_retention_worker(database: Database) {
    tokio::spawn(async move {
        loop {
            let worker_database = database.clone();
            let queue_started = std::time::Instant::now();
            let permit = match worker_database.acquire_runtime_permit().await {
                Ok(permit) => permit,
                Err(error) => {
                    tracing::error!(%error, "audit retention database admission closed");
                    break;
                }
            };
            let queue_duration_ms =
                u64::try_from(queue_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let operation_started = std::time::Instant::now();
                let outcome = worker_database.cleanup_audit_retention();
                tracing::debug!(
                    operation = "database.audit_retention",
                    queue_duration_ms,
                    operation_duration_ms =
                        u64::try_from(operation_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    "database operation completed"
                );
                outcome
            })
            .await
            {
                Ok(Ok(outcome)) => log_audit_retention_outcome(outcome),
                Ok(Err(error)) => tracing::error!(%error, "audit retention cleanup failed"),
                Err(error) => tracing::error!(%error, "audit retention worker failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        }
    });
}

fn log_audit_retention_outcome(outcome: AuditRetentionOutcome) {
    if outcome.security_deleted > 0 {
        tracing::warn!(
            routine_deleted = outcome.routine_deleted,
            security_deleted = outcome.security_deleted,
            "audit retention removed security-priority events"
        );
    } else if outcome.routine_deleted > 0 {
        tracing::info!(
            routine_deleted = outcome.routine_deleted,
            "excess routine audit events removed"
        );
    }
}
