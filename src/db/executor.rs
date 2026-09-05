use super::Database;
use std::{error::Error, fmt, time::Duration};

const DATABASE_EXECUTOR_QUEUE_TIMEOUT: Duration = Duration::from_secs(1);

/// Transport-neutral admission failure produced before a database task starts.
///
/// The class and elapsed queue time are retained so an adapter can preserve
/// the existing overload telemetry without the database layer choosing an HTTP
/// response.
#[derive(Debug)]
pub(crate) struct DatabaseExecutorAdmission {
    class: &'static str,
    queue_duration: Duration,
}

impl DatabaseExecutorAdmission {
    pub(crate) fn class(&self) -> &'static str {
        self.class
    }

    pub(crate) fn queue_duration(&self) -> Duration {
        self.queue_duration
    }
}

impl fmt::Display for DatabaseExecutorAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("database executor capacity unavailable")
    }
}

impl Error for DatabaseExecutorAdmission {}

/// Failures that can occur around, rather than inside, a database operation.
/// The operation error stays generic so neither services nor the executor need
/// to depend on an HTTP error type.
#[derive(Debug)]
pub(crate) enum DatabaseExecutionError<E> {
    Admission(DatabaseExecutorAdmission),
    Join(tokio::task::JoinError),
    Operation(E),
}

/// Runs synchronous database work behind the fair per-database semaphore.
///
/// The permit is moved into the blocking task. Dropping the request future can
/// therefore never admit replacement work while SQLite is still running.
pub(crate) async fn execute_database_operation<T, E, F>(
    database: Database,
    class: &'static str,
    operation: F,
) -> Result<T, DatabaseExecutionError<E>>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<T, E> + Send + 'static,
{
    let queue_started = std::time::Instant::now();
    let permit = tokio::time::timeout(
        DATABASE_EXECUTOR_QUEUE_TIMEOUT,
        database.acquire_runtime_permit(),
    )
    .await
    .map_err(|_| admission(class, queue_started.elapsed()))?
    .map_err(|_| admission(class, queue_started.elapsed()))?;

    execute_admitted_database_operation(database, class, queue_started.elapsed(), permit, operation)
        .await
}

/// Runs a synchronous transfer write after serializing writers ahead of the
/// general database queue. A single timeout covers both admission stages.
pub(crate) async fn execute_transfer_database_operation<T, E, F>(
    database: Database,
    class: &'static str,
    operation: F,
) -> Result<T, DatabaseExecutionError<E>>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<T, E> + Send + 'static,
{
    let queue_started = std::time::Instant::now();
    let permit = tokio::time::timeout(
        DATABASE_EXECUTOR_QUEUE_TIMEOUT,
        database.acquire_transfer_runtime_permit(),
    )
    .await
    .map_err(|_| admission(class, queue_started.elapsed()))?
    .map_err(|_| admission(class, queue_started.elapsed()))?;

    execute_admitted_database_operation(database, class, queue_started.elapsed(), permit, operation)
        .await
}

async fn execute_admitted_database_operation<T, E, F, P>(
    database: Database,
    class: &'static str,
    queue_duration: Duration,
    permit: P,
    operation: F,
) -> Result<T, DatabaseExecutionError<E>>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<T, E> + Send + 'static,
    P: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let operation_started = std::time::Instant::now();
        let result = operation(database);
        tracing::debug!(
            operation = "database.executor",
            class,
            queue_duration_ms = duration_millis(queue_duration),
            operation_duration_ms = duration_millis(operation_started.elapsed()),
            "database operation completed"
        );
        result
    })
    .await
    .map_err(DatabaseExecutionError::Join)?
    .map_err(DatabaseExecutionError::Operation)
}

fn admission<E>(class: &'static str, queue_duration: Duration) -> DatabaseExecutionError<E> {
    DatabaseExecutionError::Admission(DatabaseExecutorAdmission {
        class,
        queue_duration,
    })
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
