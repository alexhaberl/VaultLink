use super::Database;
use std::{error::Error, fmt, time::Duration};

/// Transport-neutral admission failure produced before a database task starts.
///
/// The class and elapsed queue time are retained so an adapter can preserve
/// the existing overload telemetry without the database layer choosing an HTTP
/// response.
#[derive(Debug)]
pub(crate) struct DatabaseExecutorAdmission {
    class: &'static str,
    queue_duration: Duration,
    state: super::DatabaseAdmissionState,
}

impl DatabaseExecutorAdmission {
    pub(super) fn new(database: &Database, class: &'static str, queue_duration: Duration) -> Self {
        Self {
            class,
            queue_duration,
            state: database.runtime_admission_state(),
        }
    }

    pub(crate) fn class(&self) -> &'static str {
        self.class
    }

    pub(crate) fn queue_duration(&self) -> Duration {
        self.queue_duration
    }

    pub(crate) fn state(&self) -> super::DatabaseAdmissionState {
        self.state
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

/// Queues synchronous database work behind the fair per-database semaphore.
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
    super::dispatch_database_work(database, class, move |database, permit| {
        let _permit = permit;
        operation(database)
    })
    .await
    .map_err(DatabaseExecutionError::Admission)?
    .await
    .map_err(DatabaseExecutionError::Join)?
    .map_err(DatabaseExecutionError::Operation)
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
    super::dispatch_transfer_database_work(database, class, move |database, permit| {
        let _permit = permit;
        operation(database)
    })
    .await
    .map_err(DatabaseExecutionError::Admission)?
    .await
    .map_err(DatabaseExecutionError::Join)?
    .map_err(DatabaseExecutionError::Operation)
}
