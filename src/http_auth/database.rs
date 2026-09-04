#[derive(Debug, Clone, Copy)]
pub enum MissingSession {
    RedirectToLogin,
    Unauthorized,
}

#[derive(Debug)]
pub struct HttpAuthError {
    pub status: StatusCode,
    pub message: &'static str,
    pub redirect: Option<&'static str>,
    pub kind: HttpAuthErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAuthErrorKind {
    Request,
    SessionRevoked,
    AuditUnavailable,
    CapacityUnavailable,
    AmbiguousAuthentication,
    InsufficientScope,
}

impl HttpAuthError {
    pub fn status(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            redirect: None,
            kind: HttpAuthErrorKind::Request,
        }
    }

    pub(crate) fn with_kind(
        status: StatusCode,
        message: &'static str,
        kind: HttpAuthErrorKind,
    ) -> Self {
        Self {
            status,
            message,
            redirect: None,
            kind,
        }
    }

    pub fn redirect(location: &'static str) -> Self {
        Self {
            status: StatusCode::SEE_OTHER,
            message: location,
            redirect: Some(location),
            kind: HttpAuthErrorKind::Request,
        }
    }
}
impl From<ReportedInternalError> for HttpAuthError {
    fn from(_: ReportedInternalError) -> Self {
        Self::status(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    }
}

pub type Result<T> = std::result::Result<T, HttpAuthError>;

fn argon2_busy<T>(_: T) -> HttpAuthError {
    HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        ARGON2_BUSY_MESSAGE,
        HttpAuthErrorKind::CapacityUnavailable,
    )
}

pub(crate) async fn hash_password_admitted(
    state: &(impl Borrow<AppState> + ?Sized),
    password: crate::sensitive::SecretString,
) -> Result<String> {
    let state = borrowed_app_state(state);
    let permit = state.try_acquire_argon2().map_err(argon2_busy)?;
    tokio::task::spawn_blocking(move || {
        // Keep the owned permit in the blocking task so cancelling the request
        // cannot release capacity while Argon2 is still consuming CPU and RAM.
        let _permit = permit;
        crate::auth::hash_secret_password(&password)
    })
    .await
    .map_err(|error| {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthArgon2HashJoin,
            error,
        ))
    })?
    .map_err(|error| {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthArgon2HashFailure,
            error,
        ))
    })
}

pub(crate) async fn verify_password_admitted(
    state: &(impl Borrow<AppState> + ?Sized),
    password_hash: Option<String>,
    password: crate::sensitive::SecretString,
) -> Result<bool> {
    let state = borrowed_app_state(state);
    let permit = state.try_acquire_argon2().map_err(argon2_busy)?;
    tokio::task::spawn_blocking(move || {
        // Acquire before branching so known and unknown users receive the same
        // overload response and both paths consume one admitted Argon2 job.
        let _permit = permit;
        match password_hash {
            Some(hash) => crate::auth::verify_secret_password(&hash, &password),
            None => {
                let _ = crate::auth::hash_secret_password(&password);
                false
            }
        }
    })
    .await
    .map_err(|error| {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthArgon2VerifyJoin,
            error,
        ))
    })
}

pub(crate) async fn password_login_admitted(
    state: &(impl Borrow<AppState> + ?Sized),
    command: crate::services::auth::PasswordLoginCommand,
) -> Result<crate::services::auth::PasswordLoginOutcome> {
    let state = borrowed_app_state(state);
    let permit = state.try_acquire_argon2().map_err(argon2_busy)?;
    let database = state.db().clone();
    let queue_started = std::time::Instant::now();
    let database_permit =
        database_runtime_permit(&database, "password_login", queue_started).await?;
    let queue_duration = queue_started.elapsed();
    let service = crate::services::auth::AuthService::new(database);
    tokio::task::spawn_blocking(move || {
        // The complete service operation owns the admitted Argon2 job. Unknown
        // and known accounts therefore share capacity and overload behavior.
        let _permit = permit;
        let _database_permit = database_permit;
        let operation_started = std::time::Instant::now();
        let result = service.login_with_password(command);
        tracing::debug!(
            operation = "database.password_login",
            queue_duration_ms = duration_millis(queue_duration),
            operation_duration_ms = duration_millis(operation_started.elapsed()),
            "database operation completed"
        );
        result
    })
    .await
    .map_err(|error| {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthPasswordLoginJoin,
            error,
        ))
    })?
    .map_err(|error| service_error(error, InternalOperation::HttpAuthDatabaseFailure))
}

pub async fn database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    run_database_operation(
        database,
        "read",
        InternalOperation::HttpAuthDatabaseReadJoin,
        operation,
    )
    .await
}

async fn run_database_operation<T, F>(
    database: Database,
    class: &'static str,
    join_operation: InternalOperation,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
{
    run_typed_database_operation(database, class, join_operation, operation, database_error).await
}

pub(crate) async fn run_typed_database_operation<T, E, F, M>(
    database: Database,
    class: &'static str,
    join_operation: InternalOperation,
    operation: F,
    map_error: M,
) -> Result<T>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> std::result::Result<T, E> + Send + 'static,
    M: FnOnce(E) -> HttpAuthError,
{
    match crate::db::execute_database_operation(database, class, operation).await {
        Ok(value) => Ok(value),
        Err(crate::db::DatabaseExecutionError::Admission(error)) => Err(
            database_capacity_unavailable(error.class(), error.queue_duration()),
        ),
        Err(crate::db::DatabaseExecutionError::Join(error)) => {
            Err(HttpAuthError::from(report_internal(join_operation, error)))
        }
        Err(crate::db::DatabaseExecutionError::Operation(error)) => Err(map_error(error)),
    }
}

pub(crate) async fn service_database<T, V, C, F>(
    database: Database,
    operation: F,
    internal_operation: InternalOperation,
) -> Result<T>
where
    T: Send + 'static,
    V: Send + 'static,
    C: Send + 'static,
    F: FnOnce(Database) -> std::result::Result<T, crate::services::error::ServiceError<V, C>>
        + Send
        + 'static,
{
    run_typed_database_operation(
        database,
        "service",
        InternalOperation::HttpAuthDatabaseReadJoin,
        operation,
        move |error| service_error(error, internal_operation),
    )
    .await
}

pub(crate) async fn required_audited_database<T, F>(database: Database, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<crate::db::Audited<T>> + Send + 'static,
{
    run_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_audit_job(operation),
    )
    .await
}

pub(crate) async fn required_audited_service_database<T, V, C, F>(
    database: Database,
    operation: F,
    internal_operation: InternalOperation,
) -> Result<T>
where
    T: Send + 'static,
    V: Send + 'static,
    C: Send + 'static,
    F: FnOnce(
            Database,
        ) -> std::result::Result<
            crate::db::Audited<T>,
            crate::services::error::ServiceError<V, C>,
        > + Send
        + 'static,
{
    run_typed_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_audit_result_job(operation),
        move |error| service_error(error, internal_operation),
    )
    .await
}

pub(crate) async fn required_audit_decision<T, R, F>(
    database: Database,
    operation: F,
) -> Result<crate::db::RequiredAuditCompletion<T, R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<crate::db::RequiredAuditDecision<T, R>>
        + Send
        + 'static,
{
    run_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_audit_decision_job(operation),
    )
    .await
}

pub(crate) async fn required_session_database<T, F>(
    database: Database,
    operation: F,
) -> Result<SessionBound<T>>
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<SessionBound<crate::db::Audited<T>>> + Send + 'static,
{
    run_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_session_audit_job(operation),
    )
    .await
}

pub(crate) async fn required_session_service_database<T, V, C, F>(
    database: Database,
    operation: F,
    internal_operation: InternalOperation,
) -> Result<SessionBound<T>>
where
    T: Send + 'static,
    V: Send + 'static,
    C: Send + 'static,
    F: FnOnce(
            Database,
        ) -> std::result::Result<
            SessionBound<crate::db::Audited<T>>,
            crate::services::error::ServiceError<V, C>,
        > + Send
        + 'static,
{
    required_session_typed_database(database, operation, move |error| {
        service_error(error, internal_operation)
    })
    .await
}

pub(crate) async fn required_session_typed_database<T, E, F, M>(
    database: Database,
    operation: F,
    map_error: M,
) -> Result<SessionBound<T>>
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> std::result::Result<SessionBound<crate::db::Audited<T>>, E>
        + Send
        + 'static,
    M: FnOnce(E) -> HttpAuthError,
{
    run_typed_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_session_audit_result_job(operation),
        map_error,
    )
    .await
}

pub(crate) async fn required_mfa_audit_database<T, F>(
    database: Database,
    authorization: MfaMutationContext,
    operation: F,
) -> Result<SessionBound<T>>
where
    T: Send + 'static,
    F: FnOnce(
            Database,
            Session,
            MfaSessionProof,
        ) -> rusqlite::Result<SessionBound<crate::db::Audited<T>>>
        + Send
        + 'static,
{
    let (session, proof) = authorization.into_parts();
    required_session_database(database, move |database| {
        operation(database, session, proof)
    })
    .await
}

pub(crate) async fn required_session_service_decision<T, R, V, C, F>(
    database: Database,
    operation: F,
    internal_operation: InternalOperation,
) -> Result<SessionBound<crate::db::RequiredAuditCompletion<T, R>>>
where
    T: Send + 'static,
    R: Send + 'static,
    V: Send + 'static,
    C: Send + 'static,
    F: FnOnce(
            Database,
        ) -> std::result::Result<
            SessionBound<crate::db::RequiredAuditDecision<T, R>>,
            crate::services::error::ServiceError<V, C>,
        > + Send
        + 'static,
{
    required_session_typed_decision(database, operation, move |error| {
        service_error(error, internal_operation)
    })
    .await
}

pub(crate) async fn required_session_typed_decision<T, R, E, F, M>(
    database: Database,
    operation: F,
    map_error: M,
) -> Result<SessionBound<crate::db::RequiredAuditCompletion<T, R>>>
where
    T: Send + 'static,
    R: Send + 'static,
    E: Send + 'static,
    F: FnOnce(
            Database,
        )
            -> std::result::Result<SessionBound<crate::db::RequiredAuditDecision<T, R>>, E>
        + Send
        + 'static,
    M: FnOnce(E) -> HttpAuthError,
{
    run_typed_database_operation(
        database,
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        crate::db::required_session_audit_decision_result_job(operation),
        map_error,
    )
    .await
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) async fn database_runtime_permit(
    database: &Database,
    class: &'static str,
    queue_started: std::time::Instant,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        database.acquire_runtime_permit(),
    )
    .await
    .map_err(|_| database_capacity_unavailable(class, queue_started.elapsed()))?
    .map_err(|_| database_capacity_unavailable(class, queue_started.elapsed()))
}

fn database_capacity_unavailable(
    class: &'static str,
    queue_duration: std::time::Duration,
) -> HttpAuthError {
    tracing::warn!(
        operation = "database.admission",
        class,
        queue_duration_ms = duration_millis(queue_duration),
        "database executor admission timed out"
    );
    HttpAuthError::with_kind(
        StatusCode::SERVICE_UNAVAILABLE,
        DATABASE_BUSY_MESSAGE,
        HttpAuthErrorKind::CapacityUnavailable,
    )
}

pub(crate) fn database_error(error: rusqlite::Error) -> HttpAuthError {
    if crate::db::is_audit_unavailable(&error) {
        tracing::error!(
            operation = "http_auth.database.audit_unavailable",
            error_type = std::any::type_name_of_val(&error),
            "required audit transaction rolled back"
        );
        HttpAuthError::with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            AUDIT_UNAVAILABLE_MESSAGE,
            HttpAuthErrorKind::AuditUnavailable,
        )
    } else if crate::db::is_sqlite_busy_or_locked(&error) {
        tracing::warn!(
            operation = "http_auth.database.sqlite_capacity",
            error_type = std::any::type_name_of_val(&error),
            "database operation timed out waiting for SQLite capacity"
        );
        HttpAuthError::with_kind(
            StatusCode::SERVICE_UNAVAILABLE,
            DATABASE_BUSY_MESSAGE,
            HttpAuthErrorKind::CapacityUnavailable,
        )
    } else {
        HttpAuthError::from(report_internal(
            InternalOperation::HttpAuthDatabaseFailure,
            error,
        ))
    }
}

pub(crate) fn service_error<V, C>(
    error: crate::services::error::ServiceError<V, C>,
    operation: InternalOperation,
) -> HttpAuthError {
    use crate::services::error::ServiceError;

    match error {
        ServiceError::Capacity(cause) => {
            if let Some((class, queue_duration)) = cause.database_executor_admission_context() {
                return database_capacity_unavailable(class, queue_duration);
            }
            tracing::warn!(
                operation = "http_auth.database.sqlite_capacity",
                error_type = "ServiceFailure",
                "database operation timed out waiting for SQLite capacity"
            );
            HttpAuthError::with_kind(
                StatusCode::SERVICE_UNAVAILABLE,
                DATABASE_BUSY_MESSAGE,
                HttpAuthErrorKind::CapacityUnavailable,
            )
        }
        ServiceError::AuditUnavailable(_cause) => {
            tracing::error!(
                operation = "http_auth.database.audit_unavailable",
                error_type = "ServiceFailure",
                "required audit transaction rolled back"
            );
            HttpAuthError::with_kind(
                StatusCode::SERVICE_UNAVAILABLE,
                AUDIT_UNAVAILABLE_MESSAGE,
                HttpAuthErrorKind::AuditUnavailable,
            )
        }
        ServiceError::Internal(cause) => {
            let operation = match cause.database_executor_join_class() {
                Some("required_audit") => InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
                Some(_) => InternalOperation::HttpAuthDatabaseReadJoin,
                None => operation,
            };
            HttpAuthError::from(report_internal(operation, cause))
        }
        ServiceError::Validation(_) | ServiceError::NotFound | ServiceError::Conflict(_) => {
            HttpAuthError::from(report_invariant(operation))
        }
    }
}
