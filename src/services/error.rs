use std::{error::Error, fmt};

/// Transport-neutral failure categories exposed by domain services.
///
/// Concrete infrastructure errors stay behind [`ServiceFailure`].  HTTP
/// adapters can therefore select their compatibility response without
/// coupling their public error contract to SQLite, Tokio, or filesystem error
/// types.
#[derive(Debug)]
pub(crate) enum ServiceError<V, C = ()> {
    Validation(V),
    NotFound,
    Conflict(C),
    Capacity(ServiceFailure),
    AuditUnavailable(ServiceFailure),
    Internal(ServiceFailure),
}

/// Opaque ownership wrapper for an infrastructure failure.
///
/// The source is retained until the request boundary consumes the error, but
/// neither `Debug` nor `Display` serializes it. `report_internal` records only
/// this wrapper's type, so SQL values, paths, and secrets cannot reach logs.
pub(crate) struct ServiceFailure {
    _source: Box<dyn Error + Send + Sync + 'static>,
    executor_context: Option<DatabaseExecutorFailureContext>,
}

impl ServiceFailure {
    pub(super) fn new(error: impl Error + Send + Sync + 'static) -> Self {
        Self {
            _source: Box::new(error),
            executor_context: None,
        }
    }

    pub(super) fn database_executor_admission(error: crate::db::DatabaseExecutorAdmission) -> Self {
        let executor_context = Some(DatabaseExecutorFailureContext::Admission {
            class: error.class(),
            queue_duration: error.queue_duration(),
        });
        Self {
            _source: Box::new(error),
            executor_context,
        }
    }

    pub(super) fn database_executor_join(
        class: &'static str,
        error: tokio::task::JoinError,
    ) -> Self {
        Self {
            _source: Box::new(error),
            executor_context: Some(DatabaseExecutorFailureContext::Join { class }),
        }
    }

    pub(crate) fn database_executor_admission_context(
        &self,
    ) -> Option<(&'static str, std::time::Duration)> {
        match self.executor_context {
            Some(DatabaseExecutorFailureContext::Admission {
                class,
                queue_duration,
            }) => Some((class, queue_duration)),
            None | Some(DatabaseExecutorFailureContext::Join { .. }) => None,
        }
    }

    pub(crate) fn database_executor_join_class(&self) -> Option<&'static str> {
        match self.executor_context {
            Some(DatabaseExecutorFailureContext::Join { class }) => Some(class),
            None | Some(DatabaseExecutorFailureContext::Admission { .. }) => None,
        }
    }
}

#[derive(Clone, Copy)]
enum DatabaseExecutorFailureContext {
    Admission {
        class: &'static str,
        queue_duration: std::time::Duration,
    },
    Join {
        class: &'static str,
    },
}

impl fmt::Debug for ServiceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceFailure([REDACTED])")
    }
}

impl fmt::Display for ServiceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("internal service failure")
    }
}

impl Error for ServiceFailure {}

impl<V, C> ServiceError<V, C> {
    pub(super) fn from_database(error: rusqlite::Error) -> Self {
        if crate::db::is_audit_unavailable(&error) {
            Self::AuditUnavailable(ServiceFailure::new(error))
        } else if crate::db::is_sqlite_busy_or_locked(&error) {
            Self::Capacity(ServiceFailure::new(error))
        } else {
            Self::Internal(ServiceFailure::new(error))
        }
    }

    pub(super) fn from_database_with_conflict(error: rusqlite::Error, conflict: C) -> Self {
        if crate::db::is_sqlite_unique_constraint(&error) {
            Self::Conflict(conflict)
        } else {
            Self::from_database(error)
        }
    }

    pub(super) fn internal(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Internal(ServiceFailure::new(error))
    }
}

/// Converts infrastructure results at a service boundary without exposing
/// their concrete error type in the service's return signature.
pub(crate) trait IntoServiceError<V, C = ()> {
    fn into_service_error(self) -> ServiceError<V, C>;
}

impl<V, C> IntoServiceError<V, C> for ServiceError<V, C> {
    fn into_service_error(self) -> ServiceError<V, C> {
        self
    }
}

impl<V, C> IntoServiceError<V, C> for rusqlite::Error {
    fn into_service_error(self) -> ServiceError<V, C> {
        ServiceError::from_database(self)
    }
}

#[derive(Debug)]
pub(super) struct ServiceInvariant;

impl fmt::Display for ServiceInvariant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("service invariant violated")
    }
}

impl Error for ServiceInvariant {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infrastructure_causes_are_opaque() {
        let error = ServiceFailure::new(rusqlite::Error::InvalidQuery);
        assert_eq!(format!("{error}"), "internal service failure");
        assert_eq!(format!("{error:?}"), "ServiceFailure([REDACTED])");
        assert!(error.source().is_none());
    }

    #[test]
    fn database_failures_have_stable_categories() {
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        );
        assert!(matches!(
            ServiceError::<(), ()>::from_database(busy),
            ServiceError::Capacity(_)
        ));

        let unique = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
            None,
        );
        assert!(matches!(
            ServiceError::<(), _>::from_database_with_conflict(unique, "duplicate"),
            ServiceError::Conflict("duplicate")
        ));
    }
}
