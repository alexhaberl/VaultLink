use crate::{
    db::{AuditContext, Audited, MfaMutationContext, SessionBound},
    file_ops::{
        self, CreateDirectoryResult, DeleteInspection, DeleteResult, FileOperationError,
        RenameResult, RequiredAuditFileOutcome,
    },
    services::error::{ServiceError, ServiceFailure},
    AppState,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FileValidationError {
    InvalidPath,
    InvalidName,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FileConflict {
    DestinationExists,
    ConfirmationRequired { required_name: String },
}

pub(crate) type FileServiceError = ServiceError<FileValidationError, FileConflict>;

/// The only non-audited success exposed by the file service is the explicit
/// compatibility outcome for a filesystem mutation whose required-audit
/// commit became indeterminate after the namespace change was visible.
pub(crate) enum FileMutationError<T> {
    Service(FileServiceError),
    AuditUncertain(SessionBound<T>),
}

pub(crate) type FileMutationResult<T> = Result<SessionBound<Audited<T>>, FileMutationError<T>>;

/// Transport-neutral entry point for audited filesystem mutations.
///
/// Axum handlers only extract paths, confirmation values, and the audit actor;
/// journal/recovery semantics and the non-retryable uncertainty outcome remain
/// inside this service and `file_ops`.
#[derive(Clone)]
pub(crate) struct FileService {
    state: AppState,
}

impl FileService {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }

    pub(crate) async fn create_directory(
        &self,
        authorization: MfaMutationContext,
        parent: &str,
        name: &str,
        audit_client_ip: Option<String>,
    ) -> FileMutationResult<CreateDirectoryResult> {
        let actor = authorization.username.clone();
        let (_, proof) = authorization.into_parts();
        let audit_context = AuditContext::new(actor, audit_client_ip);
        map_file_mutation(
            file_ops::create_directory(&self.state, proof, parent, name, audit_context).await,
        )
    }

    pub(crate) async fn rename(
        &self,
        authorization: MfaMutationContext,
        path: &str,
        new_name: &str,
        audit_client_ip: Option<String>,
    ) -> FileMutationResult<RenameResult> {
        let actor = authorization.username.clone();
        let (_, proof) = authorization.into_parts();
        let audit_context = AuditContext::new(actor, audit_client_ip);
        map_file_mutation(file_ops::rename(&self.state, proof, path, new_name, audit_context).await)
    }

    pub(crate) async fn inspect_delete(
        &self,
        path: &str,
    ) -> Result<DeleteInspection, FileServiceError> {
        file_ops::inspect_delete(&self.state, path)
            .await
            .map_err(map_file_operation_error)
    }

    pub(crate) async fn delete(
        &self,
        authorization: MfaMutationContext,
        path: &str,
        confirmation: Option<&str>,
        audit_client_ip: Option<String>,
    ) -> FileMutationResult<DeleteResult> {
        let actor = authorization.username.clone();
        let (_, proof) = authorization.into_parts();
        let audit_context = AuditContext::new(actor, audit_client_ip);
        map_file_mutation(
            file_ops::delete(&self.state, proof, path, confirmation, audit_context).await,
        )
    }
}

fn map_file_mutation<T>(
    outcome: Result<RequiredAuditFileOutcome<T>, FileOperationError>,
) -> FileMutationResult<T> {
    match outcome {
        Ok(RequiredAuditFileOutcome::Audited(outcome)) => Ok(outcome),
        Ok(RequiredAuditFileOutcome::Uncertain(outcome)) => {
            Err(FileMutationError::AuditUncertain(outcome))
        }
        Err(error) => Err(FileMutationError::Service(map_file_operation_error(error))),
    }
}

fn map_file_operation_error(error: FileOperationError) -> FileServiceError {
    match error {
        FileOperationError::InvalidPath => {
            FileServiceError::Validation(FileValidationError::InvalidPath)
        }
        FileOperationError::InvalidName => {
            FileServiceError::Validation(FileValidationError::InvalidName)
        }
        FileOperationError::NotFound => FileServiceError::NotFound,
        FileOperationError::Conflict => FileServiceError::Conflict(FileConflict::DestinationExists),
        FileOperationError::ConfirmationRequired { required_name } => {
            FileServiceError::Conflict(FileConflict::ConfirmationRequired { required_name })
        }
        FileOperationError::Database(error) => FileServiceError::from_database(error),
        FileOperationError::DatabaseCapacity => FileServiceError::Capacity(ServiceFailure::new(
            std::io::Error::other("database executor capacity unavailable"),
        )),
        FileOperationError::Io(error) => FileServiceError::internal(error),
        FileOperationError::Join(error) => FileServiceError::internal(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_and_uncertain_mutations_remain_distinct_at_service_boundary() {
        let database = crate::db::Database::open(":memory:").unwrap();
        let audited = database
            .required_transaction_audited(&AuditContext::system(), |_transaction| {
                Ok((
                    CreateDirectoryResult {
                        path: "durable".into(),
                        audit_durability: file_ops::AuditDurability::Durable,
                    },
                    vec![crate::db::RequiredAuditEvent::new(
                        crate::db::AuditAction::DirectoryCreated,
                        Some("durable".into()),
                        None,
                    )],
                ))
            })
            .unwrap();
        let durable = map_file_mutation(Ok(RequiredAuditFileOutcome::Audited(
            SessionBound::Authorized(audited),
        )));
        let Ok(durable) = durable else {
            panic!("database proof must remain on the successful service path");
        };
        let durable = crate::db::release_session_audited(durable);
        assert!(matches!(durable, SessionBound::Authorized(_)));

        let uncertain = map_file_mutation(Ok(RequiredAuditFileOutcome::Uncertain(
            SessionBound::Authorized(CreateDirectoryResult {
                path: "uncertain".into(),
                audit_durability: file_ops::AuditDurability::Uncertain,
            }),
        )));
        assert!(matches!(
            uncertain,
            Err(FileMutationError::AuditUncertain(SessionBound::Authorized(
                _
            )))
        ));
    }

    #[test]
    fn file_operation_failures_are_reduced_to_service_categories() {
        assert!(matches!(
            map_file_operation_error(FileOperationError::InvalidPath),
            FileServiceError::Validation(FileValidationError::InvalidPath)
        ));
        assert!(matches!(
            map_file_operation_error(FileOperationError::NotFound),
            FileServiceError::NotFound
        ));
        assert!(matches!(
            map_file_operation_error(FileOperationError::DatabaseCapacity),
            FileServiceError::Capacity(_)
        ));
    }
}
