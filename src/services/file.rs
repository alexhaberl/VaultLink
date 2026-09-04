use crate::{
    db::{AuditContext, MfaSessionProof, SessionBound},
    file_ops::{
        self, CreateDirectoryResult, DeleteInspection, DeleteResult, FileOperationError,
        RenameResult,
    },
    AppState,
};

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
        proof: MfaSessionProof,
        parent: &str,
        name: &str,
        audit_context: AuditContext,
    ) -> Result<SessionBound<CreateDirectoryResult>, FileOperationError> {
        file_ops::create_directory(&self.state, proof, parent, name, audit_context).await
    }

    pub(crate) async fn rename(
        &self,
        proof: MfaSessionProof,
        path: &str,
        new_name: &str,
        audit_context: AuditContext,
    ) -> Result<SessionBound<RenameResult>, FileOperationError> {
        file_ops::rename(&self.state, proof, path, new_name, audit_context).await
    }

    pub(crate) async fn inspect_delete(
        &self,
        path: &str,
    ) -> Result<DeleteInspection, FileOperationError> {
        file_ops::inspect_delete(&self.state, path).await
    }

    pub(crate) async fn delete(
        &self,
        proof: MfaSessionProof,
        path: &str,
        confirmation: Option<&str>,
        audit_context: AuditContext,
    ) -> Result<SessionBound<DeleteResult>, FileOperationError> {
        file_ops::delete(&self.state, proof, path, confirmation, audit_context).await
    }
}
