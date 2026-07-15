use crate::{
    db::AuditContext,
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
        parent: &str,
        name: &str,
        audit_context: AuditContext,
    ) -> Result<CreateDirectoryResult, FileOperationError> {
        file_ops::create_directory(&self.state, parent, name, audit_context).await
    }

    pub(crate) async fn rename(
        &self,
        path: &str,
        new_name: &str,
        audit_context: AuditContext,
    ) -> Result<RenameResult, FileOperationError> {
        file_ops::rename(&self.state, path, new_name, audit_context).await
    }

    pub(crate) async fn inspect_delete(
        &self,
        path: &str,
    ) -> Result<DeleteInspection, FileOperationError> {
        file_ops::inspect_delete(&self.state, path).await
    }

    pub(crate) async fn delete(
        &self,
        path: &str,
        confirmation: Option<&str>,
        audit_context: AuditContext,
    ) -> Result<DeleteResult, FileOperationError> {
        file_ops::delete(&self.state, path, confirmation, audit_context).await
    }
}
