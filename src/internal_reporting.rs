use std::{any::type_name, sync::Once};

static INSTALL_SAFE_PANIC_HOOK: Once = Once::new();

/// Stable identifiers for internal failures at transport/authentication boundaries.
///
/// These values are log contracts. Rename a Rust variant freely, but do not change
/// its string without an explicit operations migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternalOperation {
    HttpAuthArgon2HashJoin,
    HttpAuthArgon2HashFailure,
    HttpAuthArgon2VerifyJoin,
    HttpAuthPasswordLoginJoin,
    HttpAuthDatabaseReadJoin,
    HttpAuthDatabaseRequiredAuditJoin,
    HttpAuthDatabaseFailure,
    HttpAuthWebauthnRecovery,
    HttpAuthResponseCookieHeader,
    HttpAuthClientActivityAdmissionPoisonRecovery,
    HttpAuthShareActivityAdmissionPoisonRecovery,
    HttpAuthRuntimeSettingsSnapshotPoisonRecovery,
    HttpAuthRuntimeSettingsPersistedValidation,
    HttpAuthRuntimeSettingsReload,
    HttpAuthWebauthnSnapshotPoisonRecovery,
    HttpAuthRuntimeSettingsWritePoisonRecovery,
    HttpAuthWebauthnWritePoisonRecovery,
    HttpRequestPanic,
    ApiSessionLoginCookieHeader,
    ApiSessionMfaCookieHeader,
    ApiSessionLogoutCookieHeader,
    ApiPublicUnlockCookieHeader,
    ApiServiceTokenExpiryParse,
    ApiFilesListJoin,
    ApiFilesListScan,
    ApiFilesCreateTaskJoin,
    ApiFilesRenameTaskJoin,
    ApiFilesDeleteTaskJoin,
    ApiFilesOperationFailure,
    ApiShareCreateMetadataJoin,
    ApiShareRevalidateMetadataJoin,
    ApiShareUploadTotalInvariant,
    ApiShareUploadFilesInvariant,
    ApiShareUpdateResultInvariant,
    ApiSharePasswordHashStateInvariant,
    ApiShareServiceDatabaseFailure,
    ApiAdminServiceDatabaseFailure,
    SetupLocaleCookieHeader,
    SetupBootstrapCookieHeader,
    SetupQrRender,
    SetupConfigLoad,
    SetupStorageFinalize,
    SetupMountDiscovery,
    WebAdminValidationDatabaseInvariant,
    WebTemplateRenderFailure,
    WebCommonCredentialDecode,
    WebCommonQrRender,
    WebAccountCredentialRegistrationTaskJoin,
    WebAuthCredentialRowInvariant,
    WebAuthCredentialEncode,
    WebAuthSessionCookieHeader,
    WebRenderingPublicBaseUrlParse,
    WebRenderingLocaleCookieHeader,
    WebPublicPreviewReadJoin,
    WebPublicPreviewScopeOpenJoin,
    WebPublicPreviewTextStreamBuild,
    WebPublicPreviewContentLengthHeader,
    WebPublicSearchTaskJoin,
    WebPublicDirectoryListTaskJoin,
    WebPublicFileMetadataTaskJoin,
    WebFilesCreateTaskJoin,
    WebFilesRenameTaskJoin,
    WebFilesDeleteTaskJoin,
    WebFilesOperationFailure,
    WebAdminUploadStageTaskJoin,
    WebAdminUploadDirectoriesTaskJoin,
    WebAdminUploadDestinationMatch,
    WebAdminUploadDestinationMetadata,
    WebAdminUploadPublishTaskJoin,
    WebAdminUploadFinalizerJoin,
    WebAdminUploadFileHeader,
    WebAdminSearchTaskJoin,
    WebAdminSearchFailure,
    WebAdminDirectoryListTaskJoin,
    WebAdminDirectoryListFailure,
    WebAdminDownloadOpenTaskJoin,
    WebAdminDownloadOpenFailure,
    WebAdminDownloadDispositionHeader,
    WebAdminDownloadLengthHeader,
    WebAdminPreviewReadTaskJoin,
    WebAdminPreviewTextStreamBuild,
    WebAdminPreviewContentLengthHeader,
    WebShareCreateFormMetadataTaskJoin,
    WebShareCreateMetadataTaskJoin,
    WebShareCreateRevalidateMetadataTaskJoin,
    WebSharePasswordHashStateInvariant,
    WebShareServiceDatabaseFailure,
    WebPublicUploadStageTaskJoin,
    WebPublicUploadDirectoryTaskJoin,
    WebPublicUploadDirectoryFailure,
    #[cfg(test)]
    WebPublicUploadTestCheckpoint,
    WebPublicUploadBaseMatch,
    WebPublicUploadDestinationMatch,
    WebPublicUploadDestinationExists,
    WebPublicUploadPostDirectoryDestinationExists,
    WebPublicUploadBindDestination,
    WebPublicUploadPublishTaskJoin,
    WebPublicUploadPublishFailure,
    WebPublicUploadFileHeader,
    WebPublicUploadFinalizerJoin,
    WebRawPreviewOpenJoin,
    WebRawPreviewFileMetadata,
    WebRawPreviewAsyncMetadata,
    WebRawPreviewUnsatisfiedRangeHeader,
    WebRawPreviewSeek,
    WebRawPreviewContentRangeHeader,
    WebRawPreviewContentLengthHeader,
    WebRawPreviewDispositionHeader,
    WebZipScopeOpenTaskJoin,
    WebZipPlanTaskJoin,
    WebZipMaterializeTaskJoin,
    WebZipOutputFailure,
    WebZipDispositionHeader,
    WebDownloadOpenTaskJoin,
    WebDownloadUnsatisfiedRangeHeader,
    WebDownloadSeek,
    WebDownloadContentRangeHeader,
    WebDownloadContentLengthHeader,
    WebDownloadContentTypeHeader,
    WebDownloadDispositionHeader,
    WebTransferHeartbeatDatabase,
    WebTransferHeartbeatTaskJoin,
    WebTransferLeaseBeginChannel,
    WebTransferLeaseBeginDatabase,
    WebUploadReservationBeginChannel,
    WebUploadReservationBeginDatabase,
    WebTransferCompleteTaskJoin,
    WebTransferCompleteWorkerJoin,
    WebTransferCompleteLeaseInvariant,
    WebTransferCompleteDatabase,
    WebTransferCookieHeader,
    WebUploadIoFailure,
}

impl InternalOperation {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::HttpAuthArgon2HashJoin => "http_auth.argon2.hash.join",
            Self::HttpAuthArgon2HashFailure => "http_auth.argon2.hash.failure",
            Self::HttpAuthArgon2VerifyJoin => "http_auth.argon2.verify.join",
            Self::HttpAuthPasswordLoginJoin => "http_auth.password_login.join",
            Self::HttpAuthDatabaseReadJoin => "http_auth.database.read.join",
            Self::HttpAuthDatabaseRequiredAuditJoin => "http_auth.database.required_audit.join",
            Self::HttpAuthDatabaseFailure => "http_auth.database.failure",
            Self::HttpAuthWebauthnRecovery => "http_auth.webauthn.recovery",
            Self::HttpAuthResponseCookieHeader => "http_auth.response.cookie_header",
            Self::HttpAuthClientActivityAdmissionPoisonRecovery => client_admission_code(),
            operation @ (Self::HttpAuthShareActivityAdmissionPoisonRecovery
            | Self::HttpAuthRuntimeSettingsSnapshotPoisonRecovery
            | Self::HttpAuthRuntimeSettingsPersistedValidation
            | Self::HttpAuthWebauthnSnapshotPoisonRecovery
            | Self::HttpAuthRuntimeSettingsWritePoisonRecovery
            | Self::HttpAuthWebauthnWritePoisonRecovery) => http_auth_runtime_code(operation),
            Self::HttpAuthRuntimeSettingsReload => "http_auth.runtime_settings.reload",
            Self::HttpRequestPanic => "http.request.panic",
            Self::ApiSessionLoginCookieHeader => "api.session.login.cookie_header",
            Self::ApiSessionMfaCookieHeader => "api.session.mfa.cookie_header",
            Self::ApiSessionLogoutCookieHeader => "api.session.logout.cookie_header",
            Self::ApiPublicUnlockCookieHeader => "api.public.unlock.cookie_header",
            Self::ApiServiceTokenExpiryParse => "api.service_token.expiry.parse",
            Self::ApiFilesListJoin => "api.files.list.join",
            Self::ApiFilesListScan => "api.files.list.scan",
            Self::ApiFilesCreateTaskJoin => "api.files.create.task_join",
            Self::ApiFilesRenameTaskJoin => "api.files.rename.task_join",
            Self::ApiFilesDeleteTaskJoin => "api.files.delete.task_join",
            Self::ApiFilesOperationFailure => "api.files.operation.failure",
            Self::ApiShareCreateMetadataJoin => "api.share.create.metadata_join",
            Self::ApiShareRevalidateMetadataJoin => "api.share.create.revalidate_metadata_join",
            Self::ApiShareUploadTotalInvariant => "api.share.update.upload_total_invariant",
            Self::ApiShareUploadFilesInvariant => "api.share.update.upload_files_invariant",
            Self::ApiShareUpdateResultInvariant => "api.share.update.result_invariant",
            Self::ApiSharePasswordHashStateInvariant => "api.share.password_hash_state_invariant",
            Self::ApiShareServiceDatabaseFailure => "api.share.service.database_failure",
            Self::ApiAdminServiceDatabaseFailure => "api.admin.service.database_failure",
            Self::SetupLocaleCookieHeader => "setup.locale.cookie_header",
            Self::SetupBootstrapCookieHeader => "setup.bootstrap.cookie_header",
            Self::SetupQrRender => "setup.qr.render",
            Self::SetupConfigLoad => "setup.config.load",
            Self::SetupStorageFinalize => "setup.storage.finalize",
            Self::SetupMountDiscovery => "setup.mount.discovery",
            Self::WebAdminValidationDatabaseInvariant => "web.admin.validation.database_invariant",
            Self::WebTemplateRenderFailure => "web.template.render.failure",
            Self::WebCommonCredentialDecode => "web.common.credential.decode",
            Self::WebCommonQrRender => "web.common.qr.render",
            Self::WebAccountCredentialRegistrationTaskJoin => {
                "web.account.credential_registration.task_join"
            }
            Self::WebAuthCredentialRowInvariant => "web.auth.credential_row_invariant",
            Self::WebAuthCredentialEncode => "web.auth.credential.encode",
            Self::WebAuthSessionCookieHeader => "web.auth.session.cookie_header",
            Self::WebRenderingPublicBaseUrlParse => "web.rendering.public_base_url.parse",
            Self::WebRenderingLocaleCookieHeader => "web.rendering.locale.cookie_header",
            Self::WebPublicPreviewReadJoin => "web.public_preview.read.join",
            Self::WebPublicPreviewScopeOpenJoin => "web.public_preview.scope_open.join",
            Self::WebPublicPreviewTextStreamBuild => "web.public_preview.text_stream.build",
            Self::WebPublicPreviewContentLengthHeader => "web.public_preview.content_length_header",
            Self::WebPublicSearchTaskJoin => "web.public.search.task_join",
            Self::WebPublicDirectoryListTaskJoin => "web.public.directory_list.task_join",
            Self::WebPublicFileMetadataTaskJoin => "web.public.file_metadata.task_join",
            Self::WebFilesCreateTaskJoin => "web.files.create.task_join",
            Self::WebFilesRenameTaskJoin => "web.files.rename.task_join",
            Self::WebFilesDeleteTaskJoin => "web.files.delete.task_join",
            Self::WebFilesOperationFailure => "web.files.operation.failure",
            Self::WebAdminUploadStageTaskJoin => "web.admin_upload.stage.task_join",
            Self::WebAdminUploadDirectoriesTaskJoin => "web.admin_upload.directories.task_join",
            Self::WebAdminUploadDestinationMatch => "web.admin_upload.destination.match",
            Self::WebAdminUploadDestinationMetadata => "web.admin_upload.destination.metadata",
            Self::WebAdminUploadPublishTaskJoin => "web.admin_upload.publish.task_join",
            Self::WebAdminUploadFinalizerJoin => "web.admin_upload.finalizer.join",
            Self::WebAdminUploadFileHeader => "web.admin_upload.file_header",
            Self::WebAdminSearchTaskJoin => "web.admin.search.task_join",
            Self::WebAdminSearchFailure => "web.admin.search.failure",
            Self::WebAdminDirectoryListTaskJoin => "web.admin.directory_list.task_join",
            Self::WebAdminDirectoryListFailure => "web.admin.directory_list.failure",
            Self::WebAdminDownloadOpenTaskJoin => "web.admin.download.open.task_join",
            Self::WebAdminDownloadOpenFailure => "web.admin.download.open.failure",
            Self::WebAdminDownloadDispositionHeader => "web.admin.download.disposition_header",
            Self::WebAdminDownloadLengthHeader => "web.admin.download.length_header",
            Self::WebAdminPreviewReadTaskJoin => "web.admin.preview.read.task_join",
            Self::WebAdminPreviewTextStreamBuild => "web.admin.preview.text_stream.build",
            Self::WebAdminPreviewContentLengthHeader => "web.admin.preview.content_length_header",
            Self::WebShareCreateFormMetadataTaskJoin => "web.share.create_form.metadata.task_join",
            Self::WebShareCreateMetadataTaskJoin => "web.share.create.metadata.task_join",
            Self::WebShareCreateRevalidateMetadataTaskJoin => {
                "web.share.create.revalidate_metadata.task_join"
            }
            Self::WebSharePasswordHashStateInvariant => "web.share.password_hash_state_invariant",
            Self::WebShareServiceDatabaseFailure => "web.share.service.database_failure",
            Self::WebPublicUploadStageTaskJoin => "web.public_upload.stage.task_join",
            Self::WebPublicUploadDirectoryTaskJoin => "web.public_upload.directory.task_join",
            Self::WebPublicUploadDirectoryFailure => "web.public_upload.directory.failure",
            #[cfg(test)]
            Self::WebPublicUploadTestCheckpoint => "web.public_upload.test_checkpoint",
            Self::WebPublicUploadBaseMatch => "web.public_upload.base.match",
            Self::WebPublicUploadDestinationMatch => "web.public_upload.destination.match",
            Self::WebPublicUploadDestinationExists => "web.public_upload.destination.exists",
            Self::WebPublicUploadPostDirectoryDestinationExists => {
                "web.public_upload.post_directory_destination.exists"
            }
            Self::WebPublicUploadBindDestination => "web.public_upload.destination.bind",
            Self::WebPublicUploadPublishTaskJoin => "web.public_upload.publish.task_join",
            Self::WebPublicUploadPublishFailure => "web.public_upload.publish.failure",
            Self::WebPublicUploadFileHeader => "web.public_upload.file_header",
            Self::WebPublicUploadFinalizerJoin => "web.public_upload.finalizer.join",
            Self::WebRawPreviewOpenJoin => "web.raw_preview.open.join",
            Self::WebRawPreviewFileMetadata => "web.raw_preview.file.metadata",
            Self::WebRawPreviewAsyncMetadata => "web.raw_preview.async_metadata",
            Self::WebRawPreviewUnsatisfiedRangeHeader => "web.raw_preview.unsatisfied_range_header",
            Self::WebRawPreviewSeek => "web.raw_preview.seek",
            Self::WebRawPreviewContentRangeHeader => "web.raw_preview.content_range_header",
            Self::WebRawPreviewContentLengthHeader => "web.raw_preview.content_length_header",
            Self::WebRawPreviewDispositionHeader => "web.raw_preview.disposition_header",
            Self::WebZipScopeOpenTaskJoin => "web.zip.scope_open.task_join",
            Self::WebZipPlanTaskJoin => "web.zip.plan.task_join",
            Self::WebZipMaterializeTaskJoin => "web.zip.materialize.task_join",
            Self::WebZipOutputFailure => "web.zip.output.failure",
            Self::WebZipDispositionHeader => "web.zip.disposition_header",
            Self::WebDownloadOpenTaskJoin => "web.download.open.task_join",
            Self::WebDownloadUnsatisfiedRangeHeader => "web.download.unsatisfied_range_header",
            Self::WebDownloadSeek => "web.download.seek",
            Self::WebDownloadContentRangeHeader => "web.download.content_range_header",
            Self::WebDownloadContentLengthHeader => "web.download.content_length_header",
            Self::WebDownloadContentTypeHeader => "web.download.content_type_header",
            Self::WebDownloadDispositionHeader => "web.download.disposition_header",
            Self::WebTransferHeartbeatDatabase => "web.transfer.heartbeat.database",
            Self::WebTransferHeartbeatTaskJoin => "web.transfer.heartbeat.task_join",
            Self::WebTransferLeaseBeginChannel => "web.transfer_lease.begin.channel",
            Self::WebTransferLeaseBeginDatabase => "web.transfer_lease.begin.database",
            Self::WebUploadReservationBeginChannel => "web.upload_reservation.begin.channel",
            Self::WebUploadReservationBeginDatabase => "web.upload_reservation.begin.database",
            Self::WebTransferCompleteTaskJoin => "web.transfer.complete.task_join",
            Self::WebTransferCompleteWorkerJoin => "web.transfer.complete.worker_join",
            Self::WebTransferCompleteLeaseInvariant => "web.transfer.complete.lease_invariant",
            Self::WebTransferCompleteDatabase => "web.transfer.complete.database",
            Self::WebTransferCookieHeader => "web.transfer.cookie_header",
            Self::WebUploadIoFailure => "web.upload.io_failure",
        }
    }
}

const fn http_auth_runtime_code(operation: InternalOperation) -> &'static str {
    match operation {
        InternalOperation::HttpAuthShareActivityAdmissionPoisonRecovery => {
            "http_auth.share_activity_admission.poison_recovery"
        }
        InternalOperation::HttpAuthRuntimeSettingsSnapshotPoisonRecovery => {
            "http_auth.runtime_settings.snapshot.poison_recovery"
        }
        InternalOperation::HttpAuthRuntimeSettingsPersistedValidation => {
            "http_auth.runtime_settings.persisted.validation"
        }
        InternalOperation::HttpAuthWebauthnSnapshotPoisonRecovery => {
            "http_auth.webauthn.snapshot.poison_recovery"
        }
        InternalOperation::HttpAuthRuntimeSettingsWritePoisonRecovery => {
            "http_auth.runtime_settings.write.poison_recovery"
        }
        InternalOperation::HttpAuthWebauthnWritePoisonRecovery => {
            "http_auth.webauthn.write.poison_recovery"
        }
        _ => unreachable!(),
    }
}

const fn client_admission_code() -> &'static str {
    "http_auth.client_activity_admission.poison_recovery"
}

/// Proof that an internal failure has already been reported.
///
/// This marker is intentionally neither `Clone` nor `Copy`: a boundary consumes
/// it when constructing the generic client response and cannot accidentally
/// report the same failure again during conversion.
#[derive(Debug)]
pub(crate) struct ReportedInternalError {
    _private: (),
}

/// Reports one internal error without serializing potentially sensitive values.
///
/// The concrete value is accepted so every call site must account for its error,
/// but only its Rust type is recorded. In particular, tokens, cookies, passwords,
/// header values, SQL values and paths cannot leak through `Display` or `Debug`.
///
/// Request IDs are not copied into another task-local or accepted as an argument.
/// The event is emitted into `Span::current()`; the HTTP trace span already owns
/// the server-generated `request_id` field and the configured subscriber records
/// that field with this event.
pub(crate) fn report_internal<E>(operation: InternalOperation, _error: E) -> ReportedInternalError {
    tracing::error!(
        operation = operation.code(),
        error_type = type_name::<E>(),
        "internal operation failed"
    );
    ReportedInternalError { _private: () }
}

/// Reports an impossible state without fabricating an error value.
pub(crate) fn report_invariant(operation: InternalOperation) -> ReportedInternalError {
    tracing::error!(operation = operation.code(), "internal invariant violated");
    ReportedInternalError { _private: () }
}

/// Installs a payload-blind panic hook for HTTP and process failures.
///
/// Rust invokes the process hook before an unwind reaches `CatchPanicLayer`.
/// The default hook formats the panic payload, which can contain request data
/// and control characters. Our hook deliberately ignores all panic metadata and
/// emits exactly one stable operation event. Custom HTTP panic handlers therefore
/// only construct the generic client response and must not log a second time.
pub(crate) fn install_safe_panic_hook() {
    INSTALL_SAFE_PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_panic| {
            let _reported = report_invariant(InternalOperation::HttpRequestPanic);
            #[cfg(test)]
            if let Some(location) = _panic.location() {
                eprintln!(
                    "test panic at {}:{}:{} (payload redacted)",
                    location.file(),
                    location.line(),
                    location.column()
                );
            }
        }));
    });
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fmt, io,
        sync::{Arc, Mutex},
    };

    use super::*;

    const OPERATIONS: &[InternalOperation] = &[
        InternalOperation::HttpAuthArgon2HashJoin,
        InternalOperation::HttpAuthArgon2HashFailure,
        InternalOperation::HttpAuthArgon2VerifyJoin,
        InternalOperation::HttpAuthPasswordLoginJoin,
        InternalOperation::HttpAuthDatabaseReadJoin,
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        InternalOperation::HttpAuthDatabaseFailure,
        InternalOperation::HttpAuthWebauthnRecovery,
        InternalOperation::HttpAuthResponseCookieHeader,
        InternalOperation::HttpAuthClientActivityAdmissionPoisonRecovery,
        InternalOperation::HttpAuthShareActivityAdmissionPoisonRecovery,
        InternalOperation::HttpAuthRuntimeSettingsSnapshotPoisonRecovery,
        InternalOperation::HttpAuthRuntimeSettingsPersistedValidation,
        InternalOperation::HttpAuthRuntimeSettingsReload,
        InternalOperation::HttpAuthWebauthnSnapshotPoisonRecovery,
        InternalOperation::HttpAuthRuntimeSettingsWritePoisonRecovery,
        InternalOperation::HttpAuthWebauthnWritePoisonRecovery,
        InternalOperation::HttpRequestPanic,
        InternalOperation::ApiSessionLoginCookieHeader,
        InternalOperation::ApiSessionMfaCookieHeader,
        InternalOperation::ApiSessionLogoutCookieHeader,
        InternalOperation::ApiPublicUnlockCookieHeader,
        InternalOperation::ApiServiceTokenExpiryParse,
        InternalOperation::ApiFilesListJoin,
        InternalOperation::ApiFilesListScan,
        InternalOperation::ApiFilesCreateTaskJoin,
        InternalOperation::ApiFilesRenameTaskJoin,
        InternalOperation::ApiFilesDeleteTaskJoin,
        InternalOperation::ApiFilesOperationFailure,
        InternalOperation::ApiShareCreateMetadataJoin,
        InternalOperation::ApiShareRevalidateMetadataJoin,
        InternalOperation::ApiShareUploadTotalInvariant,
        InternalOperation::ApiShareUploadFilesInvariant,
        InternalOperation::ApiShareUpdateResultInvariant,
        InternalOperation::ApiSharePasswordHashStateInvariant,
        InternalOperation::ApiShareServiceDatabaseFailure,
        InternalOperation::ApiAdminServiceDatabaseFailure,
        InternalOperation::SetupLocaleCookieHeader,
        InternalOperation::SetupBootstrapCookieHeader,
        InternalOperation::SetupQrRender,
        InternalOperation::SetupConfigLoad,
        InternalOperation::SetupStorageFinalize,
        InternalOperation::SetupMountDiscovery,
        InternalOperation::WebAdminValidationDatabaseInvariant,
        InternalOperation::WebTemplateRenderFailure,
        InternalOperation::WebCommonCredentialDecode,
        InternalOperation::WebCommonQrRender,
        InternalOperation::WebAccountCredentialRegistrationTaskJoin,
        InternalOperation::WebAuthCredentialRowInvariant,
        InternalOperation::WebAuthCredentialEncode,
        InternalOperation::WebAuthSessionCookieHeader,
        InternalOperation::WebRenderingPublicBaseUrlParse,
        InternalOperation::WebRenderingLocaleCookieHeader,
        InternalOperation::WebPublicPreviewReadJoin,
        InternalOperation::WebPublicPreviewScopeOpenJoin,
        InternalOperation::WebPublicPreviewTextStreamBuild,
        InternalOperation::WebPublicPreviewContentLengthHeader,
        InternalOperation::WebPublicSearchTaskJoin,
        InternalOperation::WebPublicDirectoryListTaskJoin,
        InternalOperation::WebPublicFileMetadataTaskJoin,
        InternalOperation::WebFilesCreateTaskJoin,
        InternalOperation::WebFilesRenameTaskJoin,
        InternalOperation::WebFilesDeleteTaskJoin,
        InternalOperation::WebFilesOperationFailure,
        InternalOperation::WebAdminUploadStageTaskJoin,
        InternalOperation::WebAdminUploadDirectoriesTaskJoin,
        InternalOperation::WebAdminUploadDestinationMatch,
        InternalOperation::WebAdminUploadDestinationMetadata,
        InternalOperation::WebAdminUploadPublishTaskJoin,
        InternalOperation::WebAdminUploadFinalizerJoin,
        InternalOperation::WebAdminUploadFileHeader,
        InternalOperation::WebAdminSearchTaskJoin,
        InternalOperation::WebAdminSearchFailure,
        InternalOperation::WebAdminDirectoryListTaskJoin,
        InternalOperation::WebAdminDirectoryListFailure,
        InternalOperation::WebAdminDownloadOpenTaskJoin,
        InternalOperation::WebAdminDownloadOpenFailure,
        InternalOperation::WebAdminDownloadDispositionHeader,
        InternalOperation::WebAdminDownloadLengthHeader,
        InternalOperation::WebAdminPreviewReadTaskJoin,
        InternalOperation::WebAdminPreviewTextStreamBuild,
        InternalOperation::WebAdminPreviewContentLengthHeader,
        InternalOperation::WebShareCreateFormMetadataTaskJoin,
        InternalOperation::WebShareCreateMetadataTaskJoin,
        InternalOperation::WebShareCreateRevalidateMetadataTaskJoin,
        InternalOperation::WebSharePasswordHashStateInvariant,
        InternalOperation::WebShareServiceDatabaseFailure,
        InternalOperation::WebPublicUploadStageTaskJoin,
        InternalOperation::WebPublicUploadDirectoryTaskJoin,
        InternalOperation::WebPublicUploadDirectoryFailure,
        InternalOperation::WebPublicUploadTestCheckpoint,
        InternalOperation::WebPublicUploadBaseMatch,
        InternalOperation::WebPublicUploadDestinationMatch,
        InternalOperation::WebPublicUploadDestinationExists,
        InternalOperation::WebPublicUploadPostDirectoryDestinationExists,
        InternalOperation::WebPublicUploadBindDestination,
        InternalOperation::WebPublicUploadPublishTaskJoin,
        InternalOperation::WebPublicUploadPublishFailure,
        InternalOperation::WebPublicUploadFileHeader,
        InternalOperation::WebPublicUploadFinalizerJoin,
        InternalOperation::WebRawPreviewOpenJoin,
        InternalOperation::WebRawPreviewFileMetadata,
        InternalOperation::WebRawPreviewAsyncMetadata,
        InternalOperation::WebRawPreviewUnsatisfiedRangeHeader,
        InternalOperation::WebRawPreviewSeek,
        InternalOperation::WebRawPreviewContentRangeHeader,
        InternalOperation::WebRawPreviewContentLengthHeader,
        InternalOperation::WebRawPreviewDispositionHeader,
        InternalOperation::WebZipScopeOpenTaskJoin,
        InternalOperation::WebZipPlanTaskJoin,
        InternalOperation::WebZipMaterializeTaskJoin,
        InternalOperation::WebZipOutputFailure,
        InternalOperation::WebZipDispositionHeader,
        InternalOperation::WebDownloadOpenTaskJoin,
        InternalOperation::WebDownloadUnsatisfiedRangeHeader,
        InternalOperation::WebDownloadSeek,
        InternalOperation::WebDownloadContentRangeHeader,
        InternalOperation::WebDownloadContentLengthHeader,
        InternalOperation::WebDownloadContentTypeHeader,
        InternalOperation::WebDownloadDispositionHeader,
        InternalOperation::WebTransferHeartbeatDatabase,
        InternalOperation::WebTransferHeartbeatTaskJoin,
        InternalOperation::WebTransferLeaseBeginChannel,
        InternalOperation::WebTransferLeaseBeginDatabase,
        InternalOperation::WebUploadReservationBeginChannel,
        InternalOperation::WebUploadReservationBeginDatabase,
        InternalOperation::WebTransferCompleteTaskJoin,
        InternalOperation::WebTransferCompleteWorkerJoin,
        InternalOperation::WebTransferCompleteLeaseInvariant,
        InternalOperation::WebTransferCompleteDatabase,
        InternalOperation::WebTransferCookieHeader,
        InternalOperation::WebUploadIoFailure,
    ];

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    struct SensitiveFailure(&'static str);

    impl fmt::Display for SensitiveFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl fmt::Debug for SensitiveFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    fn capture(event: impl FnOnce()) -> String {
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, event);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn operation_codes_are_unique_and_stable() {
        let actual = OPERATIONS
            .iter()
            .copied()
            .map(InternalOperation::code)
            .collect::<Vec<_>>();
        assert_eq!(actual.len(), actual.iter().collect::<HashSet<_>>().len());
        assert_eq!(
            actual,
            [
                "http_auth.argon2.hash.join",
                "http_auth.argon2.hash.failure",
                "http_auth.argon2.verify.join",
                "http_auth.password_login.join",
                "http_auth.database.read.join",
                "http_auth.database.required_audit.join",
                "http_auth.database.failure",
                "http_auth.webauthn.recovery",
                "http_auth.response.cookie_header",
                "http_auth.client_activity_admission.poison_recovery",
                "http_auth.share_activity_admission.poison_recovery",
                "http_auth.runtime_settings.snapshot.poison_recovery",
                "http_auth.runtime_settings.persisted.validation",
                "http_auth.runtime_settings.reload",
                "http_auth.webauthn.snapshot.poison_recovery",
                "http_auth.runtime_settings.write.poison_recovery",
                "http_auth.webauthn.write.poison_recovery",
                "http.request.panic",
                "api.session.login.cookie_header",
                "api.session.mfa.cookie_header",
                "api.session.logout.cookie_header",
                "api.public.unlock.cookie_header",
                "api.service_token.expiry.parse",
                "api.files.list.join",
                "api.files.list.scan",
                "api.files.create.task_join",
                "api.files.rename.task_join",
                "api.files.delete.task_join",
                "api.files.operation.failure",
                "api.share.create.metadata_join",
                "api.share.create.revalidate_metadata_join",
                "api.share.update.upload_total_invariant",
                "api.share.update.upload_files_invariant",
                "api.share.update.result_invariant",
                "api.share.password_hash_state_invariant",
                "api.share.service.database_failure",
                "api.admin.service.database_failure",
                "setup.locale.cookie_header",
                "setup.bootstrap.cookie_header",
                "setup.qr.render",
                "setup.config.load",
                "setup.storage.finalize",
                "setup.mount.discovery",
                "web.admin.validation.database_invariant",
                "web.template.render.failure",
                "web.common.credential.decode",
                "web.common.qr.render",
                "web.account.credential_registration.task_join",
                "web.auth.credential_row_invariant",
                "web.auth.credential.encode",
                "web.auth.session.cookie_header",
                "web.rendering.public_base_url.parse",
                "web.rendering.locale.cookie_header",
                "web.public_preview.read.join",
                "web.public_preview.scope_open.join",
                "web.public_preview.text_stream.build",
                "web.public_preview.content_length_header",
                "web.public.search.task_join",
                "web.public.directory_list.task_join",
                "web.public.file_metadata.task_join",
                "web.files.create.task_join",
                "web.files.rename.task_join",
                "web.files.delete.task_join",
                "web.files.operation.failure",
                "web.admin_upload.stage.task_join",
                "web.admin_upload.directories.task_join",
                "web.admin_upload.destination.match",
                "web.admin_upload.destination.metadata",
                "web.admin_upload.publish.task_join",
                "web.admin_upload.finalizer.join",
                "web.admin_upload.file_header",
                "web.admin.search.task_join",
                "web.admin.search.failure",
                "web.admin.directory_list.task_join",
                "web.admin.directory_list.failure",
                "web.admin.download.open.task_join",
                "web.admin.download.open.failure",
                "web.admin.download.disposition_header",
                "web.admin.download.length_header",
                "web.admin.preview.read.task_join",
                "web.admin.preview.text_stream.build",
                "web.admin.preview.content_length_header",
                "web.share.create_form.metadata.task_join",
                "web.share.create.metadata.task_join",
                "web.share.create.revalidate_metadata.task_join",
                "web.share.password_hash_state_invariant",
                "web.share.service.database_failure",
                "web.public_upload.stage.task_join",
                "web.public_upload.directory.task_join",
                "web.public_upload.directory.failure",
                "web.public_upload.test_checkpoint",
                "web.public_upload.base.match",
                "web.public_upload.destination.match",
                "web.public_upload.destination.exists",
                "web.public_upload.post_directory_destination.exists",
                "web.public_upload.destination.bind",
                "web.public_upload.publish.task_join",
                "web.public_upload.publish.failure",
                "web.public_upload.file_header",
                "web.public_upload.finalizer.join",
                "web.raw_preview.open.join",
                "web.raw_preview.file.metadata",
                "web.raw_preview.async_metadata",
                "web.raw_preview.unsatisfied_range_header",
                "web.raw_preview.seek",
                "web.raw_preview.content_range_header",
                "web.raw_preview.content_length_header",
                "web.raw_preview.disposition_header",
                "web.zip.scope_open.task_join",
                "web.zip.plan.task_join",
                "web.zip.materialize.task_join",
                "web.zip.output.failure",
                "web.zip.disposition_header",
                "web.download.open.task_join",
                "web.download.unsatisfied_range_header",
                "web.download.seek",
                "web.download.content_range_header",
                "web.download.content_length_header",
                "web.download.content_type_header",
                "web.download.disposition_header",
                "web.transfer.heartbeat.database",
                "web.transfer.heartbeat.task_join",
                "web.transfer_lease.begin.channel",
                "web.transfer_lease.begin.database",
                "web.upload_reservation.begin.channel",
                "web.upload_reservation.begin.database",
                "web.transfer.complete.task_join",
                "web.transfer.complete.worker_join",
                "web.transfer.complete.lease_invariant",
                "web.transfer.complete.database",
                "web.transfer.cookie_header",
                "web.upload.io_failure",
            ]
        );
    }

    #[test]
    fn internal_error_is_reported_once_in_request_span_without_secret_material() {
        let operation = InternalOperation::ApiSessionLoginCookieHeader;
        let request_id = "server-generated-request-id";
        let secret = "Bearer vlk_st_v1_super-secret\r\nCookie: stolen";
        let output = capture(|| {
            let span = tracing::info_span!("http_request", request_id);
            let _entered = span.enter();
            let _reported = report_internal(operation, SensitiveFailure(secret));
        });

        assert_eq!(output.matches(operation.code()).count(), 1, "{output}");
        assert_eq!(output.matches("internal operation failed").count(), 1);
        assert!(output.contains(request_id), "{output}");
        assert!(output.contains("SensitiveFailure"), "{output}");
        assert!(!output.contains("super-secret"), "{output}");
        assert!(!output.contains("Cookie: stolen"), "{output}");
    }

    #[test]
    fn invariant_is_reported_once_with_its_stable_code() {
        let operation = InternalOperation::ApiShareUpdateResultInvariant;
        let output = capture(|| {
            let _reported = report_invariant(operation);
        });

        assert_eq!(output.matches(operation.code()).count(), 1, "{output}");
        assert_eq!(output.matches("internal invariant violated").count(), 1);
        assert!(!output.contains("error_type"), "{output}");
    }

    #[test]
    fn panic_hook_reports_once_without_formatting_the_payload() {
        let request_id = "panic-request-id";
        let secret = "token=panic-secret\r\nforged-event=true";
        let output = capture(|| {
            install_safe_panic_hook();
            let span = tracing::info_span!("http_request", request_id);
            let _entered = span.enter();
            let result = std::panic::catch_unwind(|| {
                std::panic::panic_any(secret.to_owned());
            });
            assert!(result.is_err());
        });

        assert_eq!(
            output
                .matches(InternalOperation::HttpRequestPanic.code())
                .count(),
            1,
            "{output}"
        );
        assert!(output.contains(request_id), "{output}");
        assert!(!output.contains("panic-secret"), "{output}");
        assert!(!output.contains("forged-event"), "{output}");
    }

    #[test]
    fn mapped_error_is_not_reported_again_by_http_or_web_boundaries() {
        let operation = InternalOperation::HttpAuthDatabaseFailure;
        let output = capture(|| {
            let reported = report_internal(operation, SensitiveFailure("password=hunter2"));
            let auth_error = crate::http_auth::HttpAuthError::from(reported);
            let _web_error = crate::web::AppError::from(auth_error);
        });

        assert_eq!(output.matches(operation.code()).count(), 1, "{output}");
        assert_eq!(output.matches("internal operation failed").count(), 1);
        assert!(!output.contains("hunter2"), "{output}");
    }
}
