fn share_database_app_error(error: ShareServiceError) -> AppError {
    AppError::from(crate::http_auth::service_error(
        error,
        InternalOperation::WebShareServiceDatabaseFailure,
    ))
}

fn share_service_app_error(error: ShareServiceError) -> AppError {
    match error {
        ServiceError::Validation(ShareValidationError::InvalidPath) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid target path")
        }
        ServiceError::Validation(ShareValidationError::InvalidAlias) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid alias")
        }
        ServiceError::Validation(ShareValidationError::ExpirationNotFuture) => {
            AppError(StatusCode::BAD_REQUEST, "Expiration date is in the past")
        }
        ServiceError::Validation(ShareValidationError::UploadPermissionRequiresDirectory) => {
            AppError(
                StatusCode::BAD_REQUEST,
                "Uploads are available for folder links only",
            )
        }
        ServiceError::Validation(ShareValidationError::InvalidDownloadLimit) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid transfer limit")
        }
        ServiceError::Validation(ShareValidationError::InvalidUploadLimit) => {
            AppError(StatusCode::BAD_REQUEST, "Invalid upload limit")
        }
        ServiceError::Validation(ShareValidationError::UploadLimitsRequireDirectoryUpload) => {
            AppError(
                StatusCode::BAD_REQUEST,
                "Upload limits are allowed only for upload shares",
            )
        }
        ServiceError::Validation(
            ShareValidationError::InvalidUploadTotalLimit
            | ShareValidationError::UploadTotalBelowSingleLimit,
        ) => AppError(
            StatusCode::BAD_REQUEST,
            "The cumulative upload limit is invalid",
        ),
        ServiceError::Validation(ShareValidationError::InvalidUploadFileLimit) => {
            AppError(StatusCode::BAD_REQUEST, "The upload file limit is invalid")
        }
        ServiceError::Validation(ShareValidationError::OverwriteRequiresDirectoryUpload) => {
            AppError(
                StatusCode::BAD_REQUEST,
                "Overwriting is not allowed for this share",
            )
        }
        ServiceError::Validation(ShareValidationError::OverwriteDisabledForExternalWriters) => {
            AppError(
                StatusCode::BAD_REQUEST,
                "Overwriting is disabled with external storage writers",
            )
        }
        ServiceError::Validation(ShareValidationError::PasswordConfirmationRequired) => AppError(
            StatusCode::BAD_REQUEST,
            "Password and confirmation are required for password protection",
        ),
        ServiceError::Validation(ShareValidationError::PasswordConfirmationMismatch) => {
            AppError(StatusCode::BAD_REQUEST, "Passwords do not match")
        }
        ServiceError::Validation(
            ShareValidationError::InvalidPasswordCharacterLength
            | ShareValidationError::PasswordTooManyBytes,
        ) => AppError(
            StatusCode::BAD_REQUEST,
            "Share password does not meet the policy",
        ),
        ServiceError::Internal(cause) => AppError::from(report_internal(
            InternalOperation::WebSharePasswordHashStateInvariant,
            cause,
        )),
        error => AppError::from(crate::http_auth::service_error(
            error,
            InternalOperation::WebShareServiceDatabaseFailure,
        )),
    }
}

fn share_storage_recovery_app_error(error: ShareServiceError) -> AppError {
    match error {
        error @ (ServiceError::Capacity(_) | ServiceError::AuditUnavailable(_)) => {
            AppError::from(crate::http_auth::service_error(
                error,
                InternalOperation::WebShareServiceDatabaseFailure,
            ))
        }
        ServiceError::Internal(cause) => {
            let _reported =
                report_internal(InternalOperation::WebShareServiceDatabaseFailure, cause);
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage state is being recovered",
            )
        }
        ServiceError::Validation(_) | ServiceError::NotFound | ServiceError::Conflict(_) => {
            let _reported = report_invariant(InternalOperation::WebShareServiceDatabaseFailure);
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage state is being recovered",
            )
        }
    }
}
