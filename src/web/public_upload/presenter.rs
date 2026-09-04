use axum::{
    extract::Json,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use serde::Serialize;

use super::{PublicUploadRejection, Result};
use crate::{
    i18n,
    internal_reporting::{report_internal, InternalOperation},
    services::public_upload::PublicUploadSuccess,
    web::{
        common::encoded,
        transfer_runtime::{public_share_route, public_upload_error},
        AppError,
    },
};

pub(super) fn success_response(
    uri: &Uri,
    token: &str,
    success: &PublicUploadSuccess,
) -> Result<Response> {
    let upload_status = if success.audit_durability_uncertain() {
        "audit_uncertain"
    } else {
        success.disposition().redirect_notice()
    };
    let public_route = public_share_route(uri, token);
    let redirect_target = if success.upload_subdir().is_empty() {
        format!("{public_route}?upload={upload_status}")
    } else {
        format!(
            "{public_route}?path={}&upload={upload_status}",
            encoded(success.upload_subdir())
        )
    };
    let mut response = Redirect::to(&redirect_target).into_response();
    response.headers_mut().insert(
        "x-vaultlink-upload-file",
        HeaderValue::from_str(&encoded(success.file())).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicUploadFileHeader,
                error,
            ))
        })?,
    );
    response.headers_mut().insert(
        "x-vaultlink-upload-outcome",
        HeaderValue::from_static(success.disposition().outcome()),
    );
    if success.disposition().storage_durability_uncertain() {
        response.headers_mut().insert(
            "x-vaultlink-durability",
            HeaderValue::from_static("uncertain"),
        );
    }
    if success.audit_durability_uncertain() {
        response.headers_mut().insert(
            "x-vaultlink-audit-durability",
            HeaderValue::from_static("uncertain"),
        );
    }
    Ok(response)
}

pub(super) fn rejection_response(token: &str, rejection: &PublicUploadRejection) -> Response {
    public_upload_error(
        token,
        rejection.upload_subdir(),
        rejection.status(),
        rejection.message(),
    )
}

#[derive(Serialize)]
pub(in crate::web) struct UploadQueueSuccess {
    pub(in crate::web) file: String,
    pub(in crate::web) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::web) warning: Option<&'static str>,
}

#[derive(Serialize)]
struct UploadQueueErrorEnvelope {
    error: UploadQueueError,
}

#[derive(Serialize)]
struct UploadQueueError {
    code: String,
    message: String,
}

pub(in crate::web) fn error_response(status: StatusCode, message: &str) -> Response {
    let admission_rejected =
        status == StatusCode::SERVICE_UNAVAILABLE && message.starts_with("Too many concurrent ");
    let code = match status {
        StatusCode::SERVICE_UNAVAILABLE
            if message == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE =>
        {
            "audit_unavailable"
        }
        StatusCode::BAD_REQUEST => "invalid_upload",
        StatusCode::UNAUTHORIZED => "share_locked",
        StatusCode::FORBIDDEN => "upload_forbidden",
        StatusCode::NOT_FOUND => "target_not_found",
        StatusCode::CONFLICT => "file_exists",
        StatusCode::REQUEST_TIMEOUT => "upload_timeout",
        StatusCode::PAYLOAD_TOO_LARGE => "upload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "blocked_extension",
        StatusCode::INSUFFICIENT_STORAGE => "insufficient_storage",
        _ => "upload_failed",
    };
    let locale = i18n::current_locale();
    let message = if message == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
        std::borrow::Cow::Borrowed(i18n::text(locale, i18n::AUDIT_TEMPORARILY_UNAVAILABLE))
    } else if message == crate::http_auth::ARGON2_BUSY_MESSAGE {
        std::borrow::Cow::Borrowed(i18n::text(locale, i18n::PASSWORD_PROCESSING_UNAVAILABLE))
    } else {
        i18n::localized_text(locale, message)
    };
    let mut response = (
        status,
        Json(UploadQueueErrorEnvelope {
            error: UploadQueueError {
                code: code.to_string(),
                message: message.into_owned(),
            },
        }),
    )
        .into_response();
    if admission_rejected {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::public_upload::UploadDisposition;

    #[test]
    fn typed_success_preserves_redirect_and_external_metadata_contract() {
        let success = PublicUploadSuccess::new(
            "grüße 100%.txt".to_string(),
            "reports/2026".to_string(),
            UploadDisposition::ReplacedUncertain,
            true,
        );
        let response = success_response(
            &"/api/v2/public/shares/share/upload".parse().unwrap(),
            "share",
            &success,
        )
        .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/api/v2/public/shares/share?path=reports%2F2026&upload=audit_uncertain"
        );
        assert_eq!(
            response.headers().get("x-vaultlink-upload-file").unwrap(),
            "gr%C3%BC%C3%9Fe%20100%25%2Etxt"
        );
        assert_eq!(
            response
                .headers()
                .get("x-vaultlink-upload-outcome")
                .unwrap(),
            "replaced_uncertain"
        );
        assert_eq!(
            response.headers().get("x-vaultlink-durability").unwrap(),
            "uncertain"
        );
        assert_eq!(
            response
                .headers()
                .get("x-vaultlink-audit-durability")
                .unwrap(),
            "uncertain"
        );
    }

    #[test]
    fn admission_error_keeps_retry_after_contract() {
        let response = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent public uploads",
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }
}
