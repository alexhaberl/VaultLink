use axum::{
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Serialize;

use crate::{
    internal_reporting::{report_internal, InternalOperation},
    public_upload_transport::{
        execute_public_upload, PublicUploadOutcome, PublicUploadRejection,
        PublicUploadTransportError,
    },
    services::public_upload::PublicUploadSuccess,
    PublicUploadRouteState,
};

use super::{status_code_name, ApiError, ApiResult};

#[derive(Serialize)]
struct UploadSuccess {
    file: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

pub(crate) async fn upload(
    State(state): State<PublicUploadRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    multipart: Multipart,
) -> ApiResult<Response> {
    match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token.clone(),
        multipart,
    )
    .await
    .map_err(|error| transport_error(&error))?
    {
        PublicUploadOutcome::Rejected(rejection) => Err(rejection_error(&rejection)),
        PublicUploadOutcome::Success(success) if !success.audit_durability_uncertain() => {
            success_redirect(&token, &success)
        }
        PublicUploadOutcome::Success(success) => Ok((
            StatusCode::ACCEPTED,
            Json(UploadSuccess {
                file: success.file().to_string(),
                outcome: success.disposition().outcome().to_string(),
                warning: Some("audit_durability_uncertain"),
            }),
        )
            .into_response()),
    }
}

fn transport_error(error: &PublicUploadTransportError) -> ApiError {
    let status = error.status();
    let code = if error.message() == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
        "audit_unavailable"
    } else {
        status_code_name(status)
    };
    let mut api_error = ApiError::new(
        status,
        code,
        status.canonical_reason().unwrap_or("Request failed"),
    );
    if status == StatusCode::SERVICE_UNAVAILABLE
        && (error.message() == crate::http_auth::ARGON2_BUSY_MESSAGE
            || error.message() == crate::http_auth::DATABASE_BUSY_MESSAGE
            || error.message().starts_with("Too many concurrent "))
    {
        api_error.retry_after_seconds = Some(1);
    }
    api_error
}

fn rejection_error(rejection: &PublicUploadRejection) -> ApiError {
    let status = rejection.status();
    ApiError::new(
        status,
        status_code_name(status),
        status.canonical_reason().unwrap_or("Request failed"),
    )
}

fn success_redirect(token: &str, success: &PublicUploadSuccess) -> ApiResult<Response> {
    let upload_status = success.disposition().redirect_notice();
    let public_route = format!("/api/v2/public/shares/{token}");
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
            ApiError::from(report_internal(
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
    Ok(response)
}

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}
