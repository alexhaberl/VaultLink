use axum::{
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Serialize;

#[derive(Serialize)]
struct UploadOperationTicket {
    upload_id: String,
    expires_at: String,
    status_url: String,
}

pub(crate) async fn create_operation(
    State(state): State<PublicUploadRouteState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
) -> ApiResult<Response> {
    let issued = crate::public_upload_transport::create_public_upload_operation(
        &state.into_upload_context(),
        &headers,
        &token,
    )
    .await
    .map_err(|error| transport_error(&error))?
    .ok_or(ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "upload_operation_limit",
        "Too many upload operations",
    ))?;
    let (upload_id, expires_at) = issued;
    Ok((
        StatusCode::CREATED,
        Json(UploadOperationTicket {
            status_url: format!("/api/v2/public/shares/{token}/upload/operations/{upload_id}"),
            upload_id,
            expires_at,
        }),
    )
        .into_response())
}

pub(crate) async fn operation_status(
    State(state): State<PublicUploadRouteState>,
    headers: HeaderMap,
    AxPath((token, upload_id)): AxPath<(String, String)>,
) -> ApiResult<Response> {
    let view = crate::public_upload_transport::public_upload_operation(
        &state.into_upload_context(),
        &headers,
        &token,
        &upload_id,
    )
    .await
    .map_err(|error| transport_error(&error))?
    .ok_or(ApiError::new(
        StatusCode::GONE,
        "upload_id_unavailable",
        "Upload operation unavailable",
    ))?;
    Ok(Json(view).into_response())
}

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<&'static str>,
}

pub(crate) async fn upload(
    State(state): State<PublicUploadRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> ApiResult<Response> {
    crate::public_upload_transport::preflight_upload_authorization(
        &state.clone().into_upload_context(),
        &headers,
        &token,
    )
    .await
    .map_err(|error| transport_error(&error))?;
    let upload_id = crate::upload_operation::take_upload_id(&mut multipart, &headers)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_upload",
                "Invalid upload ID",
            )
        })?;
    let status_url = Some(format!(
        "/api/v2/public/shares/{token}/upload/operations/{}",
        upload_id.id
    ));
    match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token.clone(),
        multipart,
        Some(upload_id),
    )
    .await
    .map_err(|error| {
        let mut response = transport_error(&error);
        if response.code == "upload_in_progress" {
            response.status_url = status_url;
        }
        response
    })? {
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
                warnings: success.warnings().codes(),
            }),
        )
            .into_response()),
    }
}

fn transport_error(error: &PublicUploadTransportError) -> ApiError {
    let status = error.status();
    let code = if error.message() == "Upload ID conflicts with request" {
        "upload_id_conflict"
    } else if error.message() == "Upload operation already started; check its status" {
        "upload_in_progress"
    } else if error.message() == "Upload outcome is unknown; check its status" {
        "outcome_unknown"
    } else if error.message() == "Upload operation was rejected; create a new operation" {
        "upload_rejected"
    } else if error.message() == crate::http_auth::AUDIT_UNAVAILABLE_MESSAGE {
        "audit_unavailable"
    } else {
        status_code_name(status)
    };
    let mut api_error = ApiError::new(
        status,
        code,
        status.canonical_reason().unwrap_or("Request failed"),
    );
    if code == "upload_in_progress" {
        api_error.retry_after_seconds = Some(1);
    }
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
    if success.warnings().any() {
        response.headers_mut().insert(
            "x-vaultlink-upload-warnings",
            HeaderValue::from_static(success.warnings().header()),
        );
    }
    Ok(response)
}

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}
