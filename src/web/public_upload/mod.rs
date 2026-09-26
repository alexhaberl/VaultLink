use axum::{
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[path = "presenter.rs"]
mod presenter;
pub(super) use presenter::{error_response as upload_queue_error_response, UploadQueueSuccess};

#[derive(Serialize)]
struct UploadOperationTicket {
    upload_id: String,
    expires_at: String,
    status_url: String,
}

pub(super) async fn create_operation(
    State(state): State<PublicUploadRouteState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
) -> Result<Response> {
    let issued = crate::public_upload_transport::create_public_upload_operation(
        &state.into_upload_context(),
        &headers,
        &token,
    )
    .await
    .map_err(|error| transport_error(&error))?
    .ok_or(AppError(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many upload operations",
    ))?;
    let (upload_id, expires_at) = issued;
    Ok((
        StatusCode::CREATED,
        Json(UploadOperationTicket {
            status_url: format!("/v/{token}/upload/operations/{upload_id}"),
            upload_id,
            expires_at,
        }),
    )
        .into_response())
}

pub(super) async fn operation_status(
    State(state): State<PublicUploadRouteState>,
    headers: HeaderMap,
    AxPath((token, upload_id)): AxPath<(String, String)>,
) -> Result<Response> {
    let view = crate::public_upload_transport::public_upload_operation(
        &state.into_upload_context(),
        &headers,
        &token,
        &upload_id,
    )
    .await
    .map_err(|error| transport_error(&error))?
    .ok_or(AppError(StatusCode::GONE, "Upload operation unavailable"))?;
    Ok(Json(view).into_response())
}

use crate::{
    public_upload_transport::{
        execute_public_upload, PublicUploadOutcome, PublicUploadRejection,
        PublicUploadTransportError,
    },
    PublicUploadRouteState,
};

use super::{AppError, Result};

#[cfg(test)]
pub(super) use crate::public_upload_transport::{
    install_public_upload_test_hook, PublicUploadTestHook, PublicUploadTestPhase,
};

fn transport_error(error: &PublicUploadTransportError) -> AppError {
    AppError(error.status(), error.message())
}

pub(crate) async fn upload(
    State(state): State<PublicUploadRouteState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    multipart: Multipart,
) -> Result<Response> {
    let outcome = match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token.clone(),
        multipart,
        None,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error)
            if error.status() == StatusCode::CONFLICT
                && error.message() == "Upload ID conflicts with request" =>
        {
            let route = super::transfer_runtime::public_share_route(&uri, &token);
            return Ok(
                axum::response::Redirect::to(&format!("{route}?upload=id_conflict"))
                    .into_response(),
            );
        }
        Err(error) => return Err(transport_error(&error)),
    };
    match outcome {
        PublicUploadOutcome::Success(success) => {
            presenter::success_response(&uri, &token, &success)
        }
        PublicUploadOutcome::Rejected(rejection) => {
            Ok(presenter::rejection_response(&token, &rejection))
        }
    }
}

pub(super) async fn upload_queue(
    State(state): State<PublicUploadRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    mut multipart: Multipart,
) -> Result<Response> {
    crate::public_upload_transport::preflight_upload_authorization(
        &state.clone().into_upload_context(),
        &headers,
        &token,
    )
    .await
    .map_err(|error| transport_error(&error))?;
    let upload_id = crate::upload_operation::take_upload_id(&mut multipart, &headers)
        .await
        .map_err(|message| AppError(StatusCode::BAD_REQUEST, message))?;
    let status_url = Some(format!("/v/{token}/upload/operations/{}", upload_id.id));
    let outcome = match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token,
        multipart,
        Some(upload_id),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(presenter::error_response_with_status_url(
                error.status(),
                error.message(),
                status_url,
            ));
        }
    };
    match outcome {
        PublicUploadOutcome::Success(success) => {
            let warnings = success.warnings();
            let status = if warnings.any() {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            Ok((
                status,
                Json(UploadQueueSuccess {
                    file: success.file().to_string(),
                    outcome: success.disposition().outcome().to_string(),
                    warning: warnings.legacy_code(),
                    warnings: warnings.codes(),
                }),
            )
                .into_response())
        }
        PublicUploadOutcome::Rejected(rejection) => Ok(upload_queue_error_response(
            rejection.status(),
            rejection
                .status()
                .canonical_reason()
                .unwrap_or("Upload failed"),
        )),
    }
}

pub(super) async fn prepare_upload(
    State(state): State<PublicUploadRouteState>,
    mut headers: HeaderMap,
    AxPath(token): AxPath<String>,
    axum::extract::Form(form): axum::extract::Form<super::upload_prepare::UploadPrepareForm>,
) -> Result<axum::response::Html<String>> {
    let state = state.into_upload_context();
    let (upload_id, path, allow_overwrite) =
        crate::public_upload_transport::prepare_public_upload_operation(
            &state,
            &mut headers,
            &token,
            &form.path,
            &form.csrf,
        )
        .await
        .map_err(|error| transport_error(&error))?;
    super::upload_prepare::PreparedUploadTemplate {
        action: format!("/v/{token}/upload"),
        back_link: format!("/v/{token}"),
        path,
        csrf: form.csrf,
        upload_id,
        allow_overwrite,
    }
    .render_page()
}
