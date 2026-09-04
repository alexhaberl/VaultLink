use axum::{
    extract::{Json, Multipart, OriginalUri, Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

#[path = "presenter.rs"]
mod presenter;
pub(super) use presenter::{error_response as upload_queue_error_response, UploadQueueSuccess};

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
    match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token.clone(),
        multipart,
    )
    .await
    .map_err(|error| transport_error(&error))?
    {
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
    multipart: Multipart,
) -> Result<Response> {
    let outcome = match execute_public_upload(
        state.into_upload_context(),
        &headers,
        token,
        multipart,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(upload_queue_error_response(error.status(), error.message()));
        }
    };
    match outcome {
        PublicUploadOutcome::Success(success) => {
            let audit_uncertain = success.audit_durability_uncertain();
            let status = if audit_uncertain {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            Ok((
                status,
                Json(UploadQueueSuccess {
                    file: success.file().to_string(),
                    outcome: success.disposition().outcome().to_string(),
                    warning: audit_uncertain.then_some("audit_durability_uncertain"),
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
