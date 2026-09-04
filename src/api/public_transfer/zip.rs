use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::io::ReaderStream;

use crate::{
    http_auth::{
        current_audit_client_ip, current_client_limit_key, make_transfer_cookie, runtime_settings,
        share_is_unlocked, transfer_cookie, ClientActivityPermit, TransferCookieScope,
    },
    internal_reporting::{report_internal, InternalOperation},
    services::public_transfer::{
        build_zip_temp, direct_zip_stream_with_resources, plan_zip, transfer_stream,
        PublicTransferClient, PublicTransferLease, PublicTransferService, ReservedZipStream,
        ZipBuildError, ZipPlan, ZipTempReservation, BUFFERED_RESPONSE_CHUNK_BYTES,
    },
    PublicTransferRouteState,
};

use super::{download_adapter::BrowseQuery, set_transfer_cookie, ApiError, ApiResult};

struct GenerationResources {
    _zip_permit: OwnedSemaphorePermit,
    _peer_permit: ClientActivityPermit,
}

struct TransferResources {
    generation: GenerationResources,
    transfer: PublicTransferLease,
}

impl TransferResources {
    fn session_token(&self) -> &str {
        self.transfer.session_token()
    }

    async fn cancel(self) {
        drop(self.generation);
        self.transfer.cancel().await;
    }
}

struct MaterializationResources {
    transfer: TransferResources,
    reservation: ZipTempReservation,
}

async fn blocking_with_resources<R, T, F>(
    resources: R,
    operation: F,
) -> Result<(R, T), tokio::task::JoinError>
where
    R: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::spawn(async move {
        let output = tokio::task::spawn_blocking(operation).await?;
        Ok::<_, tokio::task::JoinError>((resources, output))
    })
    .await?
}

pub(crate) async fn download_zip(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> ApiResult<Response> {
    let service = state.public_transfer_service();
    let share = service.share_for_transfer(&token).await?;
    authorize(&state, &headers, &share).await?;
    let (share, guard) = service.storage_share_for_transfer(&token, share.id).await?;
    authorize(&state, &headers, &share).await?;
    let prepared = service
        .prepare_zip_scope(share, query.path.as_deref(), guard)
        .await?;
    let resources = begin_resources(&state, &service, &headers, &prepared).await?;
    let cookie = make_transfer_cookie(
        &state,
        &prepared.share,
        resources.session_token(),
        TransferCookieScope::Api,
    );
    let name = zip_filename(&prepared.share.relative_path);
    let body = prepare_body(&state, resources, prepared).await?;
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    let disposition = HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{name}"))
        .map_err(|error| {
            ApiError::from(report_internal(
                InternalOperation::WebZipDispositionHeader,
                error,
            ))
        })?;
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, disposition);
    set_transfer_cookie(&mut response, &cookie)?;
    Ok(response)
}

async fn authorize(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &crate::db::Share,
) -> ApiResult<()> {
    if !share_is_unlocked(state, headers, share).await? {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    }
    if !share.is_directory || !share.permission.can_download() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
        ));
    }
    Ok(())
}

async fn begin_resources(
    state: &PublicTransferRouteState,
    service: &PublicTransferService,
    headers: &HeaderMap,
    prepared: &crate::services::public_transfer::PreparedZipScope,
) -> ApiResult<TransferResources> {
    let generation = GenerationResources {
        _peer_permit: state
            .try_acquire_expensive_peer(current_client_limit_key())
            .ok_or_else(capacity_error)?,
        _zip_permit: state
            .try_acquire_zip_generation()
            .map_err(|_| capacity_error())?,
    };
    let resource_key = if prepared.subpath.is_empty() {
        ".".to_owned()
    } else {
        prepared.subpath.clone()
    };
    let client = PublicTransferClient {
        client_key: current_client_limit_key().to_string(),
        session_token: transfer_cookie(headers, prepared.share.id).map(str::to_owned),
        audit_client_ip: runtime_settings(state)
            .audit_client_ip_enabled
            .then(current_audit_client_ip)
            .flatten()
            .map(|ip| ip.to_string()),
    };
    let transfer = service
        .begin(&prepared.share, client, resource_key, "zip_download")
        .await?;
    Ok(TransferResources {
        generation,
        transfer,
    })
}

fn capacity_error() -> ApiError {
    let mut error = ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "internal_error",
        "Service Unavailable",
    );
    error.retry_after_seconds = Some(1);
    error
}

async fn prepare_body(
    state: &PublicTransferRouteState,
    resources: TransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
) -> ApiResult<Body> {
    let settings = runtime_settings(state);
    let directory = prepared.directory.clone();
    let path = prepared.subpath.clone();
    let (resources, plan) =
        blocking_with_resources(resources, move || plan_zip(&directory, &path, &settings))
            .await
            .map_err(|error| {
                ApiError::from(report_internal(
                    InternalOperation::WebZipPlanTaskJoin,
                    error,
                ))
            })?;
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            resources.cancel().await;
            return Err(zip_error(&error));
        }
    };
    let reservation = if plan.requires_direct_stream() {
        Ok(None)
    } else {
        ZipTempReservation::acquire(state, plan.estimated_archive_size).await
    };
    let reservation = match reservation {
        Ok(reservation) => reservation,
        Err(_) => {
            resources.cancel().await;
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "internal_error",
                "Service Unavailable",
            ));
        }
    };
    if let Some(reservation) = reservation {
        materialize(state, resources, prepared, plan, reservation).await
    } else {
        Ok(direct_body(state, resources, prepared, plan))
    }
}

async fn materialize(
    state: &PublicTransferRouteState,
    resources: TransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
    plan: ZipPlan,
    reservation: ZipTempReservation,
) -> ApiResult<Body> {
    let materialization = MaterializationResources {
        transfer: resources,
        reservation,
    };
    let directory = prepared.directory.clone();
    let (materialization, (plan, result)) = blocking_with_resources(materialization, move || {
        let result = build_zip_temp(&directory, &plan).and_then(|file| {
            let length = file.metadata().map_err(ZipBuildError::Output)?.len();
            Ok((file, length))
        });
        (plan, result)
    })
    .await
    .map_err(|error| {
        ApiError::from(report_internal(
            InternalOperation::WebZipMaterializeTaskJoin,
            error,
        ))
    })?;
    match result {
        Ok((file, length)) => Ok(materialized_body(
            state,
            materialization,
            prepared.share.id,
            file,
            length,
        )),
        Err(error) if error.is_output_capacity_error() => {
            let MaterializationResources {
                transfer,
                reservation,
            } = materialization;
            drop(reservation);
            Ok(direct_body(state, transfer, prepared, plan))
        }
        Err(error) => {
            let MaterializationResources {
                transfer,
                reservation,
            } = materialization;
            drop(reservation);
            transfer.cancel().await;
            Err(zip_error(&error))
        }
    }
}

fn materialized_body(
    state: &PublicTransferRouteState,
    materialization: MaterializationResources,
    share_id: i64,
    file: std::fs::File,
    length: u64,
) -> Body {
    let MaterializationResources {
        transfer,
        reservation,
    } = materialization;
    drop(transfer.generation);
    Body::from_stream(transfer_stream(
        ReservedZipStream {
            inner: ReaderStream::with_capacity(
                tokio::fs::File::from_std(file),
                BUFFERED_RESPONSE_CHUNK_BYTES,
            ),
            _reservation: reservation,
        },
        state,
        transfer.transfer,
        "zip_download",
        share_id,
        Some(length),
    ))
}

fn direct_body(
    state: &PublicTransferRouteState,
    resources: TransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
    plan: ZipPlan,
) -> Body {
    Body::from_stream(transfer_stream(
        direct_zip_stream_with_resources(prepared.directory, plan, resources.generation, || {}),
        state,
        resources.transfer,
        "zip_download",
        prepared.share.id,
        None,
    ))
}

fn zip_error(error: &ZipBuildError) -> ApiError {
    match error {
        ZipBuildError::Limit(_) => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Payload Too Large",
        ),
        ZipBuildError::Source(_) => ApiError::new(StatusCode::NOT_FOUND, "not_found", "Not Found"),
        ZipBuildError::Output(_) => {
            let _reported = report_internal(InternalOperation::WebZipOutputFailure, error);
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal Server Error",
            )
        }
    }
}

fn zip_filename(relative_path: &str) -> String {
    let name = Path::new(relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    percent_encoding::utf8_percent_encode(
        &format!("{name}.zip"),
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string()
}
