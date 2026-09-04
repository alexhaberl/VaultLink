use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use tokio_util::io::ReaderStream;

use crate::{
    http_auth::{
        current_audit_client_ip, current_client_limit_key, make_transfer_cookie, runtime_settings,
        share_is_unlocked, transfer_cookie, TransferCookieScope,
    },
    internal_reporting::{report_internal, InternalOperation},
    services::public_transfer::{
        build_zip_temp, direct_zip_stream_with_resources, plan_zip, transfer_stream,
        PublicTransferClient, PublicTransferService, ReservedZipStream, ZipBuildError, ZipPlan,
        ZipTempReservation,
    },
    PublicTransferRouteState,
};

#[cfg(test)]
use super::{block_zip_for_test, zip_test_phase_active, ZipBlockingTestPhase};
use super::{
    zip_blocking_with_resources, ZipGenerationResources, ZipMaterializationResources,
    ZipTransferResources,
};
use crate::web::{
    common::{encoded, BrowseQuery},
    transfer::PreparedZip,
    transfer_runtime::set_transfer_cookie,
    AppError, Result, BUFFERED_RESPONSE_CHUNK_BYTES,
};

pub(crate) async fn download_zip(
    State(state): State<PublicTransferRouteState>,
    OriginalUri(_uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Response> {
    let service = state.public_transfer_service();
    let share = service.share_for_transfer(&token).await?;
    authorize_zip(&state, &headers, &share).await?;
    let (share, storage_guard) = service.storage_share_for_transfer(&token, share.id).await?;
    authorize_zip(&state, &headers, &share).await?;
    let prepared = service
        .prepare_zip_scope(share, query.path.as_deref(), storage_guard)
        .await?;
    let resources = begin_zip_resources(&state, &service, &headers, &prepared).await?;
    let cookie = make_transfer_cookie(
        &state,
        &prepared.share,
        resources.session_token(),
        TransferCookieScope::Web,
    );
    let filename = zip_filename(&prepared.share.relative_path);
    let body = prepare_zip_body(&state, resources, prepared).await?;
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    let disposition = HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
        .map_err(|error| {
            AppError::from(report_internal(
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

async fn authorize_zip(
    state: &PublicTransferRouteState,
    headers: &HeaderMap,
    share: &crate::db::Share,
) -> Result<()> {
    if !share_is_unlocked(state, headers, share).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !share.is_directory || !share.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "ZIP download not allowed"));
    }
    Ok(())
}

async fn begin_zip_resources(
    state: &PublicTransferRouteState,
    service: &PublicTransferService,
    headers: &HeaderMap,
    prepared: &crate::services::public_transfer::PreparedZipScope,
) -> Result<ZipTransferResources> {
    let generation = ZipGenerationResources {
        _peer_permit: state
            .try_acquire_expensive_peer(current_client_limit_key())
            .ok_or(AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent expensive operations from this client",
            ))?,
        _zip_permit: state.try_acquire_zip_generation().map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent ZIP builds",
            )
        })?,
    };
    let resource_key = if prepared.subpath.is_empty() {
        ".".to_owned()
    } else {
        prepared.subpath.clone()
    };
    let session_token = transfer_cookie(headers, prepared.share.id).map(str::to_owned);
    let client = PublicTransferClient {
        client_key: current_client_limit_key().to_string(),
        session_token,
        audit_client_ip: runtime_settings(state)
            .audit_client_ip_enabled
            .then(current_audit_client_ip)
            .flatten()
            .map(|ip| ip.to_string()),
    };
    let transfer = service
        .begin(&prepared.share, client, resource_key, "zip_download")
        .await?;
    Ok(ZipTransferResources {
        generation,
        transfer,
    })
}

async fn prepare_zip_body(
    state: &PublicTransferRouteState,
    resources: ZipTransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
) -> Result<Body> {
    let settings = runtime_settings(state);
    let plan_directory = prepared.directory.clone();
    let plan_path = prepared.subpath.clone();
    #[cfg(test)]
    let plan_test_path = prepared.share.relative_path.clone();
    let (resources, plan) = zip_blocking_with_resources(resources, move || {
        #[cfg(test)]
        block_zip_for_test(&plan_test_path, ZipBlockingTestPhase::Plan);
        plan_zip(&plan_directory, &plan_path, &settings)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
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
    let reservation = zip_reservation(state, &prepared.share.relative_path, &plan).await;
    let reservation = match reservation {
        Ok(reservation) => reservation,
        Err(_) => {
            resources.cancel().await;
            return Err(AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage capacity could not be determined",
            ));
        }
    };
    if let Some(reservation) = reservation {
        materialized_or_direct(state, resources, prepared, plan, reservation).await
    } else {
        Ok(direct_body(state, resources, prepared, plan))
    }
}

async fn zip_reservation(
    state: &PublicTransferRouteState,
    test_path: &str,
    plan: &ZipPlan,
) -> std::io::Result<Option<ZipTempReservation>> {
    #[cfg(not(test))]
    let _ = test_path;
    #[cfg(test)]
    {
        if plan.requires_direct_stream()
            || zip_test_phase_active(test_path, ZipBlockingTestPhase::Direct)
        {
            return Ok(None);
        }
        if zip_test_phase_active(test_path, ZipBlockingTestPhase::Materialize) {
            return Ok(Some(ZipTempReservation::acquire_unchecked_for_test(
                plan.estimated_archive_size,
            )));
        }
    }
    if plan.requires_direct_stream() {
        Ok(None)
    } else {
        ZipTempReservation::acquire(state, plan.estimated_archive_size).await
    }
}

async fn materialized_or_direct(
    state: &PublicTransferRouteState,
    resources: ZipTransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
    plan: ZipPlan,
    reservation: ZipTempReservation,
) -> Result<Body> {
    let materialization = ZipMaterializationResources {
        transfer: resources,
        reservation,
    };
    let directory = prepared.directory.clone();
    #[cfg(test)]
    let test_path = prepared.share.relative_path.clone();
    let (materialization, (plan, result)) =
        zip_blocking_with_resources(materialization, move || {
            #[cfg(test)]
            block_zip_for_test(&test_path, ZipBlockingTestPhase::Materialize);
            let result = build_zip_temp(&directory, &plan).and_then(|file| {
                let length = file.metadata().map_err(ZipBuildError::Output)?.len();
                Ok((file, length))
            });
            (plan, result)
        })
        .await
        .map_err(|error| {
            AppError::from(report_internal(
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
            let ZipMaterializationResources {
                transfer,
                reservation,
            } = materialization;
            drop(reservation);
            Ok(direct_body(state, transfer, prepared, plan))
        }
        Err(error) => {
            let ZipMaterializationResources {
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
    materialization: ZipMaterializationResources,
    share_id: i64,
    file: std::fs::File,
    length: u64,
) -> Body {
    let ZipMaterializationResources {
        transfer,
        reservation,
    } = materialization;
    PreparedZip::materialized(transfer, move |lease| {
        Body::from_stream(transfer_stream(
            ReservedZipStream {
                inner: ReaderStream::with_capacity(
                    tokio::fs::File::from_std(file),
                    BUFFERED_RESPONSE_CHUNK_BYTES,
                ),
                _reservation: reservation,
            },
            state,
            lease,
            "zip_download",
            share_id,
            Some(length),
        ))
    })
    .into_body()
}

fn direct_body(
    state: &PublicTransferRouteState,
    resources: ZipTransferResources,
    prepared: crate::services::public_transfer::PreparedZipScope,
    plan: ZipPlan,
) -> Body {
    let share_id = prepared.share.id;
    #[cfg(test)]
    let test_path = prepared.share.relative_path.clone();
    PreparedZip::direct(resources, move |lease, generation| {
        Body::from_stream(transfer_stream(
            direct_zip_stream_with_resources(prepared.directory, plan, generation, move || {
                #[cfg(test)]
                block_zip_for_test(&test_path, ZipBlockingTestPhase::Direct);
            }),
            state,
            lease,
            "zip_download",
            share_id,
            None,
        ))
    })
    .into_body()
}

fn zip_error(error: &ZipBuildError) -> AppError {
    match error {
        ZipBuildError::Limit(_) => AppError(StatusCode::PAYLOAD_TOO_LARGE, "ZIP limit reached"),
        ZipBuildError::Source(_) => AppError(StatusCode::NOT_FOUND, "ZIP source unavailable"),
        ZipBuildError::Output(_) => {
            let _reported = report_internal(InternalOperation::WebZipOutputFailure, error);
            AppError(StatusCode::INTERNAL_SERVER_ERROR, "ZIP creation failed")
        }
    }
}

fn zip_filename(relative_path: &str) -> String {
    let name = Path::new(relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    encoded(&format!("{name}.zip"))
}
