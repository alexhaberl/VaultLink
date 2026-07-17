use std::path::Path;

use axum::{
    body::Body,
    extract::{OriginalUri, Path as AxPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::io::ReaderStream;

use crate::{
    http_auth::{
        current_client_limit_key, runtime_settings, share_is_unlocked, try_acquire_client_activity,
        ClientActivityPermit,
    },
    path_security,
    range::parse_byte_range,
    secure_fs::SecureFile,
    AppState,
};

struct ZipGenerationResources {
    _zip_permit: OwnedSemaphorePermit,
    _peer_permit: ClientActivityPermit,
}

/// Owns every live-request resource while ZIP planning or materialization is
/// still running. It is deliberately moved into a detached supervisor before
/// each `spawn_blocking`: cancelling the HTTP future therefore cannot release
/// either admission permit or the transfer lease while blocking work remains.
struct ZipTransferResources {
    generation: ZipGenerationResources,
    transfer: super::transfer_runtime::PublicTransferLease,
}

impl ZipTransferResources {
    fn cookie(&self) -> &str {
        self.transfer.cookie()
    }

    async fn cancel(self) {
        let Self {
            generation,
            transfer,
        } = self;
        drop(generation);
        transfer.cancel().await;
    }
}

struct ZipMaterializationResources {
    transfer: ZipTransferResources,
    reservation: ZipTempReservation,
}

enum PreparedZip {
    Materialized(Body),
    Direct(Body),
}

impl PreparedZip {
    fn materialized<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(super::transfer_runtime::PublicTransferLease) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        // A materialized archive no longer consumes a generation slot while a
        // slow client downloads it.
        drop(generation);
        Self::Materialized(body(transfer))
    }

    fn direct<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(super::transfer_runtime::PublicTransferLease, ZipGenerationResources) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        Self::Direct(body(transfer, generation))
    }

    fn into_body(self) -> Body {
        match self {
            Self::Materialized(body) | Self::Direct(body) => body,
        }
    }
}

/// Retains `resources` in a detached Tokio task until the blocking operation
/// actually terminates. Dropping the caller's future detaches the supervisor;
/// it does not drop the resources around an in-flight blocking task.
async fn zip_blocking_with_resources<R, T, F>(
    resources: R,
    operation: F,
) -> std::result::Result<(R, T), tokio::task::JoinError>
where
    R: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let supervisor = tokio::spawn(async move {
        let output = tokio::task::spawn_blocking(operation).await?;
        Ok::<_, tokio::task::JoinError>((resources, output))
    });
    supervisor.await?
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ZipBlockingTestPhase {
    Plan,
    Materialize,
    Direct,
}

#[cfg(test)]
pub(super) struct ZipBlockingTestHook {
    pub(super) path: String,
    pub(super) phase: ZipBlockingTestPhase,
    pub(super) panic_after_release: bool,
    pub(super) entered: std::sync::atomic::AtomicUsize,
    pub(super) released: std::sync::Mutex<bool>,
    pub(super) wake: std::sync::Condvar,
}

#[cfg(test)]
impl ZipBlockingTestHook {
    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
pub(super) struct ZipBlockingTestGuard(pub(super) std::sync::Arc<ZipBlockingTestHook>);

#[cfg(test)]
impl Drop for ZipBlockingTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut hooks = ZIP_BLOCKING_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.retain(|active| !std::sync::Arc::ptr_eq(active, &self.0));
    }
}

#[cfg(test)]
pub(super) static ZIP_BLOCKING_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Vec<std::sync::Arc<ZipBlockingTestHook>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(super) fn install_zip_blocking_test_hook(
    hook: std::sync::Arc<ZipBlockingTestHook>,
) -> ZipBlockingTestGuard {
    ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(hook.clone());
    ZipBlockingTestGuard(hook)
}

#[cfg(test)]
fn zip_test_phase_active(path: &str, phase: ZipBlockingTestPhase) -> bool {
    ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|hook| hook.path == path && hook.phase == phase)
}

#[cfg(test)]
fn block_zip_for_test(path: &str, phase: ZipBlockingTestPhase) {
    let hook = ZIP_BLOCKING_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|hook| hook.path == path && hook.phase == phase)
        .cloned();
    let Some(hook) = hook else {
        return;
    };
    hook.entered
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut released = hook.released.lock().unwrap();
    while !*released {
        released = hook.wake.wait(released).unwrap();
    }
    drop(released);
    if hook.panic_after_release {
        panic!("injected ZIP blocking task panic");
    }
}

use super::preview_zip::{
    build_zip_temp, direct_zip_stream_with_resources, plan_zip, zip_error, ReservedZipStream,
    ZipTempReservation,
};
use super::{
    common::{encoded, internal, BrowseQuery},
    public::{get_share_for_transfer, get_storage_share_for_transfer},
    transfer_runtime::{
        begin_public_transfer, check_public_transfer_availability, complete_transfer_without_body,
        set_transfer_cookie, transfer_body,
    },
    AppError, Result,
};

pub(crate) async fn download_zip(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share_for_transfer(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.is_directory || !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "ZIP download not allowed"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share_for_transfer(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.is_directory || !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "ZIP download not allowed"));
    }
    let sub = path_security::validate_relative(q.path.as_deref().unwrap_or_default())
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid ZIP path"))?
        .to_string_lossy()
        .replace('\\', "/");
    let generation = ZipGenerationResources {
        _peer_permit: try_acquire_client_activity(
            state.expensive_peer_admission.clone(),
            current_client_limit_key(),
            crate::MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent expensive operations from this client",
        ))?,
        _zip_permit: state
            .zip_generation_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Too many concurrent ZIP builds",
                )
            })?,
    };
    let settings = runtime_settings(&state);
    let secure_root = state
        .secure_root
        .bind_directory(&sh.relative_path)
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Share target unavailable"))?;
    drop(storage_guard);
    let resource_key = if sub.is_empty() {
        ".".to_string()
    } else {
        sub.clone()
    };
    let transfer =
        begin_public_transfer(&state, &headers, &uri, &sh, resource_key, "zip_download").await?;
    let resources = ZipTransferResources {
        generation,
        transfer,
    };
    let transfer_cookie_value = resources.cookie().to_string();
    let plan_scope = secure_root.clone();
    let plan_path = sub.clone();
    let plan_settings = settings.clone();
    #[cfg(test)]
    let plan_test_path = sh.relative_path.clone();
    let (resources, plan) = zip_blocking_with_resources(resources, move || {
        #[cfg(test)]
        block_zip_for_test(&plan_test_path, ZipBlockingTestPhase::Plan);
        plan_zip(&plan_scope, &plan_path, &plan_settings)
    })
    .await
    .map_err(internal)?;
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            resources.cancel().await;
            return Err(zip_error(&error));
        }
    };
    #[cfg(test)]
    let temp_reservation = if zip_test_phase_active(&sh.relative_path, ZipBlockingTestPhase::Direct)
    {
        Ok(None)
    } else if zip_test_phase_active(&sh.relative_path, ZipBlockingTestPhase::Materialize) {
        Ok(Some(ZipTempReservation::acquire_unchecked_for_test(
            plan.estimated_archive_size,
        )))
    } else {
        ZipTempReservation::acquire(&state, plan.estimated_archive_size).await
    };
    #[cfg(not(test))]
    let temp_reservation = ZipTempReservation::acquire(&state, plan.estimated_archive_size).await;
    let temp_reservation = match temp_reservation {
        Ok(reservation) => reservation,
        Err(_) => {
            resources.cancel().await;
            return Err(AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Storage capacity could not be determined",
            ));
        }
    };
    let prepared = if let Some(reservation) = temp_reservation {
        let materialization = ZipMaterializationResources {
            transfer: resources,
            reservation,
        };
        let temp_scope = secure_root.clone();
        let temp_plan = plan.clone();
        #[cfg(test)]
        let materialization_test_path = sh.relative_path.clone();
        let (materialization, build_result) =
            zip_blocking_with_resources(materialization, move || {
                #[cfg(test)]
                block_zip_for_test(
                    &materialization_test_path,
                    ZipBlockingTestPhase::Materialize,
                );
                build_zip_temp(&temp_scope, &temp_plan)
            })
            .await
            .map_err(internal)?;
        match build_result {
            Ok(file) => {
                let ZipMaterializationResources {
                    transfer: resources,
                    reservation,
                } = materialization;
                let content_length = file.metadata().ok().map(|metadata| metadata.len());
                PreparedZip::materialized(resources, move |transfer| {
                    let stream = ReservedZipStream {
                        inner: ReaderStream::new(tokio::fs::File::from_std(file)),
                        _reservation: reservation,
                    };
                    transfer_body(
                        stream,
                        &state,
                        transfer,
                        "zip_download",
                        sh.id,
                        content_length,
                    )
                })
            }
            Err(error) if error.is_output_capacity_error() => {
                let ZipMaterializationResources {
                    transfer: resources,
                    reservation,
                } = materialization;
                drop(reservation);
                #[cfg(test)]
                let direct_test_path = sh.relative_path.clone();
                PreparedZip::direct(resources, move |transfer, generation| {
                    transfer_body(
                        direct_zip_stream_with_resources(
                            secure_root,
                            plan,
                            generation,
                            move || {
                                #[cfg(test)]
                                block_zip_for_test(&direct_test_path, ZipBlockingTestPhase::Direct);
                            },
                        ),
                        &state,
                        transfer,
                        "zip_download",
                        sh.id,
                        None,
                    )
                })
            }
            Err(error) => {
                let ZipMaterializationResources {
                    transfer: resources,
                    reservation,
                } = materialization;
                drop(reservation);
                resources.cancel().await;
                return Err(zip_error(&error));
            }
        }
    } else {
        #[cfg(test)]
        let direct_test_path = sh.relative_path.clone();
        PreparedZip::direct(resources, move |transfer, generation| {
            transfer_body(
                direct_zip_stream_with_resources(secure_root, plan, generation, move || {
                    #[cfg(test)]
                    block_zip_for_test(&direct_test_path, ZipBlockingTestPhase::Direct);
                }),
                &state,
                transfer,
                "zip_download",
                sh.id,
                None,
            )
        })
    };
    let name = Path::new(&sh.relative_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vaultlink");
    let filename = encoded(&format!("{name}.zip"));
    let body = prepared.into_body();
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
            .map_err(internal)?,
    );
    // Deliberately omit Content-Length for counted GETs. Hyper must poll the
    // wrapped stream through EOF before the transfer lease can be committed.
    set_transfer_cookie(&mut response, &transfer_cookie_value)?;
    Ok(response)
}

pub(crate) async fn download(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response> {
    let sh = get_share_for_transfer(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download not allowed"));
    }
    let expected_id = sh.id;
    let (sh, storage_guard) = get_storage_share_for_transfer(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &sh).await? {
        return Err(AppError(StatusCode::UNAUTHORIZED, "Share is locked"));
    }
    if !sh.permission.can_download() {
        return Err(AppError(StatusCode::FORBIDDEN, "Download not allowed"));
    }
    let relative_file = if sh.is_directory {
        let rel = q
            .path
            .ok_or(AppError(StatusCode::BAD_REQUEST, "File path missing"))?;
        path_security::validate_relative(&rel)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid file path"))?
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        sh.relative_path.clone()
    };
    let file = if sh.is_directory {
        state
            .secure_root
            .bind_directory(&sh.relative_path)
            .and_then(|directory| directory.open_file(&relative_file))
            .map(SecureFile::into_file)
    } else {
        state
            .secure_root
            .bind_file(&sh.relative_path)
            .map(SecureFile::into_file)
    }
    .map_err(|_| AppError(StatusCode::NOT_FOUND, "File unavailable"))?;
    drop(storage_guard);
    check_public_transfer_availability(&state, &headers, &sh, relative_file.clone(), "download")
        .await?;
    if !file.metadata().map_err(internal)?.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Not a file"));
    }
    let mut f = tokio::fs::File::from_std(file);
    let length = f.metadata().await.map_err(internal)?.len();
    let range = match headers.get(header::RANGE) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_byte_range(value, length).ok())
        {
            Some(range) => Some(range),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).map_err(internal)?,
                );
                return Ok(response);
            }
        },
        None => None,
    };
    let transfer = if method == Method::GET {
        Some(
            begin_public_transfer(
                &state,
                &headers,
                &uri,
                &sh,
                relative_file.clone(),
                "download",
            )
            .await?,
        )
    } else {
        None
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }
    let name = Path::new(&relative_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("download");
    let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    let (body, transfer_cookie_value) = if let Some(transfer) = transfer {
        let cookie = transfer.cookie().to_string();
        let body = if response_length == 0 {
            complete_transfer_without_body(&state, transfer, "download", sh.id).await?;
            Body::empty()
        } else {
            transfer_body(
                ReaderStream::new(f.take(response_length)),
                &state,
                transfer,
                "download",
                sh.id,
                Some(response_length),
            )
        };
        (body, Some(cookie))
    } else {
        (Body::empty(), None)
    };
    let mut r = Response::new(body);
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{length}")).map_err(internal)?,
        );
    }
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_length.to_string()).map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            mime_guess::from_path(&relative_file)
                .first_or_octet_stream()
                .as_ref(),
        )
        .map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
            .map_err(internal)?,
    );
    if let Some(cookie) = transfer_cookie_value {
        set_transfer_cookie(&mut r, &cookie)?;
    }
    Ok(r)
}
