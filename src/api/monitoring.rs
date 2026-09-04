use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    db::{
        MonitoringShare, MonitoringShareListOptions, MonitoringShareListStatus, MonitoringSummary,
        Permission,
    },
    http_auth::{authorize_monitoring, current_client_limit_key, database},
    MonitoringRouteState,
};

use super::{ApiError, ApiResult};

const MONITORING_RETRY_AFTER_SECONDS: u64 = 60;

fn admit_monitoring_request(state: &MonitoringRouteState) -> ApiResult<()> {
    let key = current_client_limit_key().to_string();
    if state.monitoring_limiter().check_and_record_attempt(&key) {
        Ok(())
    } else {
        Err(ApiError::rate_limited(
            "Too many monitoring requests",
            MONITORING_RETRY_AFTER_SECONDS,
        ))
    }
}

#[derive(Serialize)]
struct MonitoringShareCountsResponse {
    total: u64,
    available: u64,
    inactive: u64,
    expired: u64,
    download_limit_reached: u64,
    protected: u64,
}

#[derive(Serialize)]
struct MonitoringTransferResponse {
    month: String,
    download: u64,
    zip_download: u64,
    preview: u64,
    statistics_started_at: String,
}

#[derive(Serialize)]
struct MonitoringStorageResponse {
    free_bytes: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
pub(super) struct MonitoringSummaryResponse {
    generated_at: DateTime<Utc>,
    version: &'static str,
    shares: MonitoringShareCountsResponse,
    transfers: MonitoringTransferResponse,
    storage: Option<MonitoringStorageResponse>,
}

impl MonitoringSummaryResponse {
    fn new(
        summary: MonitoringSummary,
        generated_at: DateTime<Utc>,
        storage: Option<crate::disk_stats::DiskStats>,
    ) -> Self {
        Self {
            generated_at,
            version: env!("CARGO_PKG_VERSION"),
            shares: MonitoringShareCountsResponse {
                total: summary.total,
                available: summary.available,
                inactive: summary.inactive,
                expired: summary.expired,
                download_limit_reached: summary.download_limit_reached,
                protected: summary.protected,
            },
            transfers: MonitoringTransferResponse {
                month: summary.transfers.month,
                download: summary.transfers.download,
                zip_download: summary.transfers.zip_download,
                preview: summary.transfers.preview,
                statistics_started_at: summary.statistics_started_at,
            },
            storage: storage.map(|stats| MonitoringStorageResponse {
                free_bytes: stats.free,
                total_bytes: stats.total,
            }),
        }
    }
}

pub(super) async fn monitoring_summary(
    State(state): State<MonitoringRouteState>,
    headers: HeaderMap,
) -> ApiResult<Json<MonitoringSummaryResponse>> {
    admit_monitoring_request(&state)?;
    authorize_monitoring(&state, &headers).await?;
    let cache = state.monitoring_summary_cache().clone();
    let database_handle = state.db().clone();
    let disk_stats = state.disk_stats_cache().clone();
    let storage_root = state.secure_root().display_root().to_path_buf();
    let snapshot = cache
        .get_or_try_insert(|| async move {
            let generated_at = Utc::now();
            let database_future = database(database_handle, move |database| {
                database.monitoring_summary(generated_at)
            });
            let storage_future = disk_stats.get(&storage_root);
            let (summary, storage) = tokio::join!(database_future, storage_future);
            Ok::<_, crate::http_auth::HttpAuthError>(
                crate::monitoring_cache::MonitoringSummarySnapshot {
                    generated_at,
                    summary: summary?,
                    storage: storage.ok(),
                },
            )
        })
        .await?;
    Ok(Json(MonitoringSummaryResponse::new(
        snapshot.summary,
        snapshot.generated_at,
        snapshot.storage,
    )))
}

#[derive(Default)]
pub(super) struct MonitoringShareQuery {
    limit: Option<usize>,
    cursor: Option<i64>,
    status: Option<String>,
}

impl MonitoringShareQuery {
    fn parse(raw_query: Option<&str>) -> ApiResult<Self> {
        let mut query = Self::default();
        for (key, value) in url::form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "limit" if query.limit.is_none() => {
                    query.limit =
                        Some(value.parse().map_err(|_| {
                            ApiError::bad_request("Monitoring share limit is invalid")
                        })?);
                }
                "cursor" if query.cursor.is_none() => {
                    query.cursor = Some(value.parse().map_err(|_| {
                        ApiError::bad_request("Monitoring share cursor is invalid")
                    })?);
                }
                "status" if query.status.is_none() => query.status = Some(value.into_owned()),
                "limit" | "cursor" | "status" => {
                    return Err(ApiError::bad_request(
                        "Monitoring share query parameter is duplicated",
                    ));
                }
                _ => {}
            }
        }
        Ok(query)
    }
}

#[derive(Serialize)]
struct MonitoringShareResponse {
    id: i64,
    status: crate::db::MonitoringShareStatus,
    permission: Permission,
    is_directory: bool,
    password_protected: bool,
    created_at: String,
    expires_at: Option<DateTime<Utc>>,
    download_count: u64,
    max_downloads: Option<u64>,
    max_upload_size_bytes: Option<u64>,
    uploaded_bytes: u64,
    max_upload_total_size_bytes: Option<u64>,
    uploaded_files: u64,
    max_upload_files: Option<u64>,
}

impl From<MonitoringShare> for MonitoringShareResponse {
    fn from(share: MonitoringShare) -> Self {
        Self {
            id: share.id,
            status: share.status,
            permission: share.permission,
            is_directory: share.is_directory,
            password_protected: share.password_protected,
            created_at: share.created_at,
            expires_at: share.expires_at,
            download_count: share.download_count,
            max_downloads: share.max_downloads,
            max_upload_size_bytes: share.max_upload_size_bytes,
            uploaded_bytes: share.uploaded_bytes,
            max_upload_total_size_bytes: share.max_upload_total_size_bytes,
            uploaded_files: share.uploaded_files,
            max_upload_files: share.max_upload_files,
        }
    }
}

#[derive(Serialize)]
pub(super) struct MonitoringSharePageResponse {
    generated_at: DateTime<Utc>,
    shares: Vec<MonitoringShareResponse>,
    next_cursor: Option<i64>,
}

pub(super) async fn monitoring_share_page(
    State(state): State<MonitoringRouteState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> ApiResult<Json<MonitoringSharePageResponse>> {
    admit_monitoring_request(&state)?;
    authorize_monitoring(&state, &headers).await?;
    // Parsing is intentionally deferred until after both admission and
    // authentication. Otherwise malformed query strings can bypass the
    // monitoring request budget and expose a distinct unauthenticated error.
    let query = MonitoringShareQuery::parse(raw_query.as_deref())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::bad_request(
            "Monitoring share limit must be between 1 and 200",
        ));
    }
    if query.cursor.is_some_and(|cursor| cursor <= 0) {
        return Err(ApiError::bad_request("Monitoring share cursor is invalid"));
    }
    let status = MonitoringShareListStatus::parse(query.status.as_deref().unwrap_or("all"))
        .ok_or_else(|| ApiError::bad_request("Monitoring share status is invalid"))?;
    let generated_at = Utc::now();
    let options = MonitoringShareListOptions {
        status,
        cursor: query.cursor,
        limit,
        now: generated_at,
    };
    let page = database(state.db().clone(), move |database| {
        database.list_monitoring_share_page(&options)
    })
    .await?;
    Ok(Json(MonitoringSharePageResponse {
        generated_at,
        shares: page.shares.into_iter().map(Into::into).collect(),
        next_cursor: page.next_cursor,
    }))
}
