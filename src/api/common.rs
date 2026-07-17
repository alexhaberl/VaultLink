use axum::http::StatusCode;
use chrono::Utc;

use crate::{
    db::Share,
    http_auth::database,
    path_security,
    policy::{self, ShareAvailability},
    runtime::RuntimeSettings,
    AppState,
};

use super::{ApiError, ApiResult};

pub(super) async fn find_share_by_id(state: &AppState, id: i64) -> ApiResult<Share> {
    database(state.db.clone(), move |db| db.share_by_id(id))
        .await?
        .ok_or_else(|| ApiError::not_found("Share not found"))
}

pub(super) async fn get_share(state: &AppState, token: &str) -> ApiResult<Share> {
    let token = token.to_string();
    let share = database(state.db.clone(), move |db| db.share_by_token(&token))
        .await?
        .ok_or_else(|| ApiError::not_found("Share not found"))?;
    usable(&share)?;
    Ok(share)
}

pub(super) fn usable(share: &Share) -> ApiResult<()> {
    match policy::share_availability(share, Utc::now()) {
        ShareAvailability::Available => Ok(()),
        ShareAvailability::Inactive => Err(ApiError::new(
            StatusCode::GONE,
            "share_inactive",
            "Share is inactive",
        )),
        ShareAvailability::Expired => Err(ApiError::new(
            StatusCode::GONE,
            "share_expired",
            "Share has expired",
        )),
    }
}

pub(super) fn validate_rel(value: &str) -> ApiResult<String> {
    path_security::validate_relative(value)
        .map_err(|_| ApiError::bad_request("Invalid path"))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

pub(super) fn preview_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    policy::preview_metadata_allowed(path, settings)
}
