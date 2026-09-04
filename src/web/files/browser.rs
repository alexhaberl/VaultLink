struct AdminBrowseRequest {
    raw: String,
    relative: String,
    after: Option<String>,
    before: Option<String>,
    search: Option<String>,
    notice: Option<String>,
    sort: super::common::FileSortColumn,
    direction: super::common::FileSortDirection,
}

struct AdminBrowserListing {
    rows: Vec<AdminFileRowView>,
    truncated: bool,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

struct AdminStorageSummary {
    used: String,
    free: String,
    active_links: usize,
}

impl AdminBrowseRequest {
    fn from_query(query: BrowseQuery) -> Result<Self> {
        let sort = file_sort_column(query.sort.as_deref());
        let direction = file_sort_direction(query.direction.as_deref());
        let raw = query.path.unwrap_or_default();
        let search = query
            .q
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        validate_admin_browse_cursors(
            query.after.as_deref(),
            query.before.as_deref(),
            search.as_deref(),
        )?;
        if search
            .as_ref()
            .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
        {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                "Search query is too long",
            ));
        }
        let relative = path_security::validate_relative(&raw)
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
            .to_string_lossy()
            .replace('\\', "/");
        Ok(Self {
            raw,
            relative,
            after: query.after,
            before: query.before,
            search,
            notice: query.notice,
            sort,
            direction,
        })
    }
}

fn validate_admin_browse_cursors(
    after: Option<&str>,
    before: Option<&str>,
    search: Option<&str>,
) -> Result<()> {
    if after.is_some() && before.is_some() {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Invalid directory cursor",
        ));
    }
    if search.is_some() && (after.is_some() || before.is_some()) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Directory cursors cannot be combined with search",
        ));
    }
    Ok(())
}

async fn load_admin_storage_summary(state: &FileRouteState) -> Result<AdminStorageSummary> {
    let disk = state
        .disk_stats_cache()
        .get(state.secure_root().display_root())
        .await
        .ok();
    let used = disk
        .as_ref()
        .map(|stats| stats.total.saturating_sub(stats.free))
        .map(human)
        .unwrap_or_else(|| "n/v".into());
    let free = disk
        .as_ref()
        .map(|stats| human(stats.free))
        .unwrap_or_else(|| "n/v".into());
    let active_links = database(state.db().clone(), |database| {
        database.count_available_shares(Utc::now())
    })
    .await?;
    Ok(AdminStorageSummary {
        used,
        free,
        active_links,
    })
}

fn acquire_admin_browser_admission(
    state: &FileRouteState,
) -> Result<(ClientActivityPermit, tokio::sync::OwnedSemaphorePermit)> {
    let peer = state
        .try_acquire_expensive_peer(current_client_limit_key())
    .ok_or(AppError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many concurrent expensive operations from this client",
    ))?;
    let search = state
        .try_acquire_search()
        .map_err(|_| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many concurrent file searches",
            )
        })?;
    Ok((peer, search))
}

async fn load_admin_browser_listing(
    state: &FileRouteState,
    request: &AdminBrowseRequest,
    settings: &crate::runtime::RuntimeSettings,
) -> Result<AdminBrowserListing> {
    let (_peer_permit, _search_permit) = acquire_admin_browser_admission(state)?;
    let storage_guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let storage_generation = storage_guard.generation();
    if let Some(search) = request.search.as_deref() {
        load_admin_search_results(state, request, settings, search, storage_guard).await
    } else {
        load_admin_directory_page(
            state,
            request,
            settings,
            settings.max_search_entries,
            storage_generation,
            storage_guard,
        )
        .await
    }
}

async fn load_admin_search_results(
    state: &FileRouteState,
    request: &AdminBrowseRequest,
    settings: &crate::runtime::RuntimeSettings,
    search: &str,
    storage_guard: crate::storage_authority::StorageReadGuard,
) -> Result<AdminBrowserListing> {
    let root = state.secure_root().clone();
    let base = request.relative.clone();
    let search = search.to_string();
    let search_settings = settings.clone();
    let mut hits = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        search_tree(&root, &base, &search, &search_settings)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminSearchTaskJoin,
            error,
        ))
    })?
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebAdminSearchFailure,
            error,
        ))
    })?;
    sort_search_hits(&mut hits, request.sort, request.direction);
    let rows = hits
        .into_iter()
        .map(|hit| {
            admin_file_row_view(
                &hit.relative_path,
                hit.relative_path.clone(),
                hit.entry.is_dir,
                hit.entry.len,
                hit.entry.modified,
                settings,
            )
        })
        .collect();
    Ok(AdminBrowserListing {
        rows,
        truncated: false,
        previous_cursor: None,
        next_cursor: None,
    })
}

async fn load_admin_directory_page(
    state: &FileRouteState,
    request: &AdminBrowseRequest,
    settings: &crate::runtime::RuntimeSettings,
    scan_limit: usize,
    storage_generation: u64,
    storage_guard: crate::storage_authority::StorageReadGuard,
) -> Result<AdminBrowserListing> {
    let listing_path = request.relative.clone();
    let cursor_after = request.after.clone();
    let cursor_before = request.before.clone();
    let root = state.secure_root().clone();
    let snapshot_root = root.clone();
    let snapshot_path = listing_path.clone();
    let sort = request.sort;
    let direction = request.direction;
    let snapshot_key = DirectorySnapshotKey {
        scope: "admin".into(),
        directory: listing_path.clone(),
        sort: file_sort_column_value(request.sort),
        direction: file_sort_direction_value(request.direction),
        scan_limit,
        storage_generation,
    };
    let snapshot = state
        .directory_snapshot_cache()
        .get_or_try_load(snapshot_key, || async move {
            tokio::task::spawn_blocking(move || {
                let _storage_guard = storage_guard;
                build_directory_snapshot(
                    &snapshot_root,
                    &snapshot_path,
                    scan_limit,
                    sort,
                    direction,
                )
            })
            .await
            .map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebAdminDirectoryListTaskJoin,
                    error,
                ))
            })?
            .map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebAdminDirectoryListFailure,
                    error,
                ))
            })
        })
        .await?;
    let page = match snapshot {
        DirectoryCacheLookup::Snapshot(snapshot) => list_directory_snapshot_cursor_page(
            &snapshot,
            cursor_after.as_deref(),
            cursor_before.as_deref(),
            sort,
            direction,
        ),
        DirectoryCacheLookup::Bypass => {
            let fallback_guard = file_ops::acquire_storage_read(state)
                .await
                .map_err(storage_recovery_app_error)?;
            tokio::task::spawn_blocking(move || {
                let _storage_guard = fallback_guard;
                list_directory_cursor_page(
                    &root,
                    &listing_path,
                    cursor_after.as_deref(),
                    cursor_before.as_deref(),
                    scan_limit,
                    sort,
                    direction,
                )
            })
            .await
            .map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebAdminDirectoryListTaskJoin,
                    error,
                ))
            })?
        }
    }
    .map_err(admin_directory_page_error)?;
    let rows = page
        .entries
        .into_iter()
        .map(|entry| {
            let child = join_display(&request.relative, &entry.name);
            admin_file_row_view(
                &child,
                entry.name,
                entry.is_dir,
                entry.len,
                entry.modified,
                settings,
            )
        })
        .collect();
    Ok(AdminBrowserListing {
        rows,
        truncated: page.truncated,
        previous_cursor: page.previous_cursor,
        next_cursor: page.next_cursor,
    })
}

fn admin_directory_page_error(error: std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        AppError(StatusCode::BAD_REQUEST, "Invalid directory cursor")
    } else {
        AppError::from(report_internal(
            InternalOperation::WebAdminDirectoryListFailure,
            error,
        ))
    }
}

fn admin_browser_notice(notice: Option<&str>) -> (Option<&'static str>, bool) {
    match notice {
        Some("directory_created") => (Some("files.folder_created"), true),
        Some("path_renamed") => (Some("files.entry_renamed"), true),
        Some("path_deleted") => (Some("files.entry_deleted"), true),
        Some("path_delete_queued") => (Some("files.entry_removed_cleanup"), true),
        Some("audit_durability_uncertain") => (Some("files.audit_durability_uncertain"), false),
        Some("upload_ok") => (Some("files.uploaded"), true),
        _ => (None, false),
    }
}

fn admin_browser_template(
    state: &FileRouteState,
    request: &AdminBrowseRequest,
    summary: AdminStorageSummary,
    listing: AdminBrowserListing,
    csrf_token: String,
) -> AdminBrowserTemplate {
    let encoded_path = encoded(&request.relative);
    let current_folder_target = if request.raw.is_empty() {
        ".".to_string()
    } else {
        encoded_path.clone()
    };
    let (notice_key, notice_success) = admin_browser_notice(request.notice.as_deref());
    let headers = [
        ("common.name", super::common::FileSortColumn::Name),
        ("common.type", super::common::FileSortColumn::Type),
        ("common.size", super::common::FileSortColumn::Size),
        ("common.changed", super::common::FileSortColumn::Modified),
    ]
    .into_iter()
    .map(|(label, column)| admin_sort_header_view(label, column, request.sort, request.direction))
    .collect();
    AdminBrowserTemplate {
        notice_key,
        notice_success,
        used_storage: summary.used,
        free_storage: summary.free,
        active_links: summary.active_links,
        breadcrumbs: admin_breadcrumb_views(&request.relative),
        path: request.relative.clone(),
        path_encoded: encoded_path,
        up_url: parent_path(&request.relative)
            .map(|parent| format!("/admin?path={}", encoded(&parent))),
        csrf_token,
        replacements_allowed: state.config().storage.replacements_allowed(),
        upload_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Upload),
        folder_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Folder),
        more_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::More),
        trash_icon: super::templates::TrustedMarkup::static_icon(crate::ui::Icon::Trash),
        current_folder_target,
        sort: file_sort_column_value(request.sort),
        direction: file_sort_direction_value(request.direction),
        search: request.search.clone().unwrap_or_default(),
        search_encoded: request.search.as_deref().map(encoded),
        headers,
        rows: listing.rows,
        truncated: listing.truncated,
        previous_cursor: listing.previous_cursor.map(|cursor| encoded(&cursor)),
        next_cursor: listing.next_cursor.map(|cursor| encoded(&cursor)),
    }
}

pub(super) async fn admin_browser(
    State(state): State<FileRouteState>,
    headers: HeaderMap,
    Query(query): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let (_, session) = session(&state, &headers, true, MissingSession::RedirectToLogin).await?;
    let settings = runtime_settings(&state);
    let summary = load_admin_storage_summary(&state).await?;
    let request = AdminBrowseRequest::from_query(query)?;
    let listing = load_admin_browser_listing(&state, &request, &settings).await?;
    let body = admin_browser_template(
        &state,
        &request,
        summary,
        listing,
        session.csrf_token.clone(),
    );
    Ok(Html(super::templates::admin_page(
        &state,
        PageId::Files,
        &body,
        false,
        &session.csrf_token,
        true,
    )?))
}
