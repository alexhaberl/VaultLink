use super::*;

type SortDirection = super::super::common::FileSortDirection;

struct DirectoryRequest {
    clean_sub: String,
    after: Option<String>,
    before: Option<String>,
    sort_column: FileSortColumn,
    sort_direction: SortDirection,
    search: Option<String>,
}

struct DirectoryRows {
    rows: Vec<PublicFileRowView>,
    truncated: bool,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

pub(in crate::web) async fn public_page(
    State(state): State<PublicRouteState>,
    headers: HeaderMap,
    AxPath(token): AxPath<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Html<String>> {
    let share = get_share(&state, &token).await?;
    if !share_is_unlocked(&state, &headers, &share).await? {
        return Ok(protected_share_page(&token));
    }
    let expected_id = share.id;
    let (share, storage_guard) = get_storage_share(&state, &token, expected_id).await?;
    if !share_is_unlocked(&state, &headers, &share).await? {
        return Ok(protected_share_page(&token));
    }

    let settings = runtime_settings(&state);
    let upload_csrf = share_unlock_csrf(&state, &headers, &share).await?;
    let share_scope = bind_downloadable_directory(&state, &share, storage_guard).await?;
    let directory = if let Some(scope) = share_scope {
        Some(build_directory_view(&state, &token, &share, &settings, scope, &query).await?)
    } else {
        None
    };
    let file = if !share.is_directory && share.permission.can_download() {
        Some(build_file_view(&state, &token, &share, &settings).await?)
    } else {
        None
    };
    let upload = if share.is_directory && share.permission.can_upload() {
        Some(build_upload_view(
            &state,
            &token,
            &share,
            &query,
            upload_csrf,
        )?)
    } else {
        None
    };
    let secure_transport = url::Url::parse(&settings.public_base_url)
        .ok()
        .is_some_and(|url| url.scheme() == "https");
    let body = PublicShareTemplate {
        token,
        display_name: display_name(&share),
        public_base_url: settings.public_base_url.clone(),
        permission_label: share_permission_label(&share.permission),
        password_protected: share.password_hash.is_some(),
        expiry: share.expires_at.map(format_public_date),
        quota: quota_view(&share),
        transport_label: if secure_transport {
            i18n::text(i18n::current_locale(), i18n::HTTPS_SECURE)
        } else {
            i18n::text(i18n::current_locale(), i18n::LOCAL_HTTP)
        },
        upload_notice: upload_notice(query.upload.as_deref()),
        split_layout: share.is_directory
            && share.permission.can_download()
            && share.permission.can_upload(),
        directory,
        file,
        upload,
    };
    Ok(Html(templates::public_page(i18n::SHARE, &body)?))
}

async fn bind_downloadable_directory(
    state: &PublicRouteState,
    share: &Share,
    storage_guard: crate::storage_authority::StorageReadGuard,
) -> Result<Option<crate::secure_fs::SecureDirectory>> {
    if !share.is_directory || !share.permission.can_download() {
        drop(storage_guard);
        return Ok(None);
    }
    let scope_root = state.secure_root().clone();
    let scope_path = share.relative_path.clone();
    tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        scope_root.bind_directory(&scope_path)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicDirectoryListTaskJoin,
            error,
        ))
    })?
    .map(Some)
    .map_err(|error| {
        AppError::storage_io(error, |_| {
            AppError(StatusCode::NOT_FOUND, "Share target unavailable")
        })
    })
}

fn directory_request(query: &BrowseQuery) -> Result<DirectoryRequest> {
    let after = query.after.clone();
    let before = query.before.clone();
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
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
    if search
        .as_ref()
        .is_some_and(|value| value.len() > MAX_SEARCH_QUERY_BYTES)
    {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            "Search query is too long",
        ));
    }
    let sub = query.path.as_deref().unwrap_or_default();
    let clean_sub = path_security::validate_relative(sub)
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(DirectoryRequest {
        clean_sub,
        after,
        before,
        sort_column: file_sort_column(query.sort.as_deref()),
        sort_direction: file_sort_direction(query.direction.as_deref()),
        search,
    })
}

async fn build_directory_view(
    state: &PublicRouteState,
    token: &str,
    share: &Share,
    settings: &crate::runtime::RuntimeSettings,
    share_scope: crate::secure_fs::SecureDirectory,
    query: &BrowseQuery,
) -> Result<PublicDirectoryView> {
    let request = directory_request(query)?;
    let peer_permit = state
        .try_acquire_expensive_peer(current_client_limit_key())
        .ok_or(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent expensive operations from this client",
        ))?;
    let scan_permit = state.try_acquire_search().map_err(|_| {
        AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent file searches",
        )
    })?;
    let admission = super::super::common::ScanAdmission::new(peer_permit, scan_permit);
    let rows = if let Some(search) = request.search.clone() {
        DirectoryRows {
            rows: search_rows(
                token,
                share_scope,
                request.clean_sub.clone(),
                search,
                settings.clone(),
                request.sort_column,
                request.sort_direction,
                admission,
            )
            .await?,
            truncated: false,
            previous_cursor: None,
            next_cursor: None,
        }
    } else {
        browse_rows(
            state,
            token,
            share,
            settings,
            share_scope,
            &request,
            admission,
        )
        .await?
    };
    Ok(directory_view(token, &request, rows))
}

#[allow(clippy::too_many_arguments)]
async fn search_rows(
    token: &str,
    share_scope: crate::secure_fs::SecureDirectory,
    relative_dir: String,
    search: String,
    settings: crate::runtime::RuntimeSettings,
    sort_column: FileSortColumn,
    sort_direction: SortDirection,
    admission: std::sync::Arc<super::super::common::ScanAdmission>,
) -> Result<Vec<PublicFileRowView>> {
    let search_settings = settings.clone();
    let mut hits = admission
        .spawn_blocking(move || search_tree(&share_scope, &relative_dir, &search, &search_settings))
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicSearchTaskJoin,
                error,
            ))
        })?
        .map_err(|error| directory_io_error(&error))?;
    sort_search_hits(&mut hits, sort_column, sort_direction);
    Ok(hits
        .into_iter()
        .map(|hit| search_row(token, hit, &settings))
        .collect())
}

fn search_row(
    token: &str,
    hit: super::super::common::SearchHit,
    settings: &crate::runtime::RuntimeSettings,
) -> PublicFileRowView {
    let relative = hit.relative_path;
    let target = encoded(&relative);
    let modified = hit.entry.modified.map(public_file_time);
    let (modified_datetime, modified_label) = modified
        .map_or((None, "—".into()), |(datetime, label)| {
            (Some(datetime), label)
        });
    PublicFileRowView {
        name: relative.clone(),
        icon: file_icon(hit.entry.is_dir),
        type_label: file_type_label(hit.entry.is_dir),
        size: file_size_label(hit.entry.is_dir, hit.entry.len),
        modified_datetime,
        modified_label,
        is_directory: hit.entry.is_dir,
        open_url: hit
            .entry
            .is_dir
            .then(|| format!("/v/{token}?path={target}")),
        preview_url: (!hit.entry.is_dir && preview_allowed(&relative, settings))
            .then(|| format!("/v/{token}/preview?path={target}")),
        download_url: (!hit.entry.is_dir).then(|| format!("/v/{token}/download?path={target}")),
    }
}

async fn browse_rows(
    state: &PublicRouteState,
    token: &str,
    share: &Share,
    settings: &crate::runtime::RuntimeSettings,
    share_scope: crate::secure_fs::SecureDirectory,
    request: &DirectoryRequest,
    admission: std::sync::Arc<super::super::common::ScanAdmission>,
) -> Result<DirectoryRows> {
    let scan_limit = settings.max_search_entries;
    let cursor_after = request.after.clone();
    let cursor_before = request.before.clone();
    let snapshot_guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let storage_generation = snapshot_guard.generation();
    let snapshot_root = share_scope.clone();
    let snapshot_path = request.clean_sub.clone();
    let snapshot_sort_column = request.sort_column;
    let snapshot_sort_direction = request.sort_direction;
    let snapshot_cache = state.directory_snapshot_cache().clone();
    let snapshot_key = DirectorySnapshotKey {
        scope: format!("share:{}:{}", share.id, share.relative_path),
        directory: request.clean_sub.clone(),
        sort: file_sort_column_value(request.sort_column),
        direction: file_sort_direction_value(request.sort_direction),
        scan_limit,
        storage_generation,
    };
    let snapshot_admission = admission.clone();
    let snapshot = snapshot_cache
        .get_or_try_load(snapshot_key, || async move {
            snapshot_admission
                .spawn_blocking(move || {
                    let _storage_guard = snapshot_guard;
                    build_directory_snapshot(
                        &snapshot_root,
                        &snapshot_path,
                        scan_limit,
                        snapshot_sort_column,
                        snapshot_sort_direction,
                    )
                })
                .await
                .map_err(|error| {
                    AppError::from(report_internal(
                        InternalOperation::WebPublicDirectoryListTaskJoin,
                        error,
                    ))
                })?
                .map_err(|error| {
                    AppError::storage_io(error, |_| {
                        AppError(StatusCode::NOT_FOUND, "Share target unavailable")
                    })
                })
        })
        .await?;
    let listing = match snapshot {
        DirectoryCacheLookup::Snapshot(snapshot) => list_directory_snapshot_cursor_page(
            &snapshot,
            cursor_after.as_deref(),
            cursor_before.as_deref(),
            request.sort_column,
            request.sort_direction,
        ),
        DirectoryCacheLookup::Bypass => {
            browse_without_snapshot(
                state,
                share_scope,
                request.clean_sub.clone(),
                cursor_after,
                cursor_before,
                scan_limit,
                request.sort_column,
                request.sort_direction,
                admission,
            )
            .await?
        }
    }
    .map_err(|error| directory_io_error(&error))?;
    let rows = listing
        .entries
        .into_iter()
        .map(|entry| listing_row(token, &request.clean_sub, entry, settings))
        .collect::<Result<Vec<_>>>()?;
    Ok(DirectoryRows {
        rows,
        truncated: listing.truncated,
        previous_cursor: listing.previous_cursor,
        next_cursor: listing.next_cursor,
    })
}

#[allow(clippy::too_many_arguments)]
async fn browse_without_snapshot(
    state: &PublicRouteState,
    share_scope: crate::secure_fs::SecureDirectory,
    relative_dir: String,
    after: Option<String>,
    before: Option<String>,
    scan_limit: usize,
    sort_column: FileSortColumn,
    sort_direction: SortDirection,
    admission: std::sync::Arc<super::super::common::ScanAdmission>,
) -> Result<std::io::Result<super::super::common::DirectoryCursorPage>> {
    let guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    admission
        .spawn_blocking(move || {
            let _storage_guard = guard;
            list_directory_cursor_page(
                &share_scope,
                &relative_dir,
                after.as_deref(),
                before.as_deref(),
                scan_limit,
                sort_column,
                sort_direction,
            )
        })
        .await
        .map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebPublicDirectoryListTaskJoin,
                error,
            ))
        })
}

fn listing_row(
    token: &str,
    base: &str,
    entry: crate::secure_fs::Entry,
    settings: &crate::runtime::RuntimeSettings,
) -> Result<PublicFileRowView> {
    let relative = joined_relative(base, &entry.name)?;
    let target = encoded(&relative);
    let modified = entry.modified.map(public_file_time);
    let (modified_datetime, modified_label) = modified
        .map_or((None, "—".into()), |(datetime, label)| {
            (Some(datetime), label)
        });
    Ok(PublicFileRowView {
        name: entry.name,
        icon: file_icon(entry.is_dir),
        type_label: file_type_label(entry.is_dir),
        size: file_size_label(entry.is_dir, entry.len),
        modified_datetime,
        modified_label,
        is_directory: entry.is_dir,
        open_url: entry.is_dir.then(|| format!("/v/{token}?path={target}")),
        preview_url: (!entry.is_dir && preview_allowed(&relative, settings))
            .then(|| format!("/v/{token}/preview?path={target}")),
        download_url: (!entry.is_dir).then(|| format!("/v/{token}/download?path={target}")),
    })
}

fn directory_view(
    token: &str,
    request: &DirectoryRequest,
    rows: DirectoryRows,
) -> PublicDirectoryView {
    let encoded_sub = encoded(&request.clean_sub);
    let headers = [
        ("common.name", FileSortColumn::Name),
        ("common.type", FileSortColumn::Type),
        ("common.size", FileSortColumn::Size),
        ("common.changed", FileSortColumn::Modified),
    ]
    .into_iter()
    .map(|(label, column)| {
        public_sort_header_view(
            label,
            column,
            request.sort_column,
            request.sort_direction,
            token,
            &request.clean_sub,
            request.search.as_deref(),
        )
    })
    .collect();
    PublicDirectoryView {
        root_url: format!("/v/{token}"),
        breadcrumbs: public_breadcrumb_views(token, &request.clean_sub),
        parent_url: parent_path(&request.clean_sub)
            .map(|parent| format!("/v/{token}?path={}", encoded(&parent))),
        path: request.clean_sub.clone(),
        path_encoded: encoded_sub.clone(),
        sort: file_sort_column_value(request.sort_column),
        direction: file_sort_direction_value(request.sort_direction),
        search: request.search.clone().unwrap_or_default(),
        zip_url: format!("/v/{token}/download.zip?path={encoded_sub}"),
        headers,
        rows: rows.rows,
        truncated: rows.truncated,
        previous_cursor: rows.previous_cursor.map(|cursor| encoded(&cursor)),
        next_cursor: rows.next_cursor.map(|cursor| encoded(&cursor)),
        search_encoded: request.search.as_deref().map(encoded),
    }
}

async fn build_file_view(
    state: &PublicRouteState,
    token: &str,
    share: &Share,
    settings: &crate::runtime::RuntimeSettings,
) -> Result<PublicFileView> {
    let secure_root = state.secure_root().clone();
    let metadata_path = share.relative_path.clone();
    let storage_guard = file_ops::acquire_storage_read(state)
        .await
        .map_err(storage_recovery_app_error)?;
    let metadata = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        secure_root.metadata(&metadata_path)
    })
    .await
    .map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebPublicFileMetadataTaskJoin,
            error,
        ))
    })?
    .map_err(|error| {
        AppError::storage_io(error, |_| {
            AppError(StatusCode::NOT_FOUND, "Shared file unavailable")
        })
    })?;
    let modified = metadata.modified().ok().map(public_file_time);
    let (modified_datetime, modified_label) = modified
        .map_or((None, "—".into()), |(datetime, label)| {
            (Some(datetime), label)
        });
    Ok(PublicFileView {
        size: human(metadata.len()),
        modified_datetime,
        modified_label,
        preview_url: preview_allowed(&share.relative_path, settings)
            .then(|| format!("/v/{token}/preview")),
        download_url: format!("/v/{token}/download"),
    })
}

fn build_upload_view(
    state: &PublicRouteState,
    token: &str,
    share: &Share,
    query: &BrowseQuery,
    csrf: Option<String>,
) -> Result<PublicUploadView> {
    let path = if share.permission.can_download() {
        path_security::validate_relative(query.path.as_deref().unwrap_or_default())
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid path"))?
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        String::new()
    };
    Ok(PublicUploadView {
        heading: if share.permission == Permission::UploadOnly {
            i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE)
        } else {
            i18n::text(i18n::current_locale(), i18n::UPLOAD_FILES_PUBLIC)
        },
        hide_existing: share.permission == Permission::UploadOnly,
        path,
        action_url: format!("/v/{token}/upload"),
        queue_url: format!("/v/{token}/upload/queue"),
        csrf: csrf.unwrap_or_default(),
        allow_overwrite: share.upload_conflict_strategy.can_overwrite()
            && state.config().storage.replacements_allowed(),
        upload_icon: TrustedMarkup::static_icon(crate::ui::Icon::Upload),
        folder_icon: TrustedMarkup::static_icon(crate::ui::Icon::Folder),
    })
}

fn display_name(share: &Share) -> String {
    if share.permission == Permission::UploadOnly {
        i18n::text(i18n::current_locale(), i18n::UPLOAD_FILE).to_string()
    } else {
        share
            .relative_path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| i18n::text(i18n::current_locale(), i18n::DEFAULT_SHARE_NAME))
            .to_string()
    }
}

fn quota_view(share: &Share) -> Option<PublicQuotaView> {
    share.max_downloads.map(|maximum| PublicQuotaView {
        used: share.download_count,
        maximum,
        percent: share
            .download_count
            .saturating_mul(100)
            .saturating_div(maximum.max(1))
            .min(100),
    })
}

fn upload_notice(status: Option<&str>) -> Option<&'static str> {
    let message = match status? {
        "replaced" => i18n::text(i18n::current_locale(), i18n::FILE_REPLACED_SUCCESS),
        "ok" => i18n::text(i18n::current_locale(), i18n::UPLOAD_COMPLETED),
        "uncertain" => i18n::text(i18n::current_locale(), i18n::UPLOAD_STORAGE_UNCONFIRMED),
        "replaced_uncertain" => {
            i18n::text(i18n::current_locale(), i18n::REPLACE_STORAGE_UNCONFIRMED)
        }
        "audit_uncertain" => i18n::text(i18n::current_locale(), i18n::AUDIT_DURABILITY_UNCERTAIN),
        _ => "",
    };
    (!message.is_empty()).then_some(message)
}

fn directory_io_error(error: &std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        AppError::storage_busy()
    } else if error.kind() == std::io::ErrorKind::InvalidInput {
        AppError(StatusCode::BAD_REQUEST, "Invalid directory cursor")
    } else {
        AppError(StatusCode::NOT_FOUND, "Share target unavailable")
    }
}

fn file_icon(is_directory: bool) -> TrustedMarkup {
    TrustedMarkup::static_icon(if is_directory {
        crate::ui::Icon::Folder
    } else {
        crate::ui::Icon::File
    })
}

fn file_type_label(is_directory: bool) -> &'static str {
    i18n::text(
        i18n::current_locale(),
        if is_directory {
            i18n::FOLDER
        } else {
            i18n::FILE
        },
    )
}

fn file_size_label(is_directory: bool, bytes: u64) -> String {
    if is_directory {
        "—".into()
    } else {
        human(bytes)
    }
}
