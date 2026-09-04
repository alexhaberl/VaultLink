#[derive(Deserialize)]
struct BrowseQuery {
    path: Option<String>,
    mode: Option<String>,
    file_kind: Option<String>,
    server_mode: Option<String>,
}

#[derive(Serialize)]
struct BrowseEntry {
    name: String,
    path: String,
    is_directory: bool,
}

#[derive(Serialize)]
struct BrowseResponse {
    path: String,
    parent: Option<String>,
    entries: Vec<BrowseEntry>,
}

#[derive(Serialize)]
struct DetectedMountResponse {
    mount_point: String,
    root_mount_path: String,
    internal_directory: String,
    expected_filesystem_type: String,
    expected_mount_source: String,
    ready: bool,
}

#[derive(Serialize)]
struct MountDiscoveryResponse {
    mounts: Vec<DetectedMountResponse>,
    error: Option<String>,
}

async fn setup_mounts(State(state): State<SetupState>, headers: HeaderMap) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match storage_mount::discover_supported_mounts() {
        Ok(mounts) => {
            let mounts = mounts
                .into_iter()
                .filter_map(|mount| {
                    let mount_point = mount.mount_point.to_str()?.to_string();
                    let root_mount_path = mount.root_mount_path.to_str()?.to_string();
                    let internal_directory = mount.internal_directory.to_str()?.to_string();
                    let ready =
                        mount_layout_ready(&mount.root_mount_path, &mount.internal_directory);
                    Some(DetectedMountResponse {
                        mount_point,
                        root_mount_path,
                        internal_directory,
                        expected_filesystem_type: mount.filesystem_type,
                        expected_mount_source: mount.source,
                        ready,
                    })
                })
                .collect();
            Json(MountDiscoveryResponse {
                mounts,
                error: None,
            })
            .into_response()
        }
        Err(error) => {
            let _reported = report_internal(InternalOperation::SetupMountDiscovery, error);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(MountDiscoveryResponse {
                    mounts: Vec::new(),
                    error: Some(
                        i18n::text(i18n::current_locale(), i18n::INTERNAL_ERROR).to_owned(),
                    ),
                }),
            )
                .into_response()
        }
    }
}

fn mount_layout_ready(root_mount_path: &Path, internal_directory: &Path) -> bool {
    [
        root_mount_path.to_path_buf(),
        internal_directory.to_path_buf(),
        internal_directory.join("uploads"),
        internal_directory.join("tombstones"),
    ]
    .iter()
    .all(|path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    })
}

async fn setup_browse(
    State(state): State<SetupState>,
    headers: HeaderMap,
    Query(query): Query<BrowseQuery>,
) -> Response {
    if !setup_cookie_authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let requested = query.path.unwrap_or_else(|| "/".to_string());
    let include_files = query.mode.as_deref() == Some("file");
    let file_kind = query.file_kind.as_deref();
    let path = PathBuf::from(&requested);
    if !setup_browse_path_allowed(&path, file_kind, query.server_mode.as_deref()) {
        return (StatusCode::FORBIDDEN, "path is outside setup browser roots").into_response();
    }
    let browse_path = path.clone();
    let file_kind = file_kind.map(str::to_owned);
    let result = tokio::task::spawn_blocking(move || {
        read_setup_browse_directory(&browse_path, include_files, file_kind.as_deref())
    })
    .await;
    let entries = match result {
        Ok(Ok(entries)) => entries,
        Ok(Err(_)) | Err(_) => {
            return (StatusCode::BAD_REQUEST, "path is not readable").into_response();
        }
    };
    let parent = path
        .parent()
        .filter(|parent| {
            *parent != path
                && setup_browse_path_allowed(
                    parent,
                    query.file_kind.as_deref(),
                    query.server_mode.as_deref(),
                )
        })
        .map(|parent| parent.display().to_string());
    Json(BrowseResponse {
        path: path.display().to_string(),
        parent,
        entries,
    })
    .into_response()
}

fn read_setup_browse_directory(
    path: &Path,
    include_files: bool,
    file_kind: Option<&str>,
) -> std::io::Result<Vec<BrowseEntry>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    let filesystem_root = std::fs::File::open("/")?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| std::io::Error::other("setup browse path is not absolute"))?;
    let directory = rustix::fs::openat2(
        &filesystem_root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(std::fs::File::from)
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let read_dir = std::fs::read_dir(descriptor_path)?;
    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let is_directory = file_type.is_dir();
        let entry_path = path.join(entry.file_name());
        if !is_directory
            && !(include_files
                && file_type.is_file()
                && setup_picker_file_allowed(&entry_path, file_kind))
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry_path.display().to_string();
        entries.push(BrowseEntry {
            name,
            path,
            is_directory,
        });
    }
    entries.sort_by_key(|entry| (!entry.is_directory, entry.name.to_lowercase()));
    Ok(entries)
}

fn setup_browse_path_allowed(path: &Path, file_kind: Option<&str>, mode: Option<&str>) -> bool {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return false;
    }
    let roots: &[&str] = if file_kind.is_some() {
        &["/etc/ssl", "/etc/letsencrypt", "/etc/pki/tls"]
    } else if mode == Some("development") {
        &["/mnt", "/srv", "/media", "/var/lib/vaultlink", "/tmp"]
    } else {
        &["/mnt", "/srv", "/media", "/var/lib/vaultlink"]
    };
    if !roots.iter().any(|root| path.starts_with(root)) {
        return false;
    }
    true
}

fn setup_picker_file_allowed(path: &Path, file_kind: Option<&str>) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        (file_kind, extension.as_deref()),
        (Some("certificate"), Some("pem" | "crt" | "cer"))
            | (Some("private_key"), Some("pem" | "key"))
    )
}
