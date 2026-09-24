use axum::{extract::Multipart, http::HeaderMap};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};

use crate::db::Database;

#[derive(Clone, Default)]
pub(crate) struct UploadStorageGuard(
    std::sync::Arc<std::sync::Mutex<Option<crate::storage_authority::StorageMutationGuard>>>,
);

impl UploadStorageGuard {
    pub(crate) fn hold(&self, guard: crate::storage_authority::StorageMutationGuard) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(slot.is_none());
        *slot = Some(guard);
    }

    pub(crate) fn is_held(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    pub(crate) fn finish_clean(&self) {
        let guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(guard) = guard {
            guard.finish_clean();
        }
    }
}

pub(crate) async fn take_upload_id(
    multipart: &mut Multipart,
    headers: &HeaderMap,
) -> Result<UploadIdSelection, &'static str> {
    if let Some(header) = headers.get("idempotency-key") {
        let id = header.to_str().map_err(|_| "Invalid upload ID")?;
        return valid_upload_id(id)
            .then(|| UploadIdSelection {
                id: id.to_owned(),
                prefix: Vec::new(),
            })
            .ok_or("Invalid upload ID");
    }
    let mut prefix = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| "Invalid upload ID")?
    {
        if prefix.len() >= 6 {
            return Err("Too many multipart fields");
        }
        let (kind, maximum) = match field.name() {
            Some("upload_id") => (UploadPrefixKind::Id, 64),
            Some("path") => (
                UploadPrefixKind::Path,
                crate::http_contract::MAX_UPLOAD_PATH_FIELD_BYTES,
            ),
            Some("folder_path") => (
                UploadPrefixKind::FolderPath,
                crate::http_contract::MAX_UPLOAD_PATH_FIELD_BYTES,
            ),
            Some("overwrite_existing") => (
                UploadPrefixKind::Overwrite,
                crate::http_contract::MAX_UPLOAD_OPTION_FIELD_BYTES,
            ),
            Some("csrf") => (UploadPrefixKind::Csrf, 512),
            Some("file") => return Err("Upload ID must precede the file"),
            _ => return Err("Unknown multipart field"),
        };
        let value = limited_text(field, maximum).await?;
        prefix.push(UploadPrefixField {
            kind,
            value: value.clone(),
        });
        if kind == UploadPrefixKind::Id {
            return valid_upload_id(&value)
                .then_some(UploadIdSelection { id: value, prefix })
                .ok_or("Invalid upload ID");
        }
    }
    Err("Upload ID required")
}

pub(crate) struct UploadIdSelection {
    pub(crate) id: String,
    pub(crate) prefix: Vec<UploadPrefixField>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UploadPrefixKind {
    Id,
    Path,
    FolderPath,
    Overwrite,
    Csrf,
}

pub(crate) struct UploadPrefixField {
    pub(crate) kind: UploadPrefixKind,
    pub(crate) value: String,
}

pub(crate) fn valid_upload_id(id: &str) -> bool {
    id.len() == 43
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[derive(Clone, Copy)]
pub(crate) enum ReplayKind<'a> {
    Admin {
        csrf: &'a str,
    },
    Public {
        permission: crate::db::Permission,
        csrf: Option<&'a str>,
        csrf_header_valid: bool,
    },
}

async fn limited_text(
    mut field: axum::extract::multipart::Field<'_>,
    maximum: usize,
) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|_| "Invalid upload field")? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|len| len > maximum)
        {
            return Err("Upload field is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "Invalid upload field")
}

/// Validate a repeated multipart request without staging, quota, or filesystem
/// mutations. The returned digest uses exactly the metadata of the first pass.
pub(crate) async fn replay_fingerprint(
    mut multipart: Multipart,
    expected_id: &str,
    prefix: Vec<UploadPrefixField>,
    kind: ReplayKind<'_>,
) -> Result<String, &'static str> {
    let ReplayPrefix {
        mut base,
        mut folder,
        mut overwrite,
        mut csrf_seen,
        mut id_seen,
        mut fields,
    } = parse_replay_prefix(prefix, expected_id, kind)?;
    let mut file: Option<(String, u64, String)> = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| "Invalid upload")? {
        fields += 1;
        ensure_field_limit(fields)?;
        match field.name().unwrap_or("") {
            "upload_id" if !id_seen && file.is_none() => {
                let supplied = limited_text(field, 64).await?;
                if !crate::auth::constant_time_eq(expected_id, &supplied) {
                    return Err("Upload IDs disagree");
                }
                id_seen = true;
            }
            "path" if base.is_none() && file.is_none() => {
                let raw =
                    limited_text(field, crate::http_contract::MAX_UPLOAD_PATH_FIELD_BYTES).await?;
                let normalized = match kind {
                    ReplayKind::Admin { .. } => crate::path_security::validate_relative(&raw)
                        .map_err(|_| "Invalid upload path")?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    ReplayKind::Public { permission, .. } => {
                        crate::policy::normalize_public_upload_subdir(permission, &raw)
                            .map_err(|_| "Invalid upload path")?
                    }
                };
                base = Some(normalized);
            }
            "folder_path" if folder.is_none() && file.is_none() => {
                let raw =
                    limited_text(field, crate::http_contract::MAX_UPLOAD_PATH_FIELD_BYTES).await?;
                folder = Some(
                    crate::path_security::validate_relative(&raw)
                        .map_err(|_| "Invalid folder path")?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
            "overwrite_existing" if overwrite.is_none() => {
                if matches!(kind, ReplayKind::Admin { .. }) && file.is_some() {
                    return Err("Upload option was submitted too late");
                }
                let raw = limited_text(field, crate::http_contract::MAX_UPLOAD_OPTION_FIELD_BYTES)
                    .await?;
                overwrite = Some(raw == "1");
            }
            "csrf" if !csrf_seen && file.is_none() => {
                let supplied = limited_text(field, 512).await?;
                let expected = match kind {
                    ReplayKind::Admin { csrf } => Some(csrf),
                    ReplayKind::Public { csrf, .. } => csrf,
                };
                if expected.is_some_and(|value| !crate::auth::constant_time_eq(value, &supplied)) {
                    return Err("Invalid CSRF proof");
                }
                csrf_seen = true;
            }
            "file" if file.is_none() => {
                file = Some(hash_replayed_file(field).await?);
            }
            _ => return Err("Invalid or duplicate upload field"),
        }
    }
    finish_replay_fingerprint(kind, file, base, folder, overwrite, csrf_seen)
}

struct ReplayPrefix {
    base: Option<String>,
    folder: Option<String>,
    overwrite: Option<bool>,
    csrf_seen: bool,
    id_seen: bool,
    fields: usize,
}

fn parse_replay_prefix(
    prefix: Vec<UploadPrefixField>,
    expected_id: &str,
    kind: ReplayKind<'_>,
) -> Result<ReplayPrefix, &'static str> {
    let mut base = None;
    let mut folder = None;
    let mut overwrite = None;
    let mut csrf_seen = false;
    let mut id_seen = false;
    let mut fields = 0;
    for field in prefix {
        fields += 1;
        ensure_field_limit(fields)?;
        match field.kind {
            UploadPrefixKind::Id if !id_seen => {
                if !crate::auth::constant_time_eq(expected_id, &field.value) {
                    return Err("Upload IDs disagree");
                }
                id_seen = true;
            }
            UploadPrefixKind::Path if base.is_none() => {
                base = Some(match kind {
                    ReplayKind::Admin { .. } => {
                        crate::path_security::validate_relative(&field.value)
                            .map_err(|_| "Invalid upload path")?
                            .to_string_lossy()
                            .replace('\\', "/")
                    }
                    ReplayKind::Public { permission, .. } => {
                        crate::policy::normalize_public_upload_subdir(permission, &field.value)
                            .map_err(|_| "Invalid upload path")?
                    }
                });
            }
            UploadPrefixKind::FolderPath if folder.is_none() => {
                folder = Some(
                    crate::path_security::validate_relative(&field.value)
                        .map_err(|_| "Invalid folder path")?
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
            UploadPrefixKind::Overwrite if overwrite.is_none() => {
                overwrite = Some(field.value == "1")
            }
            UploadPrefixKind::Csrf if !csrf_seen => {
                let expected = match kind {
                    ReplayKind::Admin { csrf } => Some(csrf),
                    ReplayKind::Public { csrf, .. } => csrf,
                };
                if expected.is_some_and(|value| !crate::auth::constant_time_eq(value, &field.value))
                {
                    return Err("Invalid CSRF proof");
                }
                csrf_seen = true;
            }
            _ => return Err("Invalid or duplicate upload field"),
        }
    }
    Ok(ReplayPrefix {
        base,
        folder,
        overwrite,
        csrf_seen,
        id_seen,
        fields,
    })
}

fn ensure_field_limit(fields: usize) -> Result<(), &'static str> {
    if fields > 6 {
        Err("Too many multipart fields")
    } else {
        Ok(())
    }
}

async fn hash_replayed_file(
    mut field: axum::extract::multipart::Field<'_>,
) -> Result<(String, u64, String), &'static str> {
    let name =
        crate::path_security::safe_admin_filename(field.file_name().ok_or("File name missing")?)
            .map_err(|_| "Invalid file name")?
            .to_owned();
    let mut size = 0u64;
    let mut digest = Sha256::new();
    while let Some(chunk) = field.next().await {
        let chunk = chunk.map_err(|_| "Upload aborted")?;
        size = size
            .checked_add(chunk.len() as u64)
            .filter(|value| *value <= crate::config::MAX_UPLOAD_SIZE)
            .ok_or("Upload is too large")?;
        digest.update(&chunk);
    }
    Ok((
        name,
        size,
        data_encoding::HEXLOWER.encode(digest.finalize().as_ref()),
    ))
}

fn finish_replay_fingerprint(
    kind: ReplayKind<'_>,
    file: Option<(String, u64, String)>,
    base: Option<String>,
    folder: Option<String>,
    overwrite: Option<bool>,
    csrf_seen: bool,
) -> Result<String, &'static str> {
    let (name, size, digest) = file.ok_or("File is missing")?;
    let overwrite = overwrite.unwrap_or(false);
    let metadata = match kind {
        ReplayKind::Admin { .. } => {
            if !csrf_seen {
                return Err("CSRF proof missing");
            }
            let base = base.ok_or("Upload path missing")?;
            let directory = if let Some(folder) = folder {
                if base.is_empty() || base == "." {
                    folder
                } else {
                    format!("{base}/{folder}")
                }
            } else {
                base
            };
            serde_json::to_vec(&(name, directory, overwrite, size, digest))
        }
        ReplayKind::Public {
            csrf,
            csrf_header_valid,
            ..
        } => {
            if csrf.is_some() && !csrf_seen && !csrf_header_valid {
                return Err("CSRF proof missing");
            }
            serde_json::to_vec(&(
                name,
                base.unwrap_or_default(),
                folder.unwrap_or_default(),
                overwrite,
                size,
                digest,
            ))
        }
    }
    .map_err(|_| "Invalid upload fingerprint")?;
    Ok(data_encoding::HEXLOWER.encode(Sha256::digest(metadata).as_ref()))
}

pub(crate) struct UploadClaimGuard {
    database: Database,
    id_hash: String,
}

impl UploadClaimGuard {
    pub(crate) fn new(database: Database, id: &str) -> Self {
        let claim = Self {
            database,
            id_hash: crate::db::token_hash(id),
        };
        claim
            .database
            .register_active_upload_operation(&claim.id_hash);
        claim
    }

    pub(crate) fn id_hash(&self) -> &str {
        &self.id_hash
    }
}

impl Drop for UploadClaimGuard {
    fn drop(&mut self) {
        self.database
            .unregister_active_upload_operation(&self.id_hash);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let database = self.database.clone();
        let id_hash = self.id_hash.clone();
        handle.spawn(async move {
            let _ =
                tokio::task::spawn_blocking(move || database.release_upload_operation(&id_hash))
                    .await;
        });
    }
}
