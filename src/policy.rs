use std::path::Path;

use chrono::{DateTime, Utc};

use crate::{auth, db::Share, runtime::RuntimeSettings};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareAvailability {
    Available,
    Inactive,
    Expired,
}

pub fn share_availability(share: &Share, now: DateTime<Utc>) -> ShareAvailability {
    if !share.active {
        ShareAvailability::Inactive
    } else if share.expires_at.is_some_and(|expires| expires <= now) {
        ShareAvailability::Expired
    } else {
        ShareAvailability::Available
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharePasswordValidation {
    Valid,
    InvalidCharacterLength,
    TooManyBytes,
}

pub fn validate_share_password(
    settings: &RuntimeSettings,
    password: &str,
) -> SharePasswordValidation {
    let characters = password.chars().count();
    if characters < settings.share_password_min_length
        || characters > settings.share_password_max_length
    {
        SharePasswordValidation::InvalidCharacterLength
    } else if password.len() > auth::MAX_PASSWORD_BYTES {
        SharePasswordValidation::TooManyBytes
    } else {
        SharePasswordValidation::Valid
    }
}

pub fn valid_share_password(settings: &RuntimeSettings, password: &str) -> bool {
    validate_share_password(settings, password) == SharePasswordValidation::Valid
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewKind {
    Text,
    Image(&'static str),
    Pdf,
}

impl PreviewKind {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; charset=utf-8",
            Self::Image(content_type) => content_type,
            Self::Pdf => "application/pdf",
        }
    }

    pub fn is_media(self) -> bool {
        matches!(self, Self::Image(_) | Self::Pdf)
    }
}

pub fn preview_kind(path: &str, settings: &RuntimeSettings) -> Option<PreviewKind> {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())?
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if settings
        .preview_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&extension))
    {
        return Some(PreviewKind::Text);
    }
    if settings.pdf_preview_enabled && extension == "pdf" {
        return Some(PreviewKind::Pdf);
    }
    if settings
        .image_preview_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&extension))
    {
        return image_content_type(&extension).map(PreviewKind::Image);
    }
    None
}

pub fn preview_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    preview_kind(path, settings).is_some()
}

/// Preserve the API metadata contract: configured extensions are advertised even
/// when VaultLink has no built-in renderer for their media type.
pub fn preview_metadata_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    settings
        .preview_extensions
        .iter()
        .any(|allowed| allowed == &extension)
        || (settings.pdf_preview_enabled && extension == "pdf")
        || settings
            .image_preview_extensions
            .iter()
            .any(|allowed| allowed == &extension)
}

fn image_content_type(extension: &str) -> Option<&'static str> {
    match extension {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        "avif" => Some("image/avif"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Permission, UploadConflictStrategy};

    fn runtime_settings() -> RuntimeSettings {
        RuntimeSettings {
            public_base_url: "http://localhost:8080".into(),
            max_upload_size: 1,
            blocked_extensions: Vec::new(),
            share_password_min_length: 8,
            share_password_max_length: 128,
            share_unlock_minutes: 30,
            max_zip_size: 1,
            max_zip_files: 1,
            max_search_entries: 1,
            max_search_results: 1,
            max_preview_size: 1,
            preview_extensions: vec!["txt".into()],
            image_preview_extensions: vec!["png".into(), "tiff".into()],
            pdf_preview_enabled: true,
            max_media_preview_size: 1,
            audit_client_ip_enabled: false,
        }
    }

    fn share(active: bool, expires_at: Option<DateTime<Utc>>) -> Share {
        Share {
            id: 1,
            token: "token".into(),
            alias: None,
            relative_path: "file.txt".into(),
            is_directory: false,
            permission: Permission::DownloadOnly,
            expires_at,
            max_downloads: None,
            max_upload_size: None,
            max_upload_total_size: None,
            max_upload_files: None,
            uploaded_bytes: 0,
            uploaded_files: 0,
            download_count: 0,
            active,
            password_hash: None,
            upload_conflict_strategy: UploadConflictStrategy::Reject,
            created_at: String::new(),
            upload_policy_epoch: 0,
        }
    }

    #[test]
    fn share_expires_at_the_exact_boundary() {
        let now = Utc::now();
        assert_eq!(
            share_availability(&share(true, Some(now)), now),
            ShareAvailability::Expired
        );
        assert_eq!(
            share_availability(
                &share(true, Some(now + chrono::Duration::nanoseconds(1))),
                now
            ),
            ShareAvailability::Available
        );
        assert_eq!(
            share_availability(&share(false, None), now),
            ShareAvailability::Inactive
        );
    }

    #[test]
    fn api_metadata_preserves_configured_unmapped_image_extensions() {
        let settings = runtime_settings();
        assert!(preview_metadata_allowed("scan.tiff", &settings));
        assert!(!preview_allowed("scan.tiff", &settings));
    }
}
