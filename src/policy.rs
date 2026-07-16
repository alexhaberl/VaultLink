use std::path::Path;

use chrono::{DateTime, Utc};

use crate::{
    auth,
    db::{Permission, Share, UploadConflictStrategy},
    path_security, runtime,
    runtime::RuntimeSettings,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareUploadPolicyError {
    UploadPermissionRequiresDirectory,
    OverwriteRequiresDirectoryUpload,
    OverwriteDisabledForExternalWriters,
}

/// Computes the upload policy used by both HTTP share adapters and the domain
/// service. Keeping this decision in production code lets fuzzing exercise the
/// same rule instead of a model that can drift from the handlers.
pub fn share_upload_conflict_strategy(
    is_directory: bool,
    permission: Permission,
    overwrite_requested: bool,
    external_writers: bool,
) -> Result<UploadConflictStrategy, ShareUploadPolicyError> {
    if permission.can_upload() && !is_directory {
        return Err(ShareUploadPolicyError::UploadPermissionRequiresDirectory);
    }
    if !overwrite_requested {
        return Ok(UploadConflictStrategy::Reject);
    }
    if external_writers {
        return Err(ShareUploadPolicyError::OverwriteDisabledForExternalWriters);
    }
    if !is_directory || !permission.can_upload() {
        return Err(ShareUploadPolicyError::OverwriteRequiresDirectoryUpload);
    }
    Ok(UploadConflictStrategy::OverwriteAllowed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadFormField {
    Path,
    Overwrite,
    Csrf,
    File,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadFormStateError {
    TooManyFields,
    DuplicateOrLatePath,
    DuplicateOverwrite,
    DuplicateOrLateCsrf,
    MultipleFiles,
    UnknownField,
}

/// Tracks only multipart structure. Field contents and I/O stay in the HTTP
/// adapter, while ordering and cardinality have one production implementation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UploadFormState {
    fields_seen: usize,
    saw_path: bool,
    saw_overwrite: bool,
    saw_csrf: bool,
    saw_file: bool,
}

impl UploadFormState {
    pub fn observe(
        &mut self,
        field: UploadFormField,
        maximum_fields: usize,
    ) -> Result<(), UploadFormStateError> {
        self.fields_seen = self.fields_seen.saturating_add(1);
        if self.fields_seen > maximum_fields {
            return Err(UploadFormStateError::TooManyFields);
        }
        match field {
            UploadFormField::Path => {
                if std::mem::replace(&mut self.saw_path, true) || self.saw_file {
                    Err(UploadFormStateError::DuplicateOrLatePath)
                } else {
                    Ok(())
                }
            }
            UploadFormField::Overwrite => {
                if std::mem::replace(&mut self.saw_overwrite, true) {
                    Err(UploadFormStateError::DuplicateOverwrite)
                } else {
                    Ok(())
                }
            }
            UploadFormField::Csrf => {
                if std::mem::replace(&mut self.saw_csrf, true) || self.saw_file {
                    Err(UploadFormStateError::DuplicateOrLateCsrf)
                } else {
                    Ok(())
                }
            }
            UploadFormField::File => {
                if std::mem::replace(&mut self.saw_file, true) {
                    Err(UploadFormStateError::MultipleFiles)
                } else {
                    Ok(())
                }
            }
            UploadFormField::Unknown => Err(UploadFormStateError::UnknownField),
        }
    }

    pub fn saw_file(&self) -> bool {
        self.saw_file
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicUploadPolicyError {
    ShareRejected,
    InvalidPath,
    InvalidFilename,
    BlockedExtension,
    TooLarge,
}

pub fn normalize_public_upload_subdir(
    permission: Permission,
    value: &str,
) -> Result<String, PublicUploadPolicyError> {
    if !permission.can_upload() {
        return Err(PublicUploadPolicyError::ShareRejected);
    }
    if permission == Permission::UploadOnly {
        return Ok(String::new());
    }
    path_security::validate_relative(value)
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .map_err(|_| PublicUploadPolicyError::InvalidPath)
}

pub fn validate_public_upload_filename<'a>(
    filename: &'a str,
    blocked_extensions: &[String],
) -> Result<&'a str, PublicUploadPolicyError> {
    let filename = path_security::safe_admin_filename(filename)
        .map_err(|_| PublicUploadPolicyError::InvalidFilename)?;
    if runtime::extension_is_blocked(filename, blocked_extensions) {
        return Err(PublicUploadPolicyError::BlockedExtension);
    }
    Ok(filename)
}

pub fn add_upload_bytes(
    total: u64,
    chunk: u64,
    maximum: u64,
) -> Result<u64, PublicUploadPolicyError> {
    total
        .checked_add(chunk)
        .filter(|new_total| *new_total <= maximum)
        .ok_or(PublicUploadPolicyError::TooLarge)
}

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

    #[test]
    fn share_upload_policy_is_the_single_overwrite_decision() {
        assert_eq!(
            share_upload_conflict_strategy(true, Permission::DownloadUpload, true, false),
            Ok(UploadConflictStrategy::OverwriteAllowed)
        );
        assert_eq!(
            share_upload_conflict_strategy(false, Permission::UploadOnly, false, false),
            Err(ShareUploadPolicyError::UploadPermissionRequiresDirectory)
        );
        assert_eq!(
            share_upload_conflict_strategy(true, Permission::UploadOnly, true, true),
            Err(ShareUploadPolicyError::OverwriteDisabledForExternalWriters)
        );
    }

    #[test]
    fn upload_form_state_rejects_duplicate_and_late_security_fields() {
        let mut state = UploadFormState::default();
        state.observe(UploadFormField::Path, 4).unwrap();
        state.observe(UploadFormField::File, 4).unwrap();
        assert_eq!(
            state.observe(UploadFormField::Csrf, 4),
            Err(UploadFormStateError::DuplicateOrLateCsrf)
        );

        let mut duplicate = UploadFormState::default();
        duplicate.observe(UploadFormField::Overwrite, 4).unwrap();
        assert_eq!(
            duplicate.observe(UploadFormField::Overwrite, 4),
            Err(UploadFormStateError::DuplicateOverwrite)
        );

        let mut duplicate_path = UploadFormState::default();
        duplicate_path.observe(UploadFormField::Path, 4).unwrap();
        assert_eq!(
            duplicate_path.observe(UploadFormField::Path, 4),
            Err(UploadFormStateError::DuplicateOrLatePath)
        );

        let mut late_path = UploadFormState::default();
        late_path.observe(UploadFormField::File, 4).unwrap();
        assert_eq!(
            late_path.observe(UploadFormField::Path, 4),
            Err(UploadFormStateError::DuplicateOrLatePath)
        );

        let mut multiple_files = UploadFormState::default();
        multiple_files.observe(UploadFormField::File, 4).unwrap();
        assert_eq!(
            multiple_files.observe(UploadFormField::File, 4),
            Err(UploadFormStateError::MultipleFiles)
        );

        let mut unknown = UploadFormState::default();
        assert_eq!(
            unknown.observe(UploadFormField::Unknown, 4),
            Err(UploadFormStateError::UnknownField)
        );

        let mut too_many = UploadFormState::default();
        too_many.observe(UploadFormField::Overwrite, 1).unwrap();
        assert_eq!(
            too_many.observe(UploadFormField::Csrf, 1),
            Err(UploadFormStateError::TooManyFields)
        );
    }

    #[test]
    fn public_upload_helpers_cover_path_name_and_size() {
        assert_eq!(
            normalize_public_upload_subdir(Permission::UploadOnly, "ignored/../path").unwrap(),
            ""
        );
        assert_eq!(
            validate_public_upload_filename("payload.exe", &["exe".into()]),
            Err(PublicUploadPolicyError::BlockedExtension)
        );
        assert_eq!(add_upload_bytes(4, 6, 10), Ok(10));
        assert_eq!(
            add_upload_bytes(4, 7, 10),
            Err(PublicUploadPolicyError::TooLarge)
        );
    }
}
