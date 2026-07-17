use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::{
    config::MAX_UPLOAD_SIZE,
    db::{
        AuditContext, Database, Permission, UploadConflictStrategy,
        DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE, MAX_SQLITE_UNSIGNED,
    },
    path_security,
    policy::{self, SharePasswordValidation, ShareUploadPolicyError},
    runtime::RuntimeSettings,
    sensitive::SecretString,
    AppState,
};

/// Serializes every administrator-controlled share-authority change with the
/// public-upload policy checkpoint.  The guard is moved into the blocking DB
/// task on commit, so cancelling the HTTP adapter cannot release the storage
/// lock before the database mutation has reached a terminal result.
pub(crate) struct ShareAuthorityMutation {
    database: Database,
    storage_guard: tokio::sync::OwnedMutexGuard<()>,
}

impl ShareAuthorityMutation {
    pub(crate) async fn acquire(state: &AppState) -> Self {
        Self::from_guard(state, state.storage_mutation.clone().lock_owned().await)
    }

    pub(crate) fn from_guard(
        state: &AppState,
        storage_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Self {
        Self {
            database: state.db.clone(),
            storage_guard,
        }
    }

    pub(crate) async fn commit<T, F>(self, operation: F) -> crate::http_auth::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Database) -> rusqlite::Result<T> + Send + 'static,
    {
        let Self {
            database,
            storage_guard,
        } = self;
        crate::http_auth::required_database(database, move |database| {
            let _storage_guard = storage_guard;
            operation(database)
        })
        .await
    }
}

/// The target kind established by the secure-filesystem adapter while it holds
/// the storage mutation lock. Special files cannot be represented here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareTarget {
    File,
    Directory,
}

impl ShareTarget {
    fn is_directory(self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// Transport-neutral password input. Browser adapters use
/// `WithConfirmation`; JSON clients use `Direct`.
///
/// This type intentionally cannot be cloned because its secret members cannot
/// be cloned. A password is moved exactly once into the admitted hash task.
pub(crate) enum SharePasswordInput {
    None,
    Direct(SecretString),
    WithConfirmation {
        password: Option<SecretString>,
        confirmation: Option<SecretString>,
    },
}

/// Common input for HTML and JSON share creation. Unit conversion, date/time
/// parsing, target metadata lookup, and authentication stay in the adapters;
/// all security-relevant share rules are enforced by `ShareService`.
pub(crate) struct CreateShareCommand {
    pub(crate) token: String,
    pub(crate) path: String,
    pub(crate) target: ShareTarget,
    pub(crate) permission: Permission,
    pub(crate) alias: Option<String>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) max_downloads: Option<u64>,
    pub(crate) max_upload_size: Option<u64>,
    pub(crate) max_upload_total_size: Option<u64>,
    pub(crate) max_upload_files: Option<u64>,
    pub(crate) password: SharePasswordInput,
    pub(crate) overwrite_allowed: bool,
    pub(crate) created_by: i64,
}

/// Opaque, validated state that can safely cross the asynchronous password
/// hashing boundary. It contains no plaintext password.
pub(crate) struct PreparedCreateShare {
    token: String,
    path: String,
    is_directory: bool,
    permission: Permission,
    alias: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    max_downloads: Option<u64>,
    max_upload_size: Option<u64>,
    max_upload_total_size: Option<u64>,
    max_upload_files: Option<u64>,
    upload_conflict_strategy: UploadConflictStrategy,
    created_by: i64,
    password_protected: bool,
    audit_detail: String,
}

/// Validated state before Argon2 hashing. Splitting it explicitly moves the
/// only application-owned plaintext allocation to the hash task.
pub(crate) struct ValidatedCreateShare {
    prepared: PreparedCreateShare,
    password_to_hash: Option<SecretString>,
}

impl ValidatedCreateShare {
    pub(crate) fn into_password_hash_input(self) -> (PreparedCreateShare, Option<SecretString>) {
        (self.prepared, self.password_to_hash)
    }
}

#[derive(Debug, Error)]
pub(crate) enum ShareServiceError {
    #[error("invalid share path")]
    InvalidPath,
    #[error("invalid share alias")]
    InvalidAlias,
    #[error("share expiration must be in the future")]
    ExpirationNotFuture,
    #[error("upload permission requires a directory target")]
    UploadPermissionRequiresDirectory,
    #[error("download limit must be between 1 and SQLite's signed integer maximum")]
    InvalidDownloadLimit,
    #[error("single-file upload limit must be between 1 and the application maximum")]
    InvalidUploadLimit,
    #[error("upload limits require a directory share with upload permission")]
    UploadLimitsRequireDirectoryUpload,
    #[error("cumulative upload limit is invalid")]
    InvalidUploadTotalLimit,
    #[error("cumulative upload limit is below the effective single-file limit")]
    UploadTotalBelowSingleLimit,
    #[error("upload file-count limit is invalid")]
    InvalidUploadFileLimit,
    #[error("overwrite requires a directory share with upload permission")]
    OverwriteRequiresDirectoryUpload,
    #[error("overwrite is disabled while external storage writers are enabled")]
    OverwriteDisabledForExternalWriters,
    #[error("password and confirmation are required")]
    PasswordConfirmationRequired,
    #[error("password and confirmation do not match")]
    PasswordConfirmationMismatch,
    #[error("share password character length is outside the configured range")]
    InvalidPasswordCharacterLength,
    #[error("share password exceeds the maximum byte length")]
    PasswordTooManyBytes,
    #[error("validated password and supplied password hash disagree")]
    PasswordHashStateMismatch,
    #[error("share database operation failed")]
    Database(#[source] rusqlite::Error),
}

impl ShareServiceError {
    pub(crate) fn into_database_error(self) -> Option<rusqlite::Error> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CreatedShare {
    pub(crate) id: i64,
    pub(crate) token: String,
}

/// Transport-neutral share domain service. HTTP adapters only translate their
/// request types into `CreateShareCommand` and map the typed errors back to a
/// response. The service owns validation and the required-audit DB call.
#[derive(Clone)]
pub(crate) struct ShareService {
    database: Database,
    settings: RuntimeSettings,
    external_writers: bool,
}

impl ShareService {
    pub(crate) fn new(
        database: Database,
        settings: RuntimeSettings,
        external_writers: bool,
    ) -> Self {
        Self {
            database,
            settings,
            external_writers,
        }
    }

    pub(crate) fn prepare_create(
        &self,
        command: CreateShareCommand,
    ) -> Result<ValidatedCreateShare, ShareServiceError> {
        self.prepare_create_at(command, Utc::now())
    }

    fn prepare_create_at(
        &self,
        command: CreateShareCommand,
        now: DateTime<Utc>,
    ) -> Result<ValidatedCreateShare, ShareServiceError> {
        let path = self.normalize_target_path(&command.path)?;
        let alias = command.alias.filter(|alias| !alias.trim().is_empty());
        if alias
            .as_deref()
            .is_some_and(|alias| path_security::validate_share_alias(alias).is_err())
        {
            return Err(ShareServiceError::InvalidAlias);
        }
        if command
            .expires_at
            .as_ref()
            .is_some_and(|expires_at| expires_at <= &now)
        {
            return Err(ShareServiceError::ExpirationNotFuture);
        }

        let is_directory = command.target.is_directory();
        let allows_upload = command.permission.can_upload();
        if matches!(
            policy::share_upload_conflict_strategy(is_directory, command.permission, false, false,),
            Err(ShareUploadPolicyError::UploadPermissionRequiresDirectory)
        ) {
            return Err(ShareServiceError::UploadPermissionRequiresDirectory);
        }
        if command
            .max_downloads
            .is_some_and(|limit| limit == 0 || limit > MAX_SQLITE_UNSIGNED)
        {
            return Err(ShareServiceError::InvalidDownloadLimit);
        }
        if command
            .max_upload_size
            .is_some_and(|limit| limit == 0 || limit > MAX_UPLOAD_SIZE)
        {
            return Err(ShareServiceError::InvalidUploadLimit);
        }

        let is_upload_directory = is_directory && allows_upload;
        let has_upload_limits = command.max_upload_size.is_some()
            || command.max_upload_total_size.is_some()
            || command.max_upload_files.is_some();
        if has_upload_limits && !is_upload_directory {
            return Err(ShareServiceError::UploadLimitsRequireDirectoryUpload);
        }

        let effective_single_upload_limit = command
            .max_upload_size
            .unwrap_or(self.settings.max_upload_size)
            .min(MAX_UPLOAD_SIZE);
        let max_upload_total_size = if is_upload_directory {
            let limit = command.max_upload_total_size.unwrap_or_else(|| {
                DEFAULT_SHARE_UPLOAD_TOTAL_SIZE.max(effective_single_upload_limit)
            });
            if limit == 0 || limit > MAX_SQLITE_UNSIGNED {
                return Err(ShareServiceError::InvalidUploadTotalLimit);
            }
            if limit < effective_single_upload_limit {
                return Err(ShareServiceError::UploadTotalBelowSingleLimit);
            }
            Some(limit)
        } else {
            None
        };
        let max_upload_files = if is_upload_directory {
            let limit = command
                .max_upload_files
                .unwrap_or(DEFAULT_SHARE_UPLOAD_FILE_COUNT);
            if limit == 0 || limit > MAX_SQLITE_UNSIGNED {
                return Err(ShareServiceError::InvalidUploadFileLimit);
            }
            Some(limit)
        } else {
            None
        };

        let upload_conflict_strategy = policy::share_upload_conflict_strategy(
            is_directory,
            command.permission,
            command.overwrite_allowed,
            self.external_writers,
        )
        .map_err(|error| match error {
            ShareUploadPolicyError::UploadPermissionRequiresDirectory => {
                ShareServiceError::UploadPermissionRequiresDirectory
            }
            ShareUploadPolicyError::OverwriteRequiresDirectoryUpload => {
                ShareServiceError::OverwriteRequiresDirectoryUpload
            }
            ShareUploadPolicyError::OverwriteDisabledForExternalWriters => {
                ShareServiceError::OverwriteDisabledForExternalWriters
            }
        })?;

        let password_to_hash = self.prepare_password(command.password)?;
        let password_protected = password_to_hash.is_some();
        let audit_detail = format!(
            "path={path};permission={};alias={};expires_at={};transfer_limit={};upload_limit={};upload_total_limit={};upload_file_limit={};password_protected={password_protected};overwrite_allowed={}",
            command.permission.as_str(),
            alias.as_deref().unwrap_or(""),
            command
                .expires_at
                .as_ref()
                .map(DateTime::to_rfc3339)
                .unwrap_or_default(),
            optional_number(command.max_downloads),
            optional_number(command.max_upload_size),
            optional_number(max_upload_total_size),
            optional_number(max_upload_files),
            upload_conflict_strategy.can_overwrite(),
        );

        Ok(ValidatedCreateShare {
            prepared: PreparedCreateShare {
                token: command.token,
                path,
                is_directory,
                permission: command.permission,
                alias,
                expires_at: command.expires_at,
                max_downloads: command.max_downloads,
                max_upload_size: command.max_upload_size,
                max_upload_total_size,
                max_upload_files,
                upload_conflict_strategy,
                created_by: command.created_by,
                password_protected,
                audit_detail,
            },
            password_to_hash,
        })
    }

    /// Normalizes the target before the adapter performs its descriptor-based
    /// metadata lookup. `prepare_create` validates it again, so callers cannot
    /// bypass the invariant by constructing a command directly.
    pub(crate) fn normalize_target_path(&self, path: &str) -> Result<String, ShareServiceError> {
        path_security::validate_relative(path)
            .map_err(|_| ShareServiceError::InvalidPath)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
    }

    pub(crate) fn prepare_password(
        &self,
        input: SharePasswordInput,
    ) -> Result<Option<SecretString>, ShareServiceError> {
        let password = match input {
            SharePasswordInput::None => return Ok(None),
            SharePasswordInput::Direct(password) => {
                if password.expose_secret().trim().is_empty() {
                    return Ok(None);
                }
                password
            }
            SharePasswordInput::WithConfirmation {
                password,
                confirmation,
            } => {
                let password = nonempty_secret(password);
                let confirmation = nonempty_secret(confirmation);
                let (password, confirmation) = match (password, confirmation) {
                    // `WithConfirmation` is used only after a transport has
                    // observed an explicit password-protection request. Do
                    // not silently turn whitespace-only values into a
                    // passwordless share.
                    (None, None) => {
                        return Err(ShareServiceError::PasswordConfirmationRequired);
                    }
                    (Some(password), Some(confirmation)) => (password, confirmation),
                    _ => return Err(ShareServiceError::PasswordConfirmationRequired),
                };
                if !password.matches_confirmation(&confirmation) {
                    return Err(ShareServiceError::PasswordConfirmationMismatch);
                }
                password
            }
        };
        match policy::validate_share_password(&self.settings, password.expose_secret()) {
            SharePasswordValidation::Valid => Ok(Some(password)),
            SharePasswordValidation::InvalidCharacterLength => {
                Err(ShareServiceError::InvalidPasswordCharacterLength)
            }
            SharePasswordValidation::TooManyBytes => Err(ShareServiceError::PasswordTooManyBytes),
        }
    }

    /// Persists an already validated command together with its required audit
    /// row. The caller supplies the Argon2 result after moving the plaintext
    /// returned by `into_password_hash_input` into an admitted blocking task.
    pub(crate) fn create(
        &self,
        prepared: PreparedCreateShare,
        password_hash: Option<&str>,
        audit_context: &AuditContext,
    ) -> Result<CreatedShare, ShareServiceError> {
        if prepared.password_protected != password_hash.is_some() {
            return Err(ShareServiceError::PasswordHashStateMismatch);
        }
        let id = self
            .database
            .create_share_with_upload_limits_and_audit(
                &prepared.token,
                prepared.alias.as_deref(),
                &prepared.path,
                prepared.is_directory,
                &prepared.permission,
                prepared.expires_at,
                prepared.max_downloads,
                prepared.max_upload_size,
                prepared.max_upload_total_size,
                prepared.max_upload_files,
                prepared.created_by,
                password_hash,
                &prepared.upload_conflict_strategy,
                audit_context,
                Some(prepared.audit_detail),
            )
            .map_err(ShareServiceError::Database)?;
        Ok(CreatedShare {
            id,
            token: prepared.token,
        })
    }
}

fn nonempty_secret(secret: Option<SecretString>) -> Option<SecretString> {
    secret.filter(|secret| !secret.expose_secret().trim().is_empty())
}

fn optional_number(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn settings() -> RuntimeSettings {
        RuntimeSettings {
            public_base_url: "https://vaultlink.invalid".into(),
            max_upload_size: 16 * 1024 * 1024,
            blocked_extensions: Vec::new(),
            share_password_min_length: 12,
            share_password_max_length: 128,
            share_unlock_minutes: 30,
            max_zip_size: 1,
            max_zip_files: 1,
            max_search_entries: 1,
            max_search_results: 1,
            max_preview_size: 1,
            preview_extensions: vec!["txt".into()],
            image_preview_extensions: vec!["png".into()],
            pdf_preview_enabled: true,
            max_media_preview_size: 1,
            audit_client_ip_enabled: false,
        }
    }

    fn service(external_writers: bool) -> ShareService {
        let database = Database::open(":memory:").unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        ShareService::new(database, settings(), external_writers)
    }

    fn command() -> CreateShareCommand {
        CreateShareCommand {
            token: "share-token".into(),
            path: "documents".into(),
            target: ShareTarget::Directory,
            permission: Permission::DownloadUpload,
            alias: Some("documents-2026".into()),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            max_downloads: Some(10),
            max_upload_size: Some(1_000),
            max_upload_total_size: Some(10_000),
            max_upload_files: Some(20),
            password: SharePasswordInput::None,
            overwrite_allowed: false,
            created_by: 1,
        }
    }

    #[test]
    fn validates_and_normalizes_path_alias_and_expiration() {
        let service = service(false);
        let now = Utc::now();
        let mut valid = command();
        valid.path = "documents/./reports".into();
        valid.alias = Some("   ".into());
        valid.expires_at = Some(now + Duration::seconds(1));
        let validated = service.prepare_create_at(valid, now).unwrap();
        assert_eq!(validated.prepared.path, "documents/reports");
        assert_eq!(validated.prepared.alias, None);

        let mut invalid_path = command();
        invalid_path.path = "../private".into();
        assert!(matches!(
            service.prepare_create_at(invalid_path, now),
            Err(ShareServiceError::InvalidPath)
        ));

        let mut invalid_alias = command();
        invalid_alias.alias = Some("short".into());
        assert!(matches!(
            service.prepare_create_at(invalid_alias, now),
            Err(ShareServiceError::InvalidAlias)
        ));

        let mut expired = command();
        expired.expires_at = Some(now);
        assert!(matches!(
            service.prepare_create_at(expired, now),
            Err(ShareServiceError::ExpirationNotFuture)
        ));
    }

    #[test]
    fn target_permission_and_overwrite_rules_are_shared() {
        let local_service = service(false);
        let mut file_upload = command();
        file_upload.target = ShareTarget::File;
        assert!(matches!(
            local_service.prepare_create(file_upload),
            Err(ShareServiceError::UploadPermissionRequiresDirectory)
        ));

        let mut overwrite_download = command();
        overwrite_download.permission = Permission::DownloadOnly;
        overwrite_download.max_upload_size = None;
        overwrite_download.max_upload_total_size = None;
        overwrite_download.max_upload_files = None;
        overwrite_download.overwrite_allowed = true;
        assert!(matches!(
            local_service.prepare_create(overwrite_download),
            Err(ShareServiceError::OverwriteRequiresDirectoryUpload)
        ));

        let external_service = service(true);
        let mut overwrite_external = command();
        overwrite_external.overwrite_allowed = true;
        assert!(matches!(
            external_service.prepare_create(overwrite_external),
            Err(ShareServiceError::OverwriteDisabledForExternalWriters)
        ));
    }

    #[test]
    fn quota_defaults_and_cross_limit_invariant_are_enforced() {
        let service = service(false);
        let mut defaults = command();
        defaults.max_upload_size = None;
        defaults.max_upload_total_size = None;
        defaults.max_upload_files = None;
        let validated = service.prepare_create(defaults).unwrap();
        assert_eq!(
            validated.prepared.max_upload_total_size,
            Some(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE)
        );
        assert_eq!(
            validated.prepared.max_upload_files,
            Some(DEFAULT_SHARE_UPLOAD_FILE_COUNT)
        );

        let mut total_below_single = command();
        total_below_single.max_upload_size = Some(2_000);
        total_below_single.max_upload_total_size = Some(1_999);
        assert!(matches!(
            service.prepare_create(total_below_single),
            Err(ShareServiceError::UploadTotalBelowSingleLimit)
        ));

        let mut limits_without_upload = command();
        limits_without_upload.permission = Permission::DownloadOnly;
        assert!(matches!(
            service.prepare_create(limits_without_upload),
            Err(ShareServiceError::UploadLimitsRequireDirectoryUpload)
        ));
    }

    #[test]
    fn password_confirmation_and_configured_policy_use_owned_secrets() {
        let service = service(false);
        let (_, password) = service
            .prepare_create(command())
            .unwrap()
            .into_password_hash_input();
        assert!(password.is_none());

        let mut whitespace_only = command();
        whitespace_only.password = SharePasswordInput::WithConfirmation {
            password: Some(SecretString::from("            ")),
            confirmation: Some(SecretString::from("            ")),
        };
        assert!(matches!(
            service.prepare_create(whitespace_only),
            Err(ShareServiceError::PasswordConfirmationRequired)
        ));

        let mut mismatch = command();
        mismatch.password = SharePasswordInput::WithConfirmation {
            password: Some(SecretString::from("long enough password")),
            confirmation: Some(SecretString::from("different password")),
        };
        assert!(matches!(
            service.prepare_create(mismatch),
            Err(ShareServiceError::PasswordConfirmationMismatch)
        ));

        let mut too_short = command();
        too_short.password = SharePasswordInput::Direct(SecretString::from("short"));
        assert!(matches!(
            service.prepare_create(too_short),
            Err(ShareServiceError::InvalidPasswordCharacterLength)
        ));

        let mut valid = command();
        valid.password = SharePasswordInput::WithConfirmation {
            password: Some(SecretString::from("long enough password")),
            confirmation: Some(SecretString::from("long enough password")),
        };
        let validated = service.prepare_create(valid).unwrap();
        let (_, password) = validated.into_password_hash_input();
        assert_eq!(
            password.as_ref().map(SecretString::expose_secret),
            Some("long enough password")
        );
    }

    #[test]
    fn create_persists_share_and_required_audit_without_secret_detail() {
        let service = service(false);
        let validated = service.prepare_create(command()).unwrap();
        let (prepared, password) = validated.into_password_hash_input();
        assert!(password.is_none());
        let created = service
            .create(
                prepared,
                None,
                &AuditContext::new("admin", Some("192.0.2.1".into())),
            )
            .unwrap();
        assert_eq!(created.id, 1);
        assert_eq!(created.token, "share-token");

        let share = service
            .database
            .share_by_token("share-token")
            .unwrap()
            .unwrap();
        assert_eq!(share.relative_path, "documents");
        assert_eq!(share.alias.as_deref(), Some("documents-2026"));
        assert_eq!(share.max_upload_total_size, Some(10_000));
        let events = service.database.list_audit(None, 10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "share_created");
        assert_eq!(events[0].actor, "admin");
        assert!(!events[0]
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("password="));
    }

    #[test]
    fn create_rejects_missing_or_unexpected_hash_before_database_mutation() {
        let service = service(false);
        let mut protected = command();
        protected.password =
            SharePasswordInput::Direct(SecretString::from("correct horse battery staple"));
        let validated = service.prepare_create(protected).unwrap();
        let (prepared, _password) = validated.into_password_hash_input();
        assert!(matches!(
            service.create(prepared, None, &AuditContext::new("admin", None)),
            Err(ShareServiceError::PasswordHashStateMismatch)
        ));
        assert_eq!(service.database.count_audit(None).unwrap(), 0);
        assert!(service.database.list_shares().unwrap().is_empty());
    }
}
