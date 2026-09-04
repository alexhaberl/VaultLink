pub(crate) const MAX_SQLITE_UNSIGNED: u64 = i64::MAX as u64;
pub(crate) const MAX_AUDIT_ROWS: i64 = 100_000;

pub(crate) fn required_audit_job<T, F>(
    operation: F,
) -> impl FnOnce(Database) -> rusqlite::Result<T> + Send + 'static
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<Audited<T>> + Send + 'static,
{
    required_audit::audited_job(operation)
}

pub(crate) fn required_audit_result_job<T, E, F>(
    operation: F,
) -> impl FnOnce(Database) -> Result<T, E> + Send + 'static
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<Audited<T>, E> + Send + 'static,
{
    required_audit::audited_result_job(operation)
}

pub(crate) fn required_session_audit_job<T, F>(
    operation: F,
) -> impl FnOnce(Database) -> rusqlite::Result<SessionBound<T>> + Send + 'static
where
    T: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<SessionBound<Audited<T>>> + Send + 'static,
{
    required_audit::session_audited_job(operation)
}

pub(crate) fn required_session_audit_result_job<T, E, F>(
    operation: F,
) -> impl FnOnce(Database) -> Result<SessionBound<T>, E> + Send + 'static
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<SessionBound<Audited<T>>, E> + Send + 'static,
{
    required_audit::session_audited_result_job(operation)
}

pub(crate) fn required_audit_decision_job<T, R, F>(
    operation: F,
) -> impl FnOnce(Database) -> rusqlite::Result<RequiredAuditCompletion<T, R>> + Send + 'static
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(Database) -> rusqlite::Result<RequiredAuditDecision<T, R>> + Send + 'static,
{
    required_audit::audited_decision_job(operation)
}

pub(crate) fn required_session_audit_decision_result_job<T, R, E, F>(
    operation: F,
) -> impl FnOnce(Database) -> Result<SessionBound<RequiredAuditCompletion<T, R>>, E> + Send + 'static
where
    T: Send + 'static,
    R: Send + 'static,
    E: Send + 'static,
    F: FnOnce(Database) -> Result<SessionBound<RequiredAuditDecision<T, R>>, E> + Send + 'static,
{
    required_audit::session_audited_decision_result_job(operation)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub(crate) enum AuditPriority {
    Routine = 0,
    Security = 100,
}

impl AuditPriority {
    const fn as_i64(self) -> i64 {
        self as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditAction {
    AccountMfaChanged,
    AccountMfaEnrollmentStarted,
    AccountPasswordChanged,
    AccountTotpSettingReauthFailed,
    AdminActivated,
    AdminCreated,
    AdminDeactivated,
    AdminDownload,
    AdminPasswordReset,
    AdminPreview,
    AdminRecovered,
    AdminTotpDisabled,
    AdminTotpEnabled,
    AdminTotpReset,
    AdminUpload,
    AdminUploadDurabilityUncertain,
    AdminUploadReplaced,
    AuditClientIpsDeleted,
    DirectoryCreated,
    Download,
    InitialAdminCreated,
    LoginFailed,
    LoginSuccess,
    LoginSuccessWebauthn,
    Logout,
    MfaFailed,
    MfaReplayed,
    PasswordVerified,
    PathDeleted,
    PathRenamed,
    Preview,
    SecurityKeyReauthFailed,
    ServiceTokenCreated,
    ServiceTokenRevoked,
    ServiceTokensRevokedAll,
    SettingsUpdated,
    ShareActivated,
    ShareCreated,
    ShareDeactivated,
    ShareDeleted,
    SharePasswordRemoved,
    SharePasswordSet,
    ShareToggled,
    ShareUnlockFailed,
    ShareUnlocked,
    ShareUploadConflictUpdated,
    ShareUploadLimitsUpdated,
    Upload,
    UploadDirectoriesCreated,
    UploadDurabilityUncertain,
    UploadQuotaCommitted,
    UploadReplaced,
    WebauthnCredentialAdded,
    WebauthnCredentialDeleted,
    ZipDownload,
}

impl AuditAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AccountMfaChanged => "account_mfa_changed",
            Self::AccountMfaEnrollmentStarted => "account_mfa_enrollment_started",
            Self::AccountPasswordChanged => "account_password_changed",
            Self::AccountTotpSettingReauthFailed => "account_totp_setting_reauth_failed",
            Self::AdminActivated => "admin_activated",
            Self::AdminCreated => "admin_created",
            Self::AdminDeactivated => "admin_deactivated",
            Self::AdminDownload => "admin_download",
            Self::AdminPasswordReset => "admin_password_reset",
            Self::AdminPreview => "admin_preview",
            Self::AdminRecovered => "admin_recovered",
            Self::AdminTotpDisabled => "admin_totp_disabled",
            Self::AdminTotpEnabled => "admin_totp_enabled",
            Self::AdminTotpReset => "admin_totp_reset",
            Self::AdminUpload => "admin_upload",
            Self::AdminUploadDurabilityUncertain => "admin_upload_durability_uncertain",
            Self::AdminUploadReplaced => "admin_upload_replaced",
            Self::AuditClientIpsDeleted => "audit_client_ips_deleted",
            Self::DirectoryCreated => "directory_created",
            Self::Download => "download",
            Self::InitialAdminCreated => "initial_admin_created",
            Self::LoginFailed => "login_failed",
            Self::LoginSuccess => "login_success",
            Self::LoginSuccessWebauthn => "login_success_webauthn",
            Self::Logout => "logout",
            Self::MfaFailed => "mfa_failed",
            Self::MfaReplayed => "mfa_replayed",
            Self::PasswordVerified => "password_verified",
            Self::PathDeleted => "path_deleted",
            Self::PathRenamed => "path_renamed",
            Self::Preview => "preview",
            Self::SecurityKeyReauthFailed => "security_key_reauth_failed",
            Self::ServiceTokenCreated => "service_token_created",
            Self::ServiceTokenRevoked => "service_token_revoked",
            Self::ServiceTokensRevokedAll => "service_tokens_revoked_all",
            Self::SettingsUpdated => "settings_updated",
            Self::ShareActivated => "share_activated",
            Self::ShareCreated => "share_created",
            Self::ShareDeactivated => "share_deactivated",
            Self::ShareDeleted => "share_deleted",
            Self::SharePasswordRemoved => "share_password_removed",
            Self::SharePasswordSet => "share_password_set",
            Self::ShareToggled => "share_toggled",
            Self::ShareUnlockFailed => "share_unlock_failed",
            Self::ShareUnlocked => "share_unlocked",
            Self::ShareUploadConflictUpdated => "share_upload_conflict_updated",
            Self::ShareUploadLimitsUpdated => "share_upload_limits_updated",
            Self::Upload => "upload",
            Self::UploadDirectoriesCreated => "upload_directories_created",
            Self::UploadDurabilityUncertain => "upload_durability_uncertain",
            Self::UploadQuotaCommitted => "upload_quota_committed",
            Self::UploadReplaced => "upload_replaced",
            Self::WebauthnCredentialAdded => "webauthn_credential_added",
            Self::WebauthnCredentialDeleted => "webauthn_credential_deleted",
            Self::ZipDownload => "zip_download",
        }
    }

    const fn priority(self) -> AuditPriority {
        match self {
            Self::AdminDownload
            | Self::AdminPreview
            | Self::Download
            | Self::Preview
            | Self::UploadQuotaCommitted
            | Self::ZipDownload => AuditPriority::Routine,
            Self::AccountMfaChanged
            | Self::AccountMfaEnrollmentStarted
            | Self::AccountPasswordChanged
            | Self::AccountTotpSettingReauthFailed
            | Self::AdminActivated
            | Self::AdminCreated
            | Self::AdminDeactivated
            | Self::AdminPasswordReset
            | Self::AdminRecovered
            | Self::AdminTotpDisabled
            | Self::AdminTotpEnabled
            | Self::AdminTotpReset
            | Self::AdminUpload
            | Self::AdminUploadDurabilityUncertain
            | Self::AdminUploadReplaced
            | Self::AuditClientIpsDeleted
            | Self::DirectoryCreated
            | Self::InitialAdminCreated
            | Self::LoginFailed
            | Self::LoginSuccess
            | Self::LoginSuccessWebauthn
            | Self::Logout
            | Self::MfaFailed
            | Self::MfaReplayed
            | Self::PasswordVerified
            | Self::PathDeleted
            | Self::PathRenamed
            | Self::SecurityKeyReauthFailed
            | Self::ServiceTokenCreated
            | Self::ServiceTokenRevoked
            | Self::ServiceTokensRevokedAll
            | Self::SettingsUpdated
            | Self::ShareActivated
            | Self::ShareCreated
            | Self::ShareDeactivated
            | Self::ShareDeleted
            | Self::SharePasswordRemoved
            | Self::SharePasswordSet
            | Self::ShareToggled
            | Self::ShareUnlockFailed
            | Self::ShareUnlocked
            | Self::ShareUploadConflictUpdated
            | Self::ShareUploadLimitsUpdated
            | Self::Upload
            | Self::UploadDirectoriesCreated
            | Self::UploadDurabilityUncertain
            | Self::UploadReplaced
            | Self::WebauthnCredentialAdded
            | Self::WebauthnCredentialDeleted => AuditPriority::Security,
        }
    }

    #[cfg(test)]
    const ALL: &'static [Self] = &[
        Self::AccountMfaChanged,
        Self::AccountMfaEnrollmentStarted,
        Self::AccountPasswordChanged,
        Self::AccountTotpSettingReauthFailed,
        Self::AdminActivated,
        Self::AdminCreated,
        Self::AdminDeactivated,
        Self::AdminDownload,
        Self::AdminPasswordReset,
        Self::AdminPreview,
        Self::AdminRecovered,
        Self::AdminTotpDisabled,
        Self::AdminTotpEnabled,
        Self::AdminTotpReset,
        Self::AdminUpload,
        Self::AdminUploadDurabilityUncertain,
        Self::AdminUploadReplaced,
        Self::AuditClientIpsDeleted,
        Self::DirectoryCreated,
        Self::Download,
        Self::InitialAdminCreated,
        Self::LoginFailed,
        Self::LoginSuccess,
        Self::LoginSuccessWebauthn,
        Self::Logout,
        Self::MfaFailed,
        Self::MfaReplayed,
        Self::PasswordVerified,
        Self::PathDeleted,
        Self::PathRenamed,
        Self::Preview,
        Self::SecurityKeyReauthFailed,
        Self::ServiceTokenCreated,
        Self::ServiceTokenRevoked,
        Self::ServiceTokensRevokedAll,
        Self::SettingsUpdated,
        Self::ShareActivated,
        Self::ShareCreated,
        Self::ShareDeactivated,
        Self::ShareDeleted,
        Self::SharePasswordRemoved,
        Self::SharePasswordSet,
        Self::ShareToggled,
        Self::ShareUnlockFailed,
        Self::ShareUnlocked,
        Self::ShareUploadConflictUpdated,
        Self::ShareUploadLimitsUpdated,
        Self::Upload,
        Self::UploadDirectoriesCreated,
        Self::UploadDurabilityUncertain,
        Self::UploadQuotaCommitted,
        Self::UploadReplaced,
        Self::WebauthnCredentialAdded,
        Self::WebauthnCredentialDeleted,
        Self::ZipDownload,
    ];
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditRetentionOutcome {
    pub routine_deleted: usize,
    pub security_deleted: usize,
}

impl AuditRetentionOutcome {
    pub fn total_deleted(self) -> usize {
        self.routine_deleted.saturating_add(self.security_deleted)
    }
}
