use chrono::{DateTime, Utc};

use crate::{
    auth,
    db::{AuditContext, Database, PasswordSessionCreationOutcome},
    sensitive::SecretString,
};

/// Transport-neutral input for password authentication and pre-MFA session
/// creation. HTTP adapters remain responsible for rate limiting and cookies.
pub(crate) struct PasswordLoginCommand {
    pub(crate) username: String,
    pub(crate) password: SecretString,
    pub(crate) session_token: String,
    pub(crate) csrf_token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) audit_client_ip: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PasswordLoginOutcome {
    Created { admin_id: i64, username: String },
    InvalidCredentials,
}

pub(crate) struct TotpLoginCommand {
    pub(crate) username: String,
    pub(crate) admin_id: i64,
    pub(crate) current_session_token: String,
    pub(crate) code: SecretString,
    pub(crate) rotated_session_token: String,
    pub(crate) rotated_csrf_token: String,
    pub(crate) audit_client_ip: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TotpLoginOutcome {
    Created,
    InvalidCode,
    ReplayedOrStale,
}

#[derive(Clone)]
pub(crate) struct AuthService {
    database: Database,
}

impl AuthService {
    pub(crate) fn new(database: Database) -> Self {
        Self { database }
    }

    /// Verifies the password and creates the audited pre-MFA session as one
    /// domain operation. The DB method rechecks the password hash in its
    /// transaction so a concurrent password reset cannot mint a stale session.
    pub(crate) fn login_with_password(
        &self,
        command: PasswordLoginCommand,
    ) -> rusqlite::Result<PasswordLoginOutcome> {
        if !auth::valid_admin_username(&command.username)
            || command.password.expose_secret().len() > auth::MAX_PASSWORD_BYTES
        {
            return Ok(PasswordLoginOutcome::InvalidCredentials);
        }

        let Some(admin) = self.database.admin(&command.username)? else {
            // Keep unknown accounts on one admitted Argon2 job too. The caller
            // runs this whole service operation behind the shared admission
            // semaphore, so overload behavior stays identical for both paths.
            let _ = auth::hash_secret_password(&command.password);
            return Ok(PasswordLoginOutcome::InvalidCredentials);
        };
        let expected_password_hash = admin.password_hash.clone();
        if !auth::verify_secret_password(&admin.password_hash, &command.password) {
            return Ok(PasswordLoginOutcome::InvalidCredentials);
        }

        let context = AuditContext::new(admin.username.clone(), command.audit_client_ip);
        let outcome = self
            .database
            .create_session_for_verified_password_and_audit(
                &command.session_token,
                admin.id,
                &expected_password_hash,
                &command.csrf_token,
                command.expires_at,
                &context,
            )?;
        if outcome == PasswordSessionCreationOutcome::Created {
            Ok(PasswordLoginOutcome::Created {
                admin_id: admin.id,
                username: admin.username,
            })
        } else {
            Ok(PasswordLoginOutcome::InvalidCredentials)
        }
    }

    /// Validates TOTP and rotates the session through the replay-safe audited
    /// DB operation. No HTTP status, cookie, redirect, or JSON type enters the
    /// service boundary.
    pub(crate) fn login_with_totp(
        &self,
        command: TotpLoginCommand,
    ) -> rusqlite::Result<TotpLoginOutcome> {
        let Some(admin) = self.database.admin(&command.username)? else {
            return Ok(TotpLoginOutcome::InvalidCode);
        };
        if admin.id != command.admin_id {
            return Ok(TotpLoginOutcome::InvalidCode);
        }
        if !admin.totp_enabled {
            return Ok(TotpLoginOutcome::InvalidCode);
        }
        let Some(step) = auth::matching_totp_step_now(
            admin.totp_secret.expose_secret(),
            command.code.expose_secret(),
        ) else {
            return Ok(TotpLoginOutcome::InvalidCode);
        };

        let context = AuditContext::new(command.username, command.audit_client_ip);
        let accepted = self.database.verify_mfa_with_totp_step_and_audit(
            &command.current_session_token,
            &command.rotated_session_token,
            &command.rotated_csrf_token,
            command.admin_id,
            step,
            &context,
        )?;
        Ok(if accepted {
            TotpLoginOutcome::Created
        } else {
            TotpLoginOutcome::ReplayedOrStale
        })
    }

    pub(crate) fn logout(
        &self,
        session_token: &str,
        actor: String,
        audit_client_ip: Option<String>,
    ) -> rusqlite::Result<()> {
        self.database
            .delete_session_and_audit(session_token, &AuditContext::new(actor, audit_client_ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn service() -> (AuthService, String) {
        let database = Database::open(":memory:").unwrap();
        let password = "correct horse battery staple";
        let hash = auth::hash_password(password).unwrap();
        database
            .create_admin("admin", &hash, "JBSWY3DPEHPK3PXP")
            .unwrap();
        (AuthService::new(database), password.into())
    }

    #[test]
    fn password_login_creates_session_and_required_audit() {
        let (service, password) = service();
        let outcome = service
            .login_with_password(PasswordLoginCommand {
                username: "admin".into(),
                password: SecretString::from(password),
                session_token: "session".into(),
                csrf_token: "csrf".into(),
                expires_at: Utc::now() + Duration::hours(1),
                audit_client_ip: Some("192.0.2.1".into()),
            })
            .unwrap();
        assert_eq!(
            outcome,
            PasswordLoginOutcome::Created {
                admin_id: 1,
                username: "admin".into()
            }
        );
        assert!(service.database.session("session").unwrap().is_some());
        let events = service.database.list_audit(None, 10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "password_verified");
    }

    #[test]
    fn invalid_password_has_no_mutation_or_required_audit() {
        let (service, _) = service();
        let outcome = service
            .login_with_password(PasswordLoginCommand {
                username: "admin".into(),
                password: SecretString::from("definitely incorrect"),
                session_token: "session".into(),
                csrf_token: "csrf".into(),
                expires_at: Utc::now() + Duration::hours(1),
                audit_client_ip: None,
            })
            .unwrap();
        assert_eq!(outcome, PasswordLoginOutcome::InvalidCredentials);
        assert!(service.database.session("session").unwrap().is_none());
        assert_eq!(service.database.count_audit(None).unwrap(), 0);
    }
}
