use thiserror::Error;

use crate::{
    auth,
    db::{
        AdminDeactivationOutcome, AdminSummary, AuditContext, Database, MfaSessionProof,
        SessionBound,
    },
    sensitive::SecretString,
};

pub(crate) struct CreateAdminCommand {
    pub(crate) username: String,
    pub(crate) password: SecretString,
    pub(crate) confirmation: Option<SecretString>,
}

pub(crate) struct PreparedAdminCreate {
    username: String,
}

pub(crate) struct ValidatedAdminCreate {
    prepared: PreparedAdminCreate,
    password: SecretString,
}

impl ValidatedAdminCreate {
    pub(crate) fn into_hash_input(self) -> (PreparedAdminCreate, SecretString) {
        (self.prepared, self.password)
    }
}

pub(crate) struct CreatedAdmin {
    pub(crate) summary: AdminSummary,
    pub(crate) totp_secret: SecretString,
}

pub(crate) struct ResetTotpResult {
    pub(crate) username: String,
    pub(crate) totp_secret: SecretString,
}

#[derive(Debug, Error)]
pub(crate) enum AdminServiceError {
    #[error("invalid administrator username")]
    InvalidUsername,
    #[error("invalid administrator password")]
    InvalidPassword,
    #[error("password confirmation does not match")]
    PasswordConfirmationMismatch,
    #[error("administrator database operation failed")]
    Database(#[source] rusqlite::Error),
}

impl AdminServiceError {
    pub(crate) fn into_database_error(self) -> Option<rusqlite::Error> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct AdminService {
    database: Database,
}

impl AdminService {
    pub(crate) fn new(database: Database) -> Self {
        Self { database }
    }

    pub(crate) fn prepare_create(
        &self,
        command: CreateAdminCommand,
    ) -> Result<ValidatedAdminCreate, AdminServiceError> {
        if !auth::valid_admin_username(&command.username) {
            return Err(AdminServiceError::InvalidUsername);
        }
        let password = validate_password(command.password, command.confirmation)?;
        Ok(ValidatedAdminCreate {
            prepared: PreparedAdminCreate {
                username: command.username,
            },
            password,
        })
    }

    pub(crate) fn prepare_password(
        &self,
        password: SecretString,
        confirmation: Option<SecretString>,
    ) -> Result<SecretString, AdminServiceError> {
        validate_password(password, confirmation)
    }

    pub(crate) fn create_for_mfa_session<T>(
        &self,
        proof: &MfaSessionProof,
        prepared: &PreparedAdminCreate,
        password_hash: &str,
        context: &AuditContext,
        publish_active_admins: impl FnOnce(Vec<String>) -> T,
    ) -> Result<SessionBound<(CreatedAdmin, T)>, AdminServiceError>
    where
        T: crate::db::CommitPublication,
    {
        let secret = auth::new_totp_secret_value();
        let response_secret = secret.duplicate_for_one_time_response();
        self.database
            .create_admin_and_audit_for_session(
                proof,
                &prepared.username,
                password_hash,
                secret.expose_secret(),
                context,
                publish_active_admins,
            )
            .map(|outcome| {
                outcome.map(|(summary, publication)| {
                    (
                        CreatedAdmin {
                            summary,
                            totp_secret: response_secret,
                        },
                        publication,
                    )
                })
            })
            .map_err(AdminServiceError::Database)
    }

    pub(crate) fn set_active_for_mfa_session<T>(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        active: bool,
        context: &AuditContext,
        publish_active_admins: impl FnOnce(Vec<String>) -> T,
    ) -> Result<SessionBound<(AdminActivationResult, T)>, AdminServiceError>
    where
        T: crate::db::CommitPublication,
    {
        let outcome = if active {
            self.database
                .activate_admin_and_audit_for_session(proof, id, context, publish_active_admins)
                .map(|outcome| {
                    outcome.map(|(changed, publication)| {
                        (
                            if changed {
                                AdminActivationResult::Changed
                            } else {
                                AdminActivationResult::NotFound
                            },
                            publication,
                        )
                    })
                })
        } else {
            self.database
                .deactivate_admin_and_audit_for_session(proof, id, context, publish_active_admins)
                .map(|outcome| {
                    outcome.map(|(outcome, publication)| {
                        (AdminActivationResult::Deactivation(outcome), publication)
                    })
                })
        };
        outcome.map_err(AdminServiceError::Database)
    }

    pub(crate) fn reset_password_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        password_hash: &str,
        context: &AuditContext,
    ) -> Result<SessionBound<bool>, AdminServiceError> {
        self.database
            .reset_admin_password_and_audit_for_session(proof, id, password_hash, context)
            .map_err(AdminServiceError::Database)
    }

    pub(crate) fn reset_totp_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        context: &AuditContext,
    ) -> Result<SessionBound<Option<ResetTotpResult>>, AdminServiceError> {
        let secret = auth::new_totp_secret_value();
        let response_secret = secret.duplicate_for_one_time_response();
        self.database
            .reset_admin_totp_and_audit_for_session(proof, id, secret.expose_secret(), context)
            .map(|outcome| {
                outcome.map(|username| {
                    username.map(|username| ResetTotpResult {
                        username,
                        totp_secret: response_secret,
                    })
                })
            })
            .map_err(AdminServiceError::Database)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdminActivationResult {
    Changed,
    NotFound,
    Deactivation(AdminDeactivationOutcome),
}

fn validate_password(
    password: SecretString,
    confirmation: Option<SecretString>,
) -> Result<SecretString, AdminServiceError> {
    if let Some(confirmation) = confirmation {
        if !password.matches_confirmation(&confirmation) {
            return Err(AdminServiceError::PasswordConfirmationMismatch);
        }
    }
    if !auth::valid_admin_password(password.expose_secret()) {
        return Err(AdminServiceError::InvalidPassword);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_is_shared_for_json_and_confirmation_forms() {
        let service = AdminService::new(Database::open(":memory:").unwrap());
        assert!(matches!(
            service.prepare_create(CreateAdminCommand {
                username: "not valid".into(),
                password: SecretString::from("correct horse battery staple"),
                confirmation: None,
            }),
            Err(AdminServiceError::InvalidUsername)
        ));
        assert!(matches!(
            service.prepare_password(
                SecretString::from("correct horse battery staple"),
                Some(SecretString::from("different horse battery staple")),
            ),
            Err(AdminServiceError::PasswordConfirmationMismatch)
        ));
    }
}
