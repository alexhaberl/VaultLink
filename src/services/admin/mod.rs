use crate::{
    auth,
    db::{
        AdminDeactivationOutcome, AdminSummary, AuditContext, Audited, Database,
        MfaMutationContext, SessionBound,
    },
    sensitive::SecretString,
    services::error::ServiceError,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AdminValidationError {
    InvalidUsername,
    InvalidPassword,
    PasswordConfirmationMismatch,
}

pub(crate) type AdminServiceError = ServiceError<AdminValidationError>;

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
            return Err(AdminServiceError::Validation(
                AdminValidationError::InvalidUsername,
            ));
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
        authorization: MfaMutationContext,
        prepared: &PreparedAdminCreate,
        password_hash: &str,
        context: &AuditContext,
        publish_active_admins: impl FnOnce(Vec<String>) -> T,
    ) -> Result<SessionBound<Audited<(CreatedAdmin, T)>>, AdminServiceError>
    where
        T: crate::db::CommitPublication,
    {
        let (_, proof) = authorization.into_parts();
        let secret = auth::new_totp_secret_value();
        let response_secret = secret.duplicate_for_one_time_response();
        self.database
            .create_admin_and_audit_for_session(
                &proof,
                &prepared.username,
                password_hash,
                secret.expose_secret(),
                context,
                publish_active_admins,
            )
            .map(|outcome| {
                outcome.map(|audited| {
                    audited.map(|(summary, publication)| {
                        (
                            CreatedAdmin {
                                summary,
                                totp_secret: response_secret,
                            },
                            publication,
                        )
                    })
                })
            })
            .map_err(|error| AdminServiceError::from_database_with_conflict(error, ()))
    }

    pub(crate) fn set_active_for_mfa_session<T>(
        &self,
        authorization: MfaMutationContext,
        id: i64,
        active: bool,
        context: &AuditContext,
        publish_active_admins: impl FnOnce(Vec<String>) -> T,
    ) -> Result<SessionBound<Audited<(AdminActivationResult, T)>>, AdminServiceError>
    where
        T: crate::db::CommitPublication,
    {
        let (_, proof) = authorization.into_parts();
        let outcome = if active {
            self.database
                .activate_admin_and_audit_for_session(&proof, id, context, publish_active_admins)
                .map(|outcome| {
                    outcome.map(|audited| {
                        audited.map(|(changed, publication)| {
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
                })
        } else {
            self.database
                .deactivate_admin_and_audit_for_session(&proof, id, context, publish_active_admins)
                .map(|outcome| {
                    outcome.map(|audited| {
                        audited.map(|(outcome, publication)| {
                            (AdminActivationResult::Deactivation(outcome), publication)
                        })
                    })
                })
        };
        outcome.map_err(AdminServiceError::from_database)
    }

    pub(crate) fn reset_password_for_mfa_session(
        &self,
        authorization: MfaMutationContext,
        id: i64,
        password_hash: &str,
        context: &AuditContext,
    ) -> Result<SessionBound<Audited<bool>>, AdminServiceError> {
        let (_, proof) = authorization.into_parts();
        self.database
            .reset_admin_password_and_audit_for_session(&proof, id, password_hash, context)
            .map_err(AdminServiceError::from_database)
    }

    pub(crate) fn reset_totp_for_mfa_session(
        &self,
        authorization: MfaMutationContext,
        id: i64,
        context: &AuditContext,
    ) -> Result<SessionBound<Audited<Option<ResetTotpResult>>>, AdminServiceError> {
        let (_, proof) = authorization.into_parts();
        let secret = auth::new_totp_secret_value();
        let response_secret = secret.duplicate_for_one_time_response();
        self.database
            .reset_admin_totp_and_audit_for_session(&proof, id, secret.expose_secret(), context)
            .map(|outcome| {
                outcome.map(|audited| {
                    audited.map(|username| {
                        username.map(|username| ResetTotpResult {
                            username,
                            totp_secret: response_secret,
                        })
                    })
                })
            })
            .map_err(AdminServiceError::from_database)
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
            return Err(AdminServiceError::Validation(
                AdminValidationError::PasswordConfirmationMismatch,
            ));
        }
    }
    if !auth::valid_admin_password(password.expose_secret()) {
        return Err(AdminServiceError::Validation(
            AdminValidationError::InvalidPassword,
        ));
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
            Err(AdminServiceError::Validation(
                AdminValidationError::InvalidUsername
            ))
        ));
        assert!(matches!(
            service.prepare_password(
                SecretString::from("correct horse battery staple"),
                Some(SecretString::from("different horse battery staple")),
            ),
            Err(AdminServiceError::Validation(
                AdminValidationError::PasswordConfirmationMismatch
            ))
        ));
    }
}
