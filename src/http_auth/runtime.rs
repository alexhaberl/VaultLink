/// Persists a non-transactional observation. Successful security mutations
/// must use a required audit transaction instead.
pub(crate) async fn audit_observation(
    state: &(impl Borrow<AppState> + ?Sized),
    actor: String,
    action: AuditAction,
    object: Option<String>,
    detail: Option<String>,
) {
    let state = borrowed_app_state(state);
    let client_ip = enabled_audit_client_ip(state);
    let _result = database(state.db().clone(), move |db| {
        db.audit_action_with_client_ip(
            action,
            &actor,
            object.as_deref(),
            detail.as_deref(),
            client_ip.as_deref(),
        )
    })
    .await;
    // Every database failure class is reported at its source: admission and
    // SQLite capacity have their operational warnings, while joins and
    // unexpected failures use the central internal-error channel. Logging the
    // mapped HttpAuthError here would duplicate the same failure event.
}

pub fn runtime_settings(state: &(impl Borrow<AppState> + ?Sized)) -> RuntimeSettings {
    borrowed_app_state(state).runtime_settings_snapshot()
}

pub fn webauthn_service(
    state: &(impl Borrow<AppState> + ?Sized),
) -> Result<crate::webauthn::WebAuthnService> {
    borrowed_app_state(state)
        .webauthn_snapshot()
        .map_err(HttpAuthError::from)
}

/// Keeps the previous in-memory settings snapshots available until SQLite's
/// required-audit transaction has committed. If audit insertion or COMMIT
/// fails, `Drop` restores both snapshots before the transaction releases its
/// writer fence, so a waiting revocation can never observe a later publication.
struct RuntimeSettingsPublication<'a> {
    runtime: RwLockWriteGuard<'a, RuntimeSettings>,
    previous_runtime: Option<RuntimeSettings>,
    webauthn: Option<RwLockWriteGuard<'a, crate::webauthn::WebAuthnService>>,
    previous_webauthn: Option<crate::webauthn::WebAuthnService>,
}

impl<'a> RuntimeSettingsPublication<'a> {
    fn publish(
        mut runtime: RwLockWriteGuard<'a, RuntimeSettings>,
        next: RuntimeSettings,
        mut webauthn: Option<RwLockWriteGuard<'a, crate::webauthn::WebAuthnService>>,
        replacement_webauthn: Option<crate::webauthn::WebAuthnService>,
    ) -> Self {
        let previous_runtime = Some(std::mem::replace(&mut *runtime, next));
        let previous_webauthn = match (webauthn.as_mut(), replacement_webauthn) {
            (Some(current), Some(replacement)) => {
                Some(std::mem::replace(&mut **current, replacement))
            }
            (None, None) => None,
            _ => unreachable!("WebAuthn snapshot lock and replacement must agree"),
        };
        Self {
            runtime,
            previous_runtime,
            webauthn,
            previous_webauthn,
        }
    }
}

impl crate::db::CommitPublication for RuntimeSettingsPublication<'_> {
    fn accept_commit(&mut self) {
        self.previous_runtime = None;
        self.previous_webauthn = None;
    }
}

impl Drop for RuntimeSettingsPublication<'_> {
    fn drop(&mut self) {
        if let (Some(current), Some(previous)) =
            (self.webauthn.as_mut(), self.previous_webauthn.take())
        {
            **current = previous;
        }
        if let Some(previous) = self.previous_runtime.take() {
            *self.runtime = previous;
        }
    }
}

pub(crate) async fn commit_runtime_settings(
    state: &(impl Borrow<AppState> + ?Sized),
    authorization: MfaMutationContext,
    next: RuntimeSettings,
    audit_actor: String,
    audit_detail: String,
) -> Result<SessionBound<crate::db::Audited<()>>> {
    let state = borrowed_app_state(state);
    let (_, proof) = authorization.into_parts();
    let security_settings_guard = state.acquire_security_settings_mutation().await;
    next.validate_for_config(state.config())
        .map_err(|_| HttpAuthError::status(StatusCode::BAD_REQUEST, "Invalid setting"))?;
    let public_url_changed = runtime_settings(state).public_base_url != next.public_base_url;
    let replacement_webauthn = if public_url_changed {
        Some(
            crate::webauthn::WebAuthnService::from_public_base_url(&next.public_base_url).map_err(
                |_| {
                    HttpAuthError::status(StatusCode::BAD_REQUEST, "Invalid WebAuthn configuration")
                },
            )?,
        )
    } else {
        None
    };
    if public_url_changed {
        let credential_count = database(state.db().clone(), |database| {
            database.webauthn_credential_count()
        })
        .await?;
        if credential_count > 0 {
            return Err(HttpAuthError::status(
                StatusCode::CONFLICT,
                "Public base URL cannot be changed while security keys are registered",
            ));
        }
    }
    let runtime_snapshots = state.runtime_publication_handles();
    let replace_webauthn = replacement_webauthn.is_some();
    #[cfg(test)]
    let test_state = state.clone();
    // Match the previous post-commit audit semantics: an update that enables
    // client-IP auditing may record this request, while a disabling update may
    // not. The database still re-checks the persisted setting at insert time.
    let audit_client_ip = next
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string());
    let audit_context = AuditContext::new(audit_actor, audit_client_ip);
    run_database_operation(
        state.db().clone(),
        "required_audit",
        InternalOperation::HttpAuthDatabaseRequiredAuditJoin,
        move |database| {
            // A cancelled request drops only the JoinHandle; the blocking database
            // operation keeps this owned guard until the runtime/WebAuthn snapshot
            // and SQLite commit have advanced together.
            let _security_settings_guard = security_settings_guard;
            // Settings commits always acquire locks in Runtime -> WebAuthn -> Database
            // order. The publication guard rolls both snapshots back on any required-
            // audit or COMMIT failure before SQLite admits a waiting revocation.
            let (current, current_webauthn) = runtime_snapshots
                .acquire(replacement_webauthn.is_some())
                .into_parts();
            let pairs = next.pairs();
            let outcome = database.replace_runtime_settings_for_mfa_session(
                &proof,
                &pairs,
                &audit_context,
                audit_detail,
                || {
                    #[cfg(test)]
                    test_state.wait_at_settings_publication_barrier_for_test();
                    RuntimeSettingsPublication::publish(
                        current,
                        next,
                        current_webauthn,
                        replacement_webauthn,
                    )
                },
            )?;
            match outcome {
                SessionBound::Authorized(audited) => {
                    Ok(SessionBound::Authorized(audited.map(|publication| {
                        runtime_snapshots.clear_poison(replace_webauthn);
                        drop(publication);
                    })))
                }
                SessionBound::SessionUnavailable => Ok(SessionBound::SessionUnavailable),
            }
        },
    )
    .await
}
