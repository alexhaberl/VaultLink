use std::sync::{Arc, RwLock, RwLockWriteGuard};

use crate::{
    config::Config,
    db::Database,
    internal_reporting::{
        report_internal, report_invariant, InternalOperation, ReportedInternalError,
    },
    runtime::RuntimeSettings,
    webauthn::WebAuthnService,
};

pub(super) struct RuntimeSnapshots {
    runtime: Arc<RwLock<RuntimeSettings>>,
    webauthn: Arc<RwLock<WebAuthnService>>,
    security_settings_mutation: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
pub(crate) struct RuntimePublicationHandles {
    runtime: Arc<RwLock<RuntimeSettings>>,
    webauthn: Arc<RwLock<WebAuthnService>>,
}

pub(crate) struct RuntimePublicationGuards<'a> {
    runtime: RwLockWriteGuard<'a, RuntimeSettings>,
    webauthn: Option<RwLockWriteGuard<'a, WebAuthnService>>,
}

impl RuntimeSnapshots {
    pub(super) fn new(runtime: RuntimeSettings, webauthn: WebAuthnService) -> Self {
        Self {
            runtime: Arc::new(RwLock::new(runtime)),
            webauthn: Arc::new(RwLock::new(webauthn)),
            security_settings_mutation: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub(super) fn settings_snapshot(
        &self,
        config: &Config,
        database: &Database,
    ) -> RuntimeSettings {
        match self.runtime.read() {
            Ok(settings) => settings.clone(),
            Err(poisoned) => {
                let _reported = report_invariant(
                    InternalOperation::HttpAuthRuntimeSettingsSnapshotPoisonRecovery,
                );
                let settings = poisoned.into_inner();
                if settings.validate_for_config(config).is_ok() {
                    let recovered = settings.clone();
                    self.runtime.clear_poison();
                    return recovered;
                }
                drop(settings);

                let mut settings = match self.runtime.write() {
                    Ok(settings) => return settings.clone(),
                    Err(poisoned) => poisoned.into_inner(),
                };
                if settings.validate_for_config(config).is_err() {
                    let replacement = match database.runtime_settings() {
                        Ok(persisted) => {
                            match crate::runtime_settings_from_persisted(config, &persisted) {
                                Ok(replacement) => replacement,
                                Err(error) => {
                                    let _reported = report_internal(
                                        InternalOperation::
                                            HttpAuthRuntimeSettingsPersistedValidation,
                                        error,
                                    );
                                    RuntimeSettings::from_config(config)
                                }
                            }
                        }
                        Err(error) => {
                            let _reported = report_internal(
                                InternalOperation::HttpAuthRuntimeSettingsReload,
                                error,
                            );
                            RuntimeSettings::from_config(config)
                        }
                    };
                    *settings = replacement;
                }
                let recovered = settings.clone();
                self.runtime.clear_poison();
                recovered
            }
        }
    }

    pub(super) fn webauthn_snapshot(
        &self,
        config: &Config,
        database: &Database,
    ) -> Result<WebAuthnService, ReportedInternalError> {
        match self.webauthn.read() {
            Ok(service) => Ok(service.clone()),
            Err(poisoned) => {
                let _reported =
                    report_invariant(InternalOperation::HttpAuthWebauthnSnapshotPoisonRecovery);
                drop(poisoned.into_inner());
                let public_base_url = self.settings_snapshot(config, database).public_base_url;
                let replacement =
                    WebAuthnService::from_public_base_url(&public_base_url).map_err(|error| {
                        report_internal(InternalOperation::HttpAuthWebauthnRecovery, error)
                    })?;
                let mut service = match self.webauthn.write() {
                    Ok(service) => return Ok(service.clone()),
                    Err(poisoned) => poisoned.into_inner(),
                };
                *service = replacement;
                let recovered = service.clone();
                self.webauthn.clear_poison();
                Ok(recovered)
            }
        }
    }

    pub(super) async fn acquire_security_settings_mutation(
        &self,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.security_settings_mutation.clone().lock_owned().await
    }

    pub(super) fn publication_handles(&self) -> RuntimePublicationHandles {
        RuntimePublicationHandles {
            runtime: self.runtime.clone(),
            webauthn: self.webauthn.clone(),
        }
    }

    #[cfg(test)]
    pub(super) fn mutate_settings(&self, mutate: impl FnOnce(&mut RuntimeSettings)) {
        let mut settings = self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mutate(&mut settings);
    }

    #[cfg(test)]
    pub(super) fn webauthn_snapshot_for_test(&self) -> WebAuthnService {
        self.webauthn
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[cfg(test)]
    pub(super) fn poison_runtime(&self) {
        let runtime = self.runtime.clone();
        assert!(std::thread::spawn(move || {
            let mut guard = runtime.write().unwrap();
            guard.max_upload_size = 0;
            panic!("poison runtime snapshot for test");
        })
        .join()
        .is_err());
    }

    #[cfg(test)]
    pub(super) fn poison_webauthn(&self) {
        let webauthn = self.webauthn.clone();
        assert!(std::thread::spawn(move || {
            let _guard = webauthn.write().unwrap();
            panic!("poison WebAuthn snapshot for test");
        })
        .join()
        .is_err());
    }

    #[cfg(test)]
    pub(super) fn runtime_is_poisoned(&self) -> bool {
        self.runtime.is_poisoned()
    }

    #[cfg(test)]
    pub(super) fn webauthn_is_poisoned(&self) -> bool {
        self.webauthn.is_poisoned()
    }
}

impl RuntimePublicationHandles {
    pub(crate) fn acquire(&self, include_webauthn: bool) -> RuntimePublicationGuards<'_> {
        let runtime = self.runtime.write().unwrap_or_else(|poisoned| {
            crate::internal_reporting::report_invariant(
                crate::internal_reporting::InternalOperation::
                    HttpAuthRuntimeSettingsWritePoisonRecovery,
            );
            poisoned.into_inner()
        });
        let webauthn = include_webauthn.then(|| {
            self.webauthn.write().unwrap_or_else(|poisoned| {
                crate::internal_reporting::report_invariant(
                    crate::internal_reporting::InternalOperation::HttpAuthWebauthnWritePoisonRecovery,
                );
                poisoned.into_inner()
            })
        });
        RuntimePublicationGuards { runtime, webauthn }
    }

    pub(crate) fn clear_poison(&self, include_webauthn: bool) {
        self.runtime.clear_poison();
        if include_webauthn {
            self.webauthn.clear_poison();
        }
    }
}

impl<'a> RuntimePublicationGuards<'a> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        RwLockWriteGuard<'a, RuntimeSettings>,
        Option<RwLockWriteGuard<'a, WebAuthnService>>,
    ) {
        (self.runtime, self.webauthn)
    }
}
