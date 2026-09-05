mod admissions;
mod probes;
mod routes;
mod runtime;
mod services;
mod storage;

use std::{net::IpAddr, sync::Arc};

use admissions::Admissions;
pub(crate) use admissions::{
    try_acquire_client_activity, try_acquire_share_activity, ClientActivityPermit,
    ShareActivityPermit,
};
use probes::Probes;
pub(crate) use probes::ReadinessState;
pub(crate) use routes::{
    AccountRouteState, AdminRouteState, AdmissionRouteState, AuthRouteState, FileRouteState,
    MonitoringRouteState, PublicRouteState, PublicTransferRouteState, PublicUploadRouteState,
    RenderingRouteState, ServiceTokenRouteState, SettingsRouteState, ShareRouteState,
};
pub(crate) use runtime::RuntimePublicationHandles;
use runtime::RuntimeSnapshots;
use services::AppServices;
use storage::StorageContext;

use crate::{
    auth::{AdminLoginLimiter, LoginLimiter},
    config::Config,
    db::Database,
    directory_cache::DirectorySnapshotCache,
    disk_stats::DiskStatsCache,
    monitoring_cache::MonitoringSummaryCache,
    readiness::ReadinessProbe,
    runtime::RuntimeSettings,
    secure_fs::SecureRoot,
    storage_authority::{StorageMutationGuard, StorageReadGuard},
    storage_cleanup::{StorageCleanupCoordinator, StorageCleanupStartError, StorageCleanupWorker},
    webauthn::WebAuthnService,
};

#[derive(Clone)]
pub struct AppState(Arc<StateInner>);

struct StateInner {
    services: AppServices,
    storage: StorageContext,
    runtime: RuntimeSnapshots,
    admissions: Admissions,
    probes: Probes,
    #[cfg(test)]
    test_hooks: TestHooks,
}

#[cfg(test)]
struct TestHooks {
    upload_directory_sync_failure: std::sync::Mutex<Option<std::io::ErrorKind>>,
    settings_publication_barrier: std::sync::Mutex<Option<crate::BlockingTestBarrier>>,
    upload_directory_creation_barrier: std::sync::Mutex<Option<crate::BlockingTestBarrier>>,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        if !config.storage.require_mount {
            std::fs::create_dir_all(&config.storage.data_directory)?;
        }
        let validated_storage = crate::storage_mount::validate_and_open(&config.storage)?;
        validated_storage.verify_path_bindings(&config.storage)?;
        let storage_instance_lock = Arc::new(crate::acquire_storage_instance_lock(
            &config.storage,
            &validated_storage,
        )?);
        validated_storage.verify_path_bindings(&config.storage)?;
        let secure_root = SecureRoot::open_configured_with_locked_internal(
            &config.storage.root_mount_path,
            config.storage.internal_directory.as_deref(),
            config.storage.require_mount,
            config.storage.forbid_user_symlinks(),
            config.storage.replacements_allowed(),
            storage_instance_lock.clone(),
        )
        .map_err(|error| {
            format!(
                "cannot initialize secure storage access (openat2 is required on Linux): {error}"
            )
        })?;
        validated_storage.verify_path_bindings(&config.storage)?;
        let database = Database::open_in_directory(validated_storage.data_file()?)?;
        database.configure_session_idle_timeout(config.security.session_idle_minutes);
        let persisted_runtime = database.runtime_settings()?;
        let runtime = crate::runtime_settings_from_persisted(&config, &persisted_runtime)
            .map_err(|error| format!("invalid persisted runtime settings: {error}"))?;
        let webauthn = WebAuthnService::from_public_base_url(&runtime.public_base_url)
            .map_err(|error| format!("invalid WebAuthn configuration: {error}"))?;
        let admissions = Admissions::new(&config.admission);
        Ok(Self(Arc::new(StateInner {
            services: AppServices::new(config, database),
            storage: StorageContext::new(secure_root, storage_instance_lock),
            runtime: RuntimeSnapshots::new(runtime, webauthn),
            admissions,
            probes: Probes::new(),
            #[cfg(test)]
            test_hooks: TestHooks {
                upload_directory_sync_failure: std::sync::Mutex::new(None),
                settings_publication_barrier: std::sync::Mutex::new(None),
                upload_directory_creation_barrier: std::sync::Mutex::new(None),
            },
        })))
    }

    pub(crate) fn config(&self) -> &Config {
        self.0.services.config()
    }

    pub(crate) fn db(&self) -> &Database {
        self.0.services.database()
    }

    /// Returns the shared database service for binary-level workers.
    pub fn database(&self) -> Database {
        self.db().clone()
    }

    pub(crate) fn secure_root(&self) -> &SecureRoot {
        self.0.storage.secure_root()
    }

    pub(crate) fn admin_login_limiter(&self) -> &AdminLoginLimiter {
        self.0.services.admin_login_limiter()
    }

    pub(crate) fn login_limiter(&self) -> &LoginLimiter {
        self.0.services.login_limiter()
    }

    pub(crate) fn share_limiter(&self) -> &LoginLimiter {
        self.0.services.share_limiter()
    }

    pub(crate) fn alias_limiter(&self) -> &LoginLimiter {
        self.0.services.alias_limiter()
    }

    pub(crate) fn public_transfer_limiter(&self) -> &LoginLimiter {
        self.0.services.public_transfer_limiter()
    }

    pub(crate) fn preview_token_limiter(&self) -> &LoginLimiter {
        self.0.services.preview_token_limiter()
    }

    pub(crate) fn monitoring_limiter(&self) -> &LoginLimiter {
        self.0.services.monitoring_limiter()
    }

    pub(crate) fn runtime_settings_snapshot(&self) -> RuntimeSettings {
        self.0.runtime.settings_snapshot(self.config(), self.db())
    }

    pub(crate) fn webauthn_snapshot(
        &self,
    ) -> Result<WebAuthnService, crate::internal_reporting::ReportedInternalError> {
        self.0.runtime.webauthn_snapshot(self.config(), self.db())
    }

    pub(crate) async fn acquire_security_settings_mutation(
        &self,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.0.runtime.acquire_security_settings_mutation().await
    }

    pub(crate) fn runtime_publication_handles(&self) -> RuntimePublicationHandles {
        self.0.runtime.publication_handles()
    }

    pub(crate) async fn acquire_storage_read(&self) -> StorageReadGuard {
        self.0.storage.acquire_read().await
    }

    pub(crate) async fn acquire_storage_mutation(&self) -> StorageMutationGuard {
        self.0.storage.acquire_mutation().await
    }

    pub(crate) async fn acquire_storage_recovery(&self) -> StorageMutationGuard {
        self.0.storage.acquire_recovery().await
    }

    pub(crate) fn storage_recovery_required(&self) -> bool {
        self.0.storage.recovery_required()
    }

    pub(crate) fn storage_cleanup(&self) -> &StorageCleanupCoordinator {
        self.0.storage.cleanup()
    }

    /// Returns the cleanup control handle used by the process shutdown path.
    pub fn storage_cleanup_coordinator(&self) -> StorageCleanupCoordinator {
        self.storage_cleanup().clone()
    }

    #[doc(hidden)]
    pub fn start_storage_cleanup_worker(
        &self,
    ) -> Result<StorageCleanupWorker, StorageCleanupStartError> {
        self.0.storage.start_cleanup_worker(self.clone())
    }

    pub(crate) fn disk_stats_cache(&self) -> &DiskStatsCache {
        self.0.storage.disk_stats_cache()
    }

    pub(crate) fn directory_snapshot_cache(&self) -> &DirectorySnapshotCache {
        self.0.storage.directory_snapshot_cache()
    }

    pub(crate) fn monitoring_summary_cache(&self) -> &MonitoringSummaryCache {
        self.0.probes.monitoring_summary_cache()
    }

    pub(crate) fn readiness_probe(&self) -> &ReadinessProbe {
        self.0.probes.readiness()
    }

    pub(crate) fn try_acquire_upload(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_upload()
    }

    pub(crate) fn try_acquire_public_upload(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_public_upload()
    }

    pub(crate) fn try_acquire_response(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_response()
    }

    pub(crate) fn try_acquire_stream(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_stream()
    }

    pub(crate) fn try_acquire_public_stream(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_public_stream()
    }

    pub(crate) fn try_acquire_buffered_response(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_buffered_response()
    }

    pub(crate) fn try_acquire_preview_render(
        &self,
        permits: u32,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_preview_render(permits)
    }

    pub(crate) fn try_acquire_zip_generation(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_zip_generation()
    }

    pub(crate) fn try_acquire_search(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_search()
    }

    pub(crate) fn try_acquire_argon2(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.admissions.try_argon2()
    }

    pub(crate) fn try_acquire_stream_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.0.admissions.try_stream_peer(peer)
    }

    pub(crate) fn try_acquire_upload_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.0.admissions.try_upload_peer(peer)
    }

    pub(crate) fn try_acquire_buffered_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.0.admissions.try_buffered_peer(peer)
    }

    pub(crate) fn try_acquire_expensive_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.0.admissions.try_expensive_peer(peer)
    }

    pub(crate) fn try_acquire_stream_share(&self, share_id: i64) -> Option<ShareActivityPermit> {
        self.0
            .admissions
            .try_stream_share(share_id, self.config().admission.max_streams_per_share)
    }

    pub(crate) fn try_acquire_upload_share(&self, share_id: i64) -> Option<ShareActivityPermit> {
        self.0
            .admissions
            .try_upload_share(share_id, self.config().admission.max_uploads_per_share)
    }
}

#[cfg(test)]
impl AppState {
    fn inner_mut_for_test(&mut self) -> &mut StateInner {
        Arc::get_mut(&mut self.0).expect("test state must be uniquely owned before replacement")
    }

    pub(crate) fn replace_config_for_test(&mut self, config: Config) {
        self.inner_mut_for_test().services.replace_config(config);
    }

    pub(crate) fn replace_login_limiter_for_test(&mut self, limiter: LoginLimiter) {
        self.inner_mut_for_test()
            .services
            .replace_login_limiter(limiter);
    }

    pub(crate) fn replace_monitoring_limiter_for_test(&mut self, limiter: LoginLimiter) {
        self.inner_mut_for_test()
            .services
            .replace_monitoring_limiter(limiter);
    }

    pub(crate) fn replace_disk_stats_cache_for_test(&mut self, cache: DiskStatsCache) {
        self.inner_mut_for_test()
            .storage
            .replace_disk_stats_cache(cache);
    }

    pub(crate) fn replace_readiness_for_test(&mut self, readiness: ReadinessProbe) {
        self.inner_mut_for_test()
            .probes
            .replace_readiness(readiness);
    }

    pub(crate) fn replace_upload_admission_for_test(
        &mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) {
        self.inner_mut_for_test()
            .admissions
            .replace_upload(admission);
    }

    pub(crate) fn replace_response_admission_for_test(
        &mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) {
        self.inner_mut_for_test()
            .admissions
            .replace_response(admission);
    }

    pub(crate) fn replace_stream_admission_for_test(
        &mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) {
        self.inner_mut_for_test()
            .admissions
            .replace_stream(admission);
    }

    pub(crate) fn replace_public_stream_admission_for_test(
        &mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) {
        self.inner_mut_for_test()
            .admissions
            .replace_public_stream(admission);
    }

    pub(crate) fn replace_zip_generation_admission_for_test(
        &mut self,
        admission: Arc<tokio::sync::Semaphore>,
    ) {
        self.inner_mut_for_test()
            .admissions
            .replace_zip_generation(admission);
    }

    pub(crate) fn upload_admission_available_for_test(&self) -> usize {
        self.0.admissions.upload_available()
    }

    pub(crate) fn zip_generation_admission_available_for_test(&self) -> usize {
        self.0.admissions.zip_generation_available()
    }

    pub(crate) fn upload_peer_admission_count_for_test(&self) -> usize {
        self.0.admissions.upload_peer_count()
    }

    pub(crate) fn stream_peer_admission_contains_for_test(&self, peer: IpAddr) -> bool {
        self.0.admissions.stream_peer_contains(peer)
    }

    pub(crate) fn expensive_peer_admission_count_for_test(&self) -> usize {
        self.0.admissions.expensive_peer_count()
    }

    pub(crate) async fn acquire_all_argon2_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.0.admissions.acquire_all_argon2().await
    }

    pub(crate) fn try_acquire_all_search_for_test(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.0.admissions.try_acquire_all_search()
    }

    pub(crate) fn try_acquire_all_zip_generation_for_test(
        &self,
    ) -> tokio::sync::OwnedSemaphorePermit {
        self.0.admissions.try_acquire_all_zip_generation()
    }

    pub(crate) async fn acquire_storage_test_exclusive(
        &self,
    ) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        self.0.storage.acquire_test_exclusive().await
    }

    pub(crate) fn try_acquire_storage_test_exclusive(
        &self,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, tokio::sync::TryLockError> {
        self.0.storage.try_acquire_test_exclusive()
    }

    pub(crate) async fn block_storage_mutations_for_test(
        &self,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.0.storage.block_mutations_for_test().await
    }

    pub(crate) fn mutate_runtime_for_test(&self, mutate: impl FnOnce(&mut RuntimeSettings)) {
        self.0.runtime.mutate_settings(mutate);
    }

    pub(crate) fn webauthn_snapshot_for_test(&self) -> WebAuthnService {
        self.0.runtime.webauthn_snapshot_for_test()
    }

    pub(crate) fn poison_runtime_for_test(&self) {
        self.0.runtime.poison_runtime();
    }

    pub(crate) fn poison_webauthn_for_test(&self) {
        self.0.runtime.poison_webauthn();
    }

    pub(crate) fn runtime_is_poisoned_for_test(&self) -> bool {
        self.0.runtime.runtime_is_poisoned()
    }

    pub(crate) fn webauthn_is_poisoned_for_test(&self) -> bool {
        self.0.runtime.webauthn_is_poisoned()
    }

    pub(crate) fn inject_upload_directory_sync_failure_for_test(
        &self,
        failure: std::io::ErrorKind,
    ) {
        *self
            .0
            .test_hooks
            .upload_directory_sync_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(failure);
    }

    pub(crate) fn take_upload_directory_sync_failure_for_test(&self) -> Option<std::io::ErrorKind> {
        self.0
            .test_hooks
            .upload_directory_sync_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    pub(crate) fn install_settings_publication_barrier_for_test(
        &self,
        barrier: crate::BlockingTestBarrier,
    ) {
        *self
            .0
            .test_hooks
            .settings_publication_barrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(barrier);
    }

    pub(crate) fn wait_at_settings_publication_barrier_for_test(&self) {
        let barrier = self
            .0
            .test_hooks
            .settings_publication_barrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((entered, release)) = barrier {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }

    pub(crate) fn install_upload_directory_creation_barrier_for_test(
        &self,
        barrier: crate::BlockingTestBarrier,
    ) {
        *self
            .0
            .test_hooks
            .upload_directory_creation_barrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(barrier);
    }

    pub(crate) fn wait_at_upload_directory_creation_barrier_for_test(&self) {
        let barrier = self
            .0
            .test_hooks
            .upload_directory_creation_barrier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((entered, release)) = barrier {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }
}
