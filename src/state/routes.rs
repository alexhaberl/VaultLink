use std::{borrow::Borrow, marker::PhantomData, net::IpAddr};

use axum::extract::FromRef;
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, TryAcquireError};

use super::ClientActivityPermit;
use crate::{
    auth::{AdminLoginLimiter, LoginLimiter},
    config::Config,
    db::Database,
    directory_cache::DirectorySnapshotCache,
    disk_stats::DiskStatsCache,
    monitoring_cache::MonitoringSummaryCache,
    secure_fs::SecureRoot,
    services::{file::FileService, public_transfer::PublicTransferService},
    AppState,
};

/// An Axum-facing view of application state.
///
/// The marker selects the capabilities visible to a handler. The wrapped
/// `AppState` deliberately has no public accessor and this type does not
/// implement `Deref`, so adding a dependency from one route domain to another
/// is a compile-time-visible change to the capability declarations below.
pub(crate) struct RouteState<Domain> {
    inner: AppState,
    domain: PhantomData<fn() -> Domain>,
}

impl<Domain> Clone for RouteState<Domain> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            domain: PhantomData,
        }
    }
}

impl<Domain> FromRef<AppState> for RouteState<Domain> {
    fn from_ref(state: &AppState) -> Self {
        Self {
            inner: state.clone(),
            domain: PhantomData,
        }
    }
}

/// Transport integration points such as authentication accept a borrowed
/// state view. Adapter modules are policy-checked to prevent calling
/// `Borrow::borrow` themselves; handlers use only the capabilities below.
impl<Domain> Borrow<AppState> for RouteState<Domain> {
    fn borrow(&self) -> &AppState {
        &self.inner
    }
}

pub(crate) enum AccountRoutes {}
pub(crate) enum AdminRoutes {}
pub(crate) enum AdmissionRoutes {}
pub(crate) enum AuthRoutes {}
pub(crate) enum FileRoutes {}
pub(crate) enum MonitoringRoutes {}
pub(crate) enum PublicRoutes {}
pub(crate) enum PublicTransferRoutes {}
pub(crate) enum PublicUploadRoutes {}
pub(crate) enum RenderingRoutes {}
pub(crate) enum ServiceTokenRoutes {}
pub(crate) enum SettingsRoutes {}
pub(crate) enum ShareRoutes {}

pub(crate) type AccountRouteState = RouteState<AccountRoutes>;
pub(crate) type AdminRouteState = RouteState<AdminRoutes>;
pub(crate) type AdmissionRouteState = RouteState<AdmissionRoutes>;
pub(crate) type AuthRouteState = RouteState<AuthRoutes>;
pub(crate) type FileRouteState = RouteState<FileRoutes>;
pub(crate) type MonitoringRouteState = RouteState<MonitoringRoutes>;
pub(crate) type PublicRouteState = RouteState<PublicRoutes>;
pub(crate) type PublicTransferRouteState = RouteState<PublicTransferRoutes>;
pub(crate) type PublicUploadRouteState = RouteState<PublicUploadRoutes>;
pub(crate) type RenderingRouteState = RouteState<RenderingRoutes>;
pub(crate) type ServiceTokenRouteState = RouteState<ServiceTokenRoutes>;
pub(crate) type SettingsRouteState = RouteState<SettingsRoutes>;
pub(crate) type ShareRouteState = RouteState<ShareRoutes>;

pub(crate) trait ConfigCapability {}
pub(crate) trait DatabaseCapability {}
pub(crate) trait SecureRootCapability {}
pub(crate) trait DiskStatsCapability {}
pub(crate) trait LoginLimiterCapability {}
pub(crate) trait AdminLoginLimiterCapability {}
pub(crate) trait SecuritySettingsCapability {}
pub(crate) trait AdmissionCapability {}
pub(crate) trait DirectoryCacheCapability {}
pub(crate) trait MonitoringCapability {}

macro_rules! grant {
    ($capability:ident => $($domain:ty),+ $(,)?) => {
        $(impl $capability for $domain {})+
    };
}

grant!(
    ConfigCapability =>
    AccountRoutes,
    AdminRoutes,
    AdmissionRoutes,
    AuthRoutes,
    FileRoutes,
    MonitoringRoutes,
    PublicRoutes,
    PublicTransferRoutes,
    RenderingRoutes,
    ServiceTokenRoutes,
    SettingsRoutes,
    ShareRoutes,
);
grant!(
    DatabaseCapability =>
    AccountRoutes,
    AdminRoutes,
    AuthRoutes,
    FileRoutes,
    MonitoringRoutes,
    PublicRoutes,
    PublicTransferRoutes,
    ServiceTokenRoutes,
    SettingsRoutes,
    ShareRoutes,
);
grant!(
    SecureRootCapability =>
    AccountRoutes,
    AdminRoutes,
    FileRoutes,
    MonitoringRoutes,
    PublicRoutes,
    PublicTransferRoutes,
    ServiceTokenRoutes,
    SettingsRoutes,
    ShareRoutes,
);
grant!(
    DiskStatsCapability =>
    AccountRoutes,
    AdminRoutes,
    FileRoutes,
    ServiceTokenRoutes,
    SettingsRoutes,
    ShareRoutes,
    MonitoringRoutes,
);
grant!(LoginLimiterCapability => AccountRoutes, AuthRoutes, ServiceTokenRoutes);
grant!(AdminLoginLimiterCapability => AdminRoutes);
grant!(SecuritySettingsCapability => AccountRoutes, AdminRoutes, SettingsRoutes);
grant!(AdmissionCapability => AdmissionRoutes, FileRoutes, PublicRoutes, PublicTransferRoutes);
grant!(DirectoryCacheCapability => FileRoutes, PublicRoutes);
grant!(MonitoringCapability => MonitoringRoutes);

impl<Domain: ConfigCapability> RouteState<Domain> {
    pub(crate) fn config(&self) -> &Config {
        self.inner.config()
    }
}

impl<Domain: DatabaseCapability> RouteState<Domain> {
    pub(crate) fn db(&self) -> &Database {
        self.inner.db()
    }
}

impl<Domain: SecureRootCapability> RouteState<Domain> {
    pub(crate) fn secure_root(&self) -> &SecureRoot {
        self.inner.secure_root()
    }
}

impl<Domain: DiskStatsCapability> RouteState<Domain> {
    pub(crate) fn disk_stats_cache(&self) -> &DiskStatsCache {
        self.inner.disk_stats_cache()
    }
}

impl<Domain: LoginLimiterCapability> RouteState<Domain> {
    pub(crate) fn login_limiter(&self) -> &LoginLimiter {
        self.inner.login_limiter()
    }
}

impl<Domain: AdminLoginLimiterCapability> RouteState<Domain> {
    pub(crate) fn admin_login_limiter(&self) -> &AdminLoginLimiter {
        self.inner.admin_login_limiter()
    }
}

impl<Domain: SecuritySettingsCapability> RouteState<Domain> {
    pub(crate) async fn acquire_security_settings_mutation(&self) -> OwnedMutexGuard<()> {
        self.inner.acquire_security_settings_mutation().await
    }
}

impl<Domain: AdmissionCapability> RouteState<Domain> {
    pub(crate) fn try_acquire_upload(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_upload()
    }

    pub(crate) fn try_acquire_response(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_response()
    }

    pub(crate) fn try_acquire_stream(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_stream()
    }

    pub(crate) fn try_acquire_public_stream(
        &self,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_public_stream()
    }

    pub(crate) fn try_acquire_buffered_response(
        &self,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_buffered_response()
    }

    pub(crate) fn try_acquire_zip_generation(
        &self,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_zip_generation()
    }

    pub(crate) fn try_acquire_preview_render(
        &self,
        permits: u32,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_preview_render(permits)
    }

    pub(crate) fn try_acquire_search(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.inner.try_acquire_search()
    }

    pub(crate) fn try_acquire_stream_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.inner.try_acquire_stream_peer(peer)
    }

    pub(crate) fn try_acquire_upload_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.inner.try_acquire_upload_peer(peer)
    }

    pub(crate) fn try_acquire_buffered_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.inner.try_acquire_buffered_peer(peer)
    }

    pub(crate) fn try_acquire_expensive_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        self.inner.try_acquire_expensive_peer(peer)
    }
}

impl RouteState<PublicRoutes> {
    pub(crate) fn share_limiter(&self) -> &LoginLimiter {
        self.inner.share_limiter()
    }

    pub(crate) fn alias_limiter(&self) -> &LoginLimiter {
        self.inner.alias_limiter()
    }
}

impl RouteState<PublicTransferRoutes> {
    pub(crate) fn preview_token_limiter(&self) -> &LoginLimiter {
        self.inner.preview_token_limiter()
    }
}

impl<Domain: DirectoryCacheCapability> RouteState<Domain> {
    pub(crate) fn directory_snapshot_cache(&self) -> &DirectorySnapshotCache {
        self.inner.directory_snapshot_cache()
    }
}

impl<Domain: MonitoringCapability> RouteState<Domain> {
    pub(crate) fn monitoring_limiter(&self) -> &LoginLimiter {
        self.inner.monitoring_limiter()
    }

    pub(crate) fn monitoring_summary_cache(&self) -> &MonitoringSummaryCache {
        self.inner.monitoring_summary_cache()
    }
}

impl RouteState<FileRoutes> {
    pub(crate) fn file_service(&self) -> FileService {
        FileService::new(self.inner.clone())
    }

    #[cfg(test)]
    pub(crate) fn take_upload_directory_sync_failure_for_test(&self) -> Option<std::io::ErrorKind> {
        self.inner.take_upload_directory_sync_failure_for_test()
    }

    #[cfg(test)]
    pub(crate) fn wait_at_upload_directory_creation_barrier_for_test(&self) {
        self.inner
            .wait_at_upload_directory_creation_barrier_for_test();
    }
}

impl RouteState<PublicTransferRoutes> {
    pub(crate) fn public_transfer_service(&self) -> PublicTransferService {
        PublicTransferService::new(self.inner.clone())
    }
}

impl RouteState<PublicUploadRoutes> {
    pub(crate) fn into_upload_context(self) -> AppState {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_states_are_derived_from_the_outer_app_state() {
        fn assert_view<T: FromRef<AppState> + Clone>() {}

        assert_view::<AccountRouteState>();
        assert_view::<AdminRouteState>();
        assert_view::<AdmissionRouteState>();
        assert_view::<AuthRouteState>();
        assert_view::<FileRouteState>();
        assert_view::<MonitoringRouteState>();
        assert_view::<PublicRouteState>();
        assert_view::<PublicTransferRouteState>();
        assert_view::<PublicUploadRouteState>();
        assert_view::<RenderingRouteState>();
        assert_view::<ServiceTokenRouteState>();
        assert_view::<SettingsRouteState>();
        assert_view::<ShareRouteState>();
    }
}
