use axum::extract::FromRef;

use crate::{
    db::Database, monitoring_cache::MonitoringSummaryCache, readiness::ReadinessProbe,
    secure_fs::SecureRoot, AppState,
};

pub(super) struct Probes {
    readiness: ReadinessProbe,
    monitoring_summary_cache: MonitoringSummaryCache,
}

impl Probes {
    pub(super) fn new() -> Self {
        Self {
            readiness: ReadinessProbe::new(),
            monitoring_summary_cache: MonitoringSummaryCache::new(),
        }
    }

    pub(super) fn readiness(&self) -> &ReadinessProbe {
        &self.readiness
    }

    pub(super) fn monitoring_summary_cache(&self) -> &MonitoringSummaryCache {
        &self.monitoring_summary_cache
    }

    #[cfg(test)]
    pub(super) fn replace_readiness(&mut self, readiness: ReadinessProbe) {
        self.readiness = readiness;
    }
}

/// Narrow route state for the readiness endpoint. The route cannot reach
/// authentication, mutation, admission, or runtime-publication state.
#[derive(Clone)]
pub(crate) struct ReadinessState {
    database: Database,
    secure_root: SecureRoot,
    probe: ReadinessProbe,
}

impl FromRef<AppState> for ReadinessState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            database: state.db().clone(),
            secure_root: state.secure_root().clone(),
            probe: state.readiness_probe().clone(),
        }
    }
}

impl ReadinessState {
    pub(crate) async fn check(&self) -> bool {
        self.probe
            .check(self.database.clone(), self.secure_root.clone())
            .await
    }
}
