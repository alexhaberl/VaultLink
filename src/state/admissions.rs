use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::{
    config::Admission,
    internal_reporting::{report_invariant, InternalOperation},
    MAX_CONCURRENT_ARGON2_OPERATIONS, MAX_CONCURRENT_SEARCHES, MAX_CONCURRENT_ZIP_GENERATIONS,
    MAX_EXPENSIVE_OPERATIONS_PER_CLIENT, MAX_IN_FLIGHT_BUFFERED_RESPONSES,
    MAX_IN_FLIGHT_BUFFERED_RESPONSES_PER_CLIENT, MAX_IN_FLIGHT_RESPONSES, MAX_IN_FLIGHT_STREAMS,
    MAX_IN_FLIGHT_STREAMS_PER_CLIENT, MAX_IN_FLIGHT_UPLOADS, MAX_IN_FLIGHT_UPLOADS_PER_CLIENT,
    TEXT_PREVIEW_RENDER_BUDGET_PERMITS,
};

pub(crate) struct ClientActivityPermit {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
    maximum: usize,
}

pub(crate) struct ShareActivityPermit {
    counts: Arc<Mutex<HashMap<i64, usize>>>,
    share_id: i64,
    maximum: usize,
}

impl Drop for ShareActivityPermit {
    fn drop(&mut self) {
        let mut counts = share_activity_counts(&self.counts, self.maximum);
        if let Some(count) = counts.get_mut(&self.share_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.share_id);
            }
        }
    }
}

impl Drop for ClientActivityPermit {
    fn drop(&mut self) {
        let mut counts = client_activity_counts(&self.counts, self.maximum);
        if let Some(count) = counts.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

fn client_activity_counts(
    counts: &Mutex<HashMap<IpAddr, usize>>,
    maximum: usize,
) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
    match counts.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let _reported =
                report_invariant(InternalOperation::HttpAuthClientActivityAdmissionPoisonRecovery);
            let mut guard = poisoned.into_inner();
            guard.retain(|_, count| {
                *count = (*count).min(maximum);
                *count > 0
            });
            counts.clear_poison();
            guard
        }
    }
}

pub(crate) fn try_acquire_client_activity(
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
    maximum: usize,
) -> Option<ClientActivityPermit> {
    let mut active = client_activity_counts(&counts, maximum);
    let count = active.entry(peer).or_default();
    if *count >= maximum {
        return None;
    }
    *count += 1;
    drop(active);
    Some(ClientActivityPermit {
        counts,
        peer,
        maximum,
    })
}

fn share_activity_counts(
    counts: &Mutex<HashMap<i64, usize>>,
    maximum: usize,
) -> std::sync::MutexGuard<'_, HashMap<i64, usize>> {
    match counts.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let _reported =
                report_invariant(InternalOperation::HttpAuthShareActivityAdmissionPoisonRecovery);
            let mut guard = poisoned.into_inner();
            guard.retain(|_, count| {
                *count = (*count).min(maximum);
                *count > 0
            });
            counts.clear_poison();
            guard
        }
    }
}

pub(crate) fn try_acquire_share_activity(
    counts: Arc<Mutex<HashMap<i64, usize>>>,
    share_id: i64,
    maximum: usize,
) -> Option<ShareActivityPermit> {
    let mut active = share_activity_counts(&counts, maximum);
    let count = active.entry(share_id).or_default();
    if *count >= maximum {
        return None;
    }
    *count += 1;
    drop(active);
    Some(ShareActivityPermit {
        counts,
        share_id,
        maximum,
    })
}

pub(super) struct Admissions {
    upload: Arc<Semaphore>,
    public_upload: Arc<Semaphore>,
    response: Arc<Semaphore>,
    stream: Arc<Semaphore>,
    public_stream: Arc<Semaphore>,
    preview_render: Arc<Semaphore>,
    zip_generation: Arc<Semaphore>,
    search: Arc<Semaphore>,
    argon2: Arc<Semaphore>,
    stream_peer: Arc<Mutex<HashMap<IpAddr, usize>>>,
    stream_share: Arc<Mutex<HashMap<i64, usize>>>,
    upload_peer: Arc<Mutex<HashMap<IpAddr, usize>>>,
    upload_share: Arc<Mutex<HashMap<i64, usize>>>,
    buffered_response: Arc<Semaphore>,
    buffered_peer: Arc<Mutex<HashMap<IpAddr, usize>>>,
    expensive_peer: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Admissions {
    pub(super) fn new(config: &Admission) -> Self {
        Self {
            upload: Arc::new(Semaphore::new(MAX_IN_FLIGHT_UPLOADS)),
            public_upload: Arc::new(Semaphore::new(config.max_public_uploads)),
            response: Arc::new(Semaphore::new(MAX_IN_FLIGHT_RESPONSES)),
            stream: Arc::new(Semaphore::new(MAX_IN_FLIGHT_STREAMS)),
            public_stream: Arc::new(Semaphore::new(config.max_public_streams)),
            preview_render: Arc::new(Semaphore::new(TEXT_PREVIEW_RENDER_BUDGET_PERMITS)),
            zip_generation: Arc::new(Semaphore::new(MAX_CONCURRENT_ZIP_GENERATIONS)),
            search: Arc::new(Semaphore::new(MAX_CONCURRENT_SEARCHES)),
            argon2: Arc::new(Semaphore::new(MAX_CONCURRENT_ARGON2_OPERATIONS)),
            stream_peer: Arc::new(Mutex::new(HashMap::new())),
            stream_share: Arc::new(Mutex::new(HashMap::new())),
            upload_peer: Arc::new(Mutex::new(HashMap::new())),
            upload_share: Arc::new(Mutex::new(HashMap::new())),
            buffered_response: Arc::new(Semaphore::new(MAX_IN_FLIGHT_BUFFERED_RESPONSES)),
            buffered_peer: Arc::new(Mutex::new(HashMap::new())),
            expensive_peer: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) fn try_upload(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.upload.clone().try_acquire_owned()
    }

    pub(super) fn try_public_upload(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.public_upload.clone().try_acquire_owned()
    }

    pub(super) fn try_response(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.response.clone().try_acquire_owned()
    }

    pub(super) fn try_stream(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.stream.clone().try_acquire_owned()
    }

    pub(super) fn try_public_stream(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.public_stream.clone().try_acquire_owned()
    }

    pub(super) fn try_buffered_response(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.buffered_response.clone().try_acquire_owned()
    }

    pub(super) fn try_preview_render(
        &self,
        permits: u32,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.preview_render.clone().try_acquire_many_owned(permits)
    }

    pub(super) fn try_zip_generation(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.zip_generation.clone().try_acquire_owned()
    }

    pub(super) fn try_search(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.search.clone().try_acquire_owned()
    }

    pub(super) fn try_argon2(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.argon2.clone().try_acquire_owned()
    }

    pub(super) fn try_stream_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        try_acquire_client_activity(
            self.stream_peer.clone(),
            peer,
            MAX_IN_FLIGHT_STREAMS_PER_CLIENT,
        )
    }

    pub(super) fn try_upload_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        try_acquire_client_activity(
            self.upload_peer.clone(),
            peer,
            MAX_IN_FLIGHT_UPLOADS_PER_CLIENT,
        )
    }

    pub(super) fn try_buffered_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        try_acquire_client_activity(
            self.buffered_peer.clone(),
            peer,
            MAX_IN_FLIGHT_BUFFERED_RESPONSES_PER_CLIENT,
        )
    }

    pub(super) fn try_expensive_peer(&self, peer: IpAddr) -> Option<ClientActivityPermit> {
        try_acquire_client_activity(
            self.expensive_peer.clone(),
            peer,
            MAX_EXPENSIVE_OPERATIONS_PER_CLIENT,
        )
    }

    pub(super) fn try_stream_share(
        &self,
        share_id: i64,
        maximum: usize,
    ) -> Option<ShareActivityPermit> {
        try_acquire_share_activity(self.stream_share.clone(), share_id, maximum)
    }

    pub(super) fn try_upload_share(
        &self,
        share_id: i64,
        maximum: usize,
    ) -> Option<ShareActivityPermit> {
        try_acquire_share_activity(self.upload_share.clone(), share_id, maximum)
    }

    #[cfg(test)]
    pub(super) fn replace_upload(&mut self, admission: Arc<Semaphore>) {
        self.upload = admission;
    }

    #[cfg(test)]
    pub(super) fn replace_response(&mut self, admission: Arc<Semaphore>) {
        self.response = admission;
    }

    #[cfg(test)]
    pub(super) fn replace_stream(&mut self, admission: Arc<Semaphore>) {
        self.stream = admission;
    }

    #[cfg(test)]
    pub(super) fn replace_public_stream(&mut self, admission: Arc<Semaphore>) {
        self.public_stream = admission;
    }

    #[cfg(test)]
    pub(super) fn replace_zip_generation(&mut self, admission: Arc<Semaphore>) {
        self.zip_generation = admission;
    }

    #[cfg(test)]
    pub(super) fn upload_available(&self) -> usize {
        self.upload.available_permits()
    }

    #[cfg(test)]
    pub(super) fn zip_generation_available(&self) -> usize {
        self.zip_generation.available_permits()
    }

    #[cfg(test)]
    pub(super) fn upload_peer_count(&self) -> usize {
        self.upload_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    pub(super) fn stream_peer_contains(&self, peer: IpAddr) -> bool {
        self.stream_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&peer)
    }

    #[cfg(test)]
    pub(super) fn expensive_peer_count(&self) -> usize {
        self.expensive_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .sum()
    }

    #[cfg(test)]
    pub(super) async fn acquire_all_argon2(&self) -> OwnedSemaphorePermit {
        self.argon2
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_ARGON2_OPERATIONS as u32)
            .await
            .expect("Argon2 test admission must remain open")
    }

    #[cfg(test)]
    pub(super) fn try_acquire_all_search(&self) -> OwnedSemaphorePermit {
        self.search
            .clone()
            .try_acquire_many_owned(MAX_CONCURRENT_SEARCHES as u32)
            .expect("search test admission must have full capacity")
    }

    #[cfg(test)]
    pub(super) fn try_acquire_all_zip_generation(&self) -> OwnedSemaphorePermit {
        self.zip_generation
            .clone()
            .try_acquire_many_owned(MAX_CONCURRENT_ZIP_GENERATIONS as u32)
            .expect("ZIP test admission must have full capacity")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use super::client_activity_counts;

    #[test]
    fn client_activity_map_is_normalized_after_poisoning() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let zero_peer = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let counts = Arc::new(Mutex::new(HashMap::from([
            (peer, usize::MAX),
            (zero_peer, 0usize),
        ])));
        let poisoned = counts.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("inject client activity map poisoning");
        })
        .is_err());

        let recovered = client_activity_counts(&counts, 4);
        assert_eq!(recovered.get(&peer), Some(&4));
        assert!(!recovered.contains_key(&zero_peer));
        drop(recovered);
        assert!(!counts.is_poisoned());
    }
}
