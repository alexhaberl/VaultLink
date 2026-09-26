//! Ownership of response capacity by file operations that outlive their request.
use std::{future::Future, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;

type Permits = (
    OwnedSemaphorePermit,
    crate::state::ClientActivityPermit,
    Option<OwnedSemaphorePermit>,
);

#[derive(Clone, Default)]
pub(crate) struct ResponseWorkAdmission(Option<Arc<Permits>>);

tokio::task_local! {
    static CURRENT: ResponseWorkAdmission;
}

impl ResponseWorkAdmission {
    pub(crate) fn new(permits: Permits) -> Self {
        Self(Some(Arc::new(permits)))
    }

    pub(crate) fn current() -> Self {
        CURRENT.try_with(Clone::clone).unwrap_or_default()
    }

    pub(crate) async fn scope<T>(self, future: impl Future<Output = T>) -> T {
        CURRENT.scope(self, future).await
    }

    pub(crate) fn spawn_blocking<F, T>(&self, operation: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let admission = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            operation()
        })
    }
}

pub(crate) fn spawn_blocking<F, T>(operation: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    ResponseWorkAdmission::current().spawn_blocking(operation)
}
