use axum::body::Body;
use tokio::sync::OwnedSemaphorePermit;

use crate::{
    http_auth::ClientActivityPermit,
    services::public_transfer::{PublicTransferLease, ZipTempReservation},
};

struct ZipGenerationResources {
    _zip_permit: OwnedSemaphorePermit,
    _peer_permit: ClientActivityPermit,
}

struct ZipTransferResources {
    generation: ZipGenerationResources,
    transfer: PublicTransferLease,
}

impl ZipTransferResources {
    fn session_token(&self) -> &str {
        self.transfer.session_token()
    }

    async fn cancel(self) {
        let Self {
            generation,
            transfer,
        } = self;
        drop(generation);
        transfer.cancel().await;
    }
}

struct ZipMaterializationResources {
    transfer: ZipTransferResources,
    reservation: ZipTempReservation,
}

enum PreparedZip {
    Materialized(Body),
    Direct(Body),
}

impl PreparedZip {
    fn materialized<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(PublicTransferLease) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        drop(generation);
        Self::Materialized(body(transfer))
    }

    fn direct<F>(resources: ZipTransferResources, body: F) -> Self
    where
        F: FnOnce(PublicTransferLease, ZipGenerationResources) -> Body,
    {
        let ZipTransferResources {
            generation,
            transfer,
        } = resources;
        Self::Direct(body(transfer, generation))
    }

    fn into_body(self) -> Body {
        match self {
            Self::Materialized(body) | Self::Direct(body) => body,
        }
    }
}

async fn zip_blocking_with_resources<R, T, F>(
    resources: R,
    operation: F,
) -> std::result::Result<(R, T), tokio::task::JoinError>
where
    R: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let supervisor = tokio::spawn(async move {
        let output = tokio::task::spawn_blocking(operation).await?;
        Ok::<_, tokio::task::JoinError>((resources, output))
    });
    supervisor.await?
}

#[cfg(test)]
pub(super) use crate::services::public_transfer::zip_test_hooks::{
    block_zip_for_test, install_zip_blocking_test_hook, zip_test_phase_active, ZipBlockingTestHook,
    ZipBlockingTestPhase,
};

#[path = "transfer/download.rs"]
mod download_adapter;
#[path = "transfer/zip.rs"]
mod zip_adapter;

pub(crate) use download_adapter::download;
pub(crate) use zip_adapter::download_zip;
