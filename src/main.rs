#![cfg_attr(all(not(test), not(debug_assertions)), forbid(unsafe_code))]
#![warn(clippy::cognitive_complexity)]

mod log_safety;
#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;

use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env,
    future::Future,
    io,
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum_server::accept::Accept;
use hyper_util::rt::TokioTimer;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use vaultlink::{
    auth,
    config::{self, CertificateSource, Config, ServerMode},
    db::{
        AdminRecoveryOutcome, AuditContext, AuditRetentionOutcome, Database, InitialAdminOutcome,
    },
    storage_mount, tls_files, web, AppState,
};
use zeroize::Zeroizing;

use log_safety::{EscapedLogPath, EscapedLogValue};

include!("server/acceptor.rs");
include!("server/runtime.rs");
include!("server/audit_worker.rs");
include!("cli/parse.rs");
include!("cli/recovery.rs");
include!("cli/validation.rs");
include!("server/shutdown.rs");
include!("server/tls.rs");

include!("cli/tests.rs");
