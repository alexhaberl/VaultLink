mod audit;
mod auth;
mod executor;
mod keyring;
mod public_sessions;
mod required_audit;
mod runtime_settings;
mod schema;
mod service_tokens;
mod shares;
mod transfers;

pub(crate) use executor::{
    execute_database_operation, execute_transfer_database_operation, DatabaseExecutionError,
    DatabaseExecutorAdmission,
};
use required_audit::{insert_required_audits, trace_required_audits};
pub use required_audit::{is_audit_unavailable, AuditContext, Audited, RequiredAuditEvent};
pub(crate) use required_audit::{
    release_session_audit_decision, release_session_audited, RequiredAuditCompletion,
    RequiredAuditDecision,
};
pub(crate) use service_tokens::{SERVICE_TOKEN_PREFIX, SERVICE_TOKEN_RANDOM_BYTES};
#[cfg(any(test, feature = "fuzzing"))]
pub use shares::rewrite_share_path;

#[cfg(test)]
use audit::enforce_audit_retention;
#[cfg(test)]
use transfers::current_utc_month;

#[cfg(test)]
use chrono::Duration;
use chrono::{DateTime, Utc};
use r2d2_sqlite::SqliteConnectionManager;
#[cfg(test)]
use rusqlite::{params, TransactionBehavior};
use rusqlite::{Connection, OpenFlags};
#[cfg(test)]
use schema::SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

include!("db/audit_model.rs");
include!("db/model.rs");
include!("db/database.rs");

#[cfg(test)]
#[path = "db/tests.rs"]
mod tests;
