use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    borrow::Borrow,
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::RwLockWriteGuard,
};

fn borrowed_app_state(state: &(impl Borrow<AppState> + ?Sized)) -> &AppState {
    state.borrow()
}

use axum::response::{IntoResponse, Redirect, Response};

use crate::{
    auth,
    db::{
        AuditAction, AuditContext, Database, MfaMutationContext, MfaSessionProof, Session,
        SessionBound, Share,
    },
    internal_reporting::{
        report_internal, report_invariant, InternalOperation, ReportedInternalError,
    },
    runtime::RuntimeSettings,
    AppState,
};

#[allow(unused_imports)]
pub(crate) use crate::state::{try_acquire_client_activity, try_acquire_share_activity};
pub(crate) use crate::state::{ClientActivityPermit, ShareActivityPermit};

pub const SESSION_COOKIE: &str = "vaultlink_session";
pub const SECURE_SESSION_COOKIE: &str = "__Host-vaultlink_session";
pub(crate) const AUDIT_UNAVAILABLE_MESSAGE: &str = "Security audit log temporarily unavailable";
pub(crate) const ARGON2_BUSY_MESSAGE: &str = "Password processing temporarily unavailable";
pub(crate) use crate::db::{SERVICE_TOKEN_PREFIX, SERVICE_TOKEN_RANDOM_BYTES};
pub(crate) const DATABASE_BUSY_MESSAGE: &str = "Database temporarily unavailable";
const TRANSFER_COOKIE_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

tokio::task_local! {
    static REQUEST_AUDIT_CLIENT_IP: Option<IpAddr>;
}

include!("http_auth/admission.rs");
include!("http_auth/database.rs");
include!("http_auth/runtime.rs");
include!("http_auth/cookies.rs");

include!("http_auth/tests.rs");
