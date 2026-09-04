use std::{
    fmt::{self, Display, Formatter},
    io::Write,
    net::SocketAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use askama::{filters::HtmlSafe, Template};
use axum::{
    extract::{Form, MatchedPath, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    Json, Router,
};
use serde::{Deserialize, Serialize};
#[cfg(panic = "unwind")]
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{
    auth,
    config::{
        Admission, CertificateSource, Config, Logging, ReverseProxy, Security, Server, ServerMode,
        Storage, Tls, MAX_TEXT_PREVIEW_SIZE,
    },
    db::{AuditContext, Database, InitialAdminOutcome},
    http_auth::named_cookie,
    i18n::{self, Locale},
    internal_reporting::{report_internal, InternalOperation},
    runtime,
    sensitive::SecretString,
    storage_mount, ui,
    web::templates::TrustedMarkup,
};
include!("setup/state.rs");
include!("setup/routes.rs");
include!("setup/handlers.rs");
include!("setup/commit.rs");
include!("setup/discovery.rs");
include!("setup/views.rs");

include!("setup/tests.rs");
