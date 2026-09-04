use std::{borrow::Cow, collections::HashMap, future::Future, sync::OnceLock};

use axum::http::HeaderMap;

use crate::http_auth::named_cookie;

include!("i18n/request.rs");

include!("i18n/catalog.rs");

include!("i18n/messages.rs");

include!("i18n/render.rs");

#[cfg(test)]
include!("i18n/tests.rs");
