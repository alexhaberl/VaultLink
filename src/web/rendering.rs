use std::sync::OnceLock;

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::{AppError, Result};
use crate::{
    i18n::{self, Locale, MessageKey},
    internal_reporting::{report_internal, InternalOperation},
    RenderingRouteState,
};

#[cfg(test)]
pub(super) fn esc(s: &str) -> String {
    let mut escaped = String::with_capacity(
        escaped_html_len(s).expect("an existing string has a representable escaped length"),
    );
    for character in s.chars() {
        push_html_escaped(&mut escaped, character);
    }
    escaped
}

pub(super) fn push_html_escaped(escaped: &mut String, character: char) {
    match character {
        '&' => escaped.push_str("&amp;"),
        '<' => escaped.push_str("&lt;"),
        '>' => escaped.push_str("&gt;"),
        '"' => escaped.push_str("&quot;"),
        '\'' => escaped.push_str("&#39;"),
        character => escaped.push(character),
    }
}

pub(super) fn escaped_html_len(value: &str) -> Option<usize> {
    value.chars().try_fold(0usize, |length, character| {
        length.checked_add(match character {
            '&' => 5,
            '<' | '>' => 4,
            '"' => 6,
            '\'' => 5,
            character => character.len_utf8(),
        })
    })
}

const APP_JAVASCRIPT: &str = include_str!("../../assets/web/app.js");

pub(super) const ASSET_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default, Deserialize)]
pub(super) struct AssetQuery {
    pub(super) v: Option<String>,
    pub(super) lang: Option<String>,
}

fn asset_cache_control(query: &AssetQuery, locale_bound: bool) -> HeaderValue {
    let version_matches = query.v.as_deref() == Some(ASSET_VERSION);
    let locale_matches = !locale_bound || matches!(query.lang.as_deref(), Some("de") | Some("en"));
    if version_matches && locale_matches {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("no-store")
    }
}

pub(super) async fn stylesheet_asset(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        crate::ui::STYLESHEET,
    )
        .into_response()
}

pub(super) async fn app_js(Query(query): Query<AssetQuery>) -> Response {
    static SCRIPTS: OnceLock<[String; 2]> = OnceLock::new();
    let scripts = SCRIPTS.get_or_init(|| {
        let source = format!("{}{}", APP_JAVASCRIPT, crate::ui::UPLOAD_QUEUE_JAVASCRIPT);
        [
            i18n::render_markers(Locale::De, &source),
            i18n::render_markers(Locale::En, &source),
        ]
    });
    let locale = match query.lang.as_deref() {
        Some("de") => Locale::De,
        Some("en") => Locale::En,
        _ => i18n::current_locale(),
    };
    let script = match locale {
        Locale::De => &scripts[0],
        Locale::En => &scripts[1],
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/javascript; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, true)),
        ],
        script.as_str(),
    )
        .into_response()
}

pub(super) const MB: u64 = 1_000_000;
pub(super) const GB: u64 = 1_000_000_000;

pub(super) async fn logo_svg(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        LOGO_SVG,
    )
        .into_response()
}

pub(super) async fn favicon_svg(Query(query): Query<AssetQuery>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, asset_cache_control(&query, false)),
        ],
        LOGO_SVG,
    )
        .into_response()
}

pub(super) async fn favicon_png(Query(query): Query<AssetQuery>) -> Response {
    let mut response = crate::ui::FAVICON_PNG.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, asset_cache_control(&query, false));
    response
}

pub(super) const LOGO_SVG: &str = crate::ui::LOGO_SVG;

#[derive(Deserialize)]
pub(super) struct LocaleForm {
    locale: String,
    return_to: String,
}

pub(super) fn safe_internal_return_to(value: &str) -> String {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
        return "/".to_string();
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() == "/locale" {
        return "/".to_string();
    }
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

pub(super) async fn set_locale(
    State(state): State<RenderingRouteState>,
    headers: HeaderMap,
    Form(form): Form<LocaleForm>,
) -> Result<Response> {
    let expected = url::Url::parse(&state.config().server.public_base_url).map_err(|error| {
        AppError::from(report_internal(
            InternalOperation::WebRenderingPublicBaseUrlParse,
            error,
        ))
    })?;
    let supplied = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| url::Url::parse(value).ok());
    if supplied.as_ref().map(url::Url::origin) != Some(expected.origin()) {
        return Err(AppError(
            StatusCode::FORBIDDEN,
            "Cross-site locale change rejected",
        ));
    }
    let locale =
        Locale::parse(&form.locale).ok_or(AppError(StatusCode::BAD_REQUEST, "Invalid language"))?;
    let return_to = safe_internal_return_to(&form.return_to);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000;{}",
        i18n::LOCALE_COOKIE,
        locale.code(),
        if state.config().security.secure_cookie {
            " Secure;"
        } else {
            ""
        }
    );
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|error| {
            AppError::from(report_internal(
                InternalOperation::WebRenderingLocaleCookieHeader,
                error,
            ))
        })?,
    );
    Ok(response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NavSection {
    Files,
    Links,
    Admins,
    ServiceTokens,
    Settings,
    Audit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PageId {
    Account,
    Files,
    Preview,
    DeleteConfirm,
    Links,
    CreateLink,
    Admins,
    AdminCreated,
    MfaReset,
    ServiceTokens,
    ServiceTokenCreated,
    Settings,
    AuditSecurity,
}

impl PageId {
    pub(super) const fn title(self) -> MessageKey {
        match self {
            Self::Account => i18n::ACCOUNT,
            Self::Files => i18n::NAV_FILES,
            Self::Preview => i18n::TITLE_PREVIEW,
            Self::DeleteConfirm => i18n::TITLE_DELETE_CONFIRM,
            Self::Links => i18n::NAV_LINKS,
            Self::CreateLink => i18n::CREATE_LINK,
            Self::Admins => i18n::NAV_ADMINS,
            Self::AdminCreated => i18n::TITLE_ADMIN_CREATED,
            Self::MfaReset => i18n::TITLE_MFA_RESET,
            Self::ServiceTokens => i18n::NAV_SERVICE_TOKENS,
            Self::ServiceTokenCreated => i18n::SERVICE_TOKEN_CREATED_TITLE,
            Self::Settings => i18n::NAV_SETTINGS,
            Self::AuditSecurity => i18n::TITLE_AUDIT_SECURITY,
        }
    }

    pub(super) const fn nav(self) -> Option<NavSection> {
        match self {
            Self::Account => None,
            Self::Files | Self::Preview | Self::DeleteConfirm => Some(NavSection::Files),
            Self::Links | Self::CreateLink => Some(NavSection::Links),
            Self::Admins | Self::AdminCreated | Self::MfaReset => Some(NavSection::Admins),
            Self::ServiceTokens | Self::ServiceTokenCreated => Some(NavSection::ServiceTokens),
            Self::Settings => Some(NavSection::Settings),
            Self::AuditSecurity => Some(NavSection::Audit),
        }
    }
}

pub(super) use crate::services::upload::{storage_full_error, storage_has_room};
