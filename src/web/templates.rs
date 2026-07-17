use std::fmt::{self, Display, Formatter};

use askama::{filters::HtmlSafe, Template};

use super::{common::human, rendering::PageId, AppError, Result};
use crate::{http_auth::runtime_settings, i18n, AppState};

#[derive(Clone)]
pub(super) struct PublicShell {
    pub(super) asset_version: &'static str,
    pub(super) locale_code: &'static str,
    pub(super) title: String,
    pub(super) skip_to_content: &'static str,
    pub(super) brand_html: String,
    pub(super) language_label: &'static str,
    pub(super) return_to: String,
    pub(super) german: bool,
    pub(super) english: bool,
}

pub(super) struct RenderedHtml(String);

impl Display for RenderedHtml {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl HtmlSafe for RenderedHtml {}

#[derive(Template)]
#[template(path = "web/public_base.html")]
struct PublicPageTemplate<'a> {
    shell: PublicShell,
    body: &'a RenderedHtml,
}

pub(super) fn public_shell(title: &str) -> PublicShell {
    let locale = i18n::current_locale();
    PublicShell {
        asset_version: super::rendering::ASSET_VERSION,
        locale_code: locale.code(),
        title: i18n::text_from_german(locale, title).into_owned(),
        skip_to_content: i18n::text(locale, i18n::SKIP_TO_CONTENT),
        brand_html: crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        language_label: i18n::text(locale, i18n::LANGUAGE),
        return_to: i18n::current_return_to(),
        german: locale == i18n::Locale::De,
        english: locale == i18n::Locale::En,
    }
}

#[derive(Clone)]
pub(super) struct AdminNavItem {
    pub(super) href: &'static str,
    pub(super) label: &'static str,
    pub(super) icon_html: String,
    pub(super) active: bool,
}

#[derive(Clone)]
pub(super) struct AdminShell {
    pub(super) asset_version: &'static str,
    pub(super) locale_code: &'static str,
    pub(super) title: &'static str,
    pub(super) skip_to_content: &'static str,
    pub(super) brand_html: String,
    pub(super) navigation_label: &'static str,
    pub(super) navigation: Vec<AdminNavItem>,
    pub(super) available_label: &'static str,
    pub(super) storage_free: String,
    pub(super) storage_total: String,
    pub(super) public_base_url: String,
    pub(super) server_mode: String,
    pub(super) admin_label: &'static str,
    pub(super) show_create_link: bool,
    pub(super) create_link_icon: String,
    pub(super) create_link_label: &'static str,
    pub(super) show_locale_switcher: bool,
    pub(super) language_label: &'static str,
    pub(super) return_to: String,
    pub(super) german: bool,
    pub(super) english: bool,
    pub(super) account_icon: String,
    pub(super) account_label: &'static str,
    pub(super) csrf_token: String,
    pub(super) logout_icon: String,
    pub(super) logout_label: &'static str,
}

#[derive(Template)]
#[template(path = "web/admin_base.html")]
struct AdminPageTemplate<'a> {
    shell: AdminShell,
    body: &'a RenderedHtml,
}

pub(super) fn admin_shell(
    state: &AppState,
    page: PageId,
    show_create_link: bool,
    csrf_token: &str,
    show_locale_switcher: bool,
) -> AdminShell {
    let locale = i18n::current_locale();
    let active = page.nav();
    let navigation = [
        (
            "/admin",
            i18n::NAV_FILES,
            crate::ui::Icon::Folder,
            super::rendering::NavSection::Files,
        ),
        (
            "/admin/shares",
            i18n::NAV_LINKS,
            crate::ui::Icon::Link,
            super::rendering::NavSection::Links,
        ),
        (
            "/admin/admins",
            i18n::NAV_ADMINS,
            crate::ui::Icon::Users,
            super::rendering::NavSection::Admins,
        ),
        (
            "/admin/settings",
            i18n::NAV_SETTINGS,
            crate::ui::Icon::Settings,
            super::rendering::NavSection::Settings,
        ),
        (
            "/admin/audit",
            i18n::NAV_AUDIT,
            crate::ui::Icon::Audit,
            super::rendering::NavSection::Audit,
        ),
    ]
    .into_iter()
    .map(|(href, label, icon, section)| AdminNavItem {
        href,
        label: i18n::text(locale, label),
        icon_html: crate::ui::icon(icon),
        active: active == Some(section),
    })
    .collect();
    let disk = state
        .disk_stats_cache
        .peek_and_refresh(state.secure_root.display_root());
    AdminShell {
        asset_version: super::rendering::ASSET_VERSION,
        locale_code: locale.code(),
        title: i18n::text(locale, page.title()),
        skip_to_content: i18n::text(locale, i18n::SKIP_TO_CONTENT),
        brand_html: crate::ui::brand_lockup(i18n::text(locale, i18n::BRAND_TAGLINE)),
        navigation_label: i18n::text(locale, i18n::MAIN_NAVIGATION),
        navigation,
        available_label: i18n::text(locale, i18n::VAULTLINK_AVAILABLE),
        storage_free: disk
            .as_ref()
            .map(|value| human(value.free))
            .unwrap_or_else(|| "n/a".into()),
        storage_total: disk
            .as_ref()
            .map(|value| human(value.total))
            .unwrap_or_else(|| "n/a".into()),
        public_base_url: runtime_settings(state).public_base_url,
        server_mode: format!("{:?}", state.config.server.mode),
        admin_label: i18n::text(locale, i18n::VAULTLINK_ADMIN),
        show_create_link,
        create_link_icon: crate::ui::icon(crate::ui::Icon::Link),
        create_link_label: i18n::text(locale, i18n::CREATE_LINK),
        show_locale_switcher,
        language_label: i18n::text(locale, i18n::LANGUAGE),
        return_to: i18n::current_return_to(),
        german: locale == i18n::Locale::De,
        english: locale == i18n::Locale::En,
        account_icon: crate::ui::icon(crate::ui::Icon::User),
        account_label: i18n::text(locale, i18n::ACCOUNT_LINK),
        csrf_token: csrf_token.into(),
        logout_icon: crate::ui::icon(crate::ui::Icon::Logout),
        logout_label: i18n::text(locale, i18n::LOG_OUT),
    }
}

pub(super) fn render<T: Template>(template: &T) -> Result<String> {
    let html = template.render().map_err(|_| {
        AppError(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Template konnte nicht gerendert werden",
        )
    })?;
    Ok(i18n::render_markers(i18n::current_locale(), &html))
}

pub(super) fn render_fragment<T: Template>(template: &T) -> Result<RenderedHtml> {
    render(template).map(RenderedHtml)
}

fn trusted_fragment(html: &str) -> RenderedHtml {
    RenderedHtml(i18n::render_markers(i18n::current_locale(), html))
}

pub(super) fn public_page<T: Template>(title: &'static str, body: &T) -> Result<String> {
    let body = render_fragment(body)?;
    render(&PublicPageTemplate {
        shell: public_shell(title),
        body: &body,
    })
}

pub(super) fn public_page_html(title: &str, body: &str) -> Result<String> {
    let body = trusted_fragment(body);
    render(&PublicPageTemplate {
        shell: public_shell(title),
        body: &body,
    })
}

pub(super) fn admin_page<T: Template>(
    state: &AppState,
    page: PageId,
    body: &T,
    show_create_link: bool,
    csrf_token: &str,
    show_locale_switcher: bool,
) -> Result<String> {
    let body = render_fragment(body)?;
    render(&AdminPageTemplate {
        shell: admin_shell(
            state,
            page,
            show_create_link,
            csrf_token,
            show_locale_switcher,
        ),
        body: &body,
    })
}

pub(super) fn admin_page_html(
    state: &AppState,
    page: PageId,
    body: &str,
    show_create_link: bool,
    csrf_token: &str,
    show_locale_switcher: bool,
) -> Result<String> {
    let body = trusted_fragment(body);
    render(&AdminPageTemplate {
        shell: admin_shell(
            state,
            page,
            show_create_link,
            csrf_token,
            show_locale_switcher,
        ),
        body: &body,
    })
}
