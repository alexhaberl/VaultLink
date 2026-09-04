use std::fmt::{self, Display, Formatter};

use askama::{filters::HtmlSafe, Template};

use crate::{
    i18n,
    internal_reporting::{report_internal, InternalOperation},
};

use super::{ApiError, ApiResult};

#[derive(Clone)]
struct TrustedMarkup(String);

impl Display for TrustedMarkup {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl HtmlSafe for TrustedMarkup {}

struct RenderedHtml(String);

impl Display for RenderedHtml {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl HtmlSafe for RenderedHtml {}

#[derive(Clone)]
struct PublicShell {
    asset_version: &'static str,
    locale_code: &'static str,
    title: String,
    skip_to_content: &'static str,
    brand_html: TrustedMarkup,
    language_label: &'static str,
    return_to: String,
    german: bool,
    english: bool,
}

#[derive(Template)]
#[template(path = "web/public_base.html")]
struct PublicPageTemplate<'a> {
    shell: PublicShell,
    body: &'a RenderedHtml,
}

pub(super) fn public_page<T: Template>(title: i18n::MessageKey, body: &T) -> ApiResult<String> {
    let locale = i18n::current_locale();
    let body = RenderedHtml(render(body)?);
    render(&PublicPageTemplate {
        shell: PublicShell {
            asset_version: env!("CARGO_PKG_VERSION"),
            locale_code: locale.code(),
            title: i18n::text(locale, title).into(),
            skip_to_content: i18n::text(locale, i18n::SKIP_TO_CONTENT),
            brand_html: TrustedMarkup(crate::ui::brand_lockup(i18n::text(
                locale,
                i18n::BRAND_TAGLINE,
            ))),
            language_label: i18n::text(locale, i18n::LANGUAGE),
            return_to: i18n::current_return_to(),
            german: locale == i18n::Locale::De,
            english: locale == i18n::Locale::En,
        },
        body: &body,
    })
}

fn render<T: Template>(template: &T) -> ApiResult<String> {
    let html = template.render().map_err(|error| {
        ApiError::from(report_internal(
            InternalOperation::WebTemplateRenderFailure,
            error,
        ))
    })?;
    Ok(i18n::render_markers(i18n::current_locale(), &html))
}
