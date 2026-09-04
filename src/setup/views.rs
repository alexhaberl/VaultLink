fn setup_form(error: Option<&str>) -> SetupFormTemplate<'_> {
    SetupFormTemplate {
        error,
        max_text_preview_size_mb: MAX_TEXT_PREVIEW_SIZE / 1_000_000,
    }
}

fn page<T: Template>(body: &T, token: Option<&str>) -> String {
    render_page(body, token, true)
}

// Transitional setup responses may contain a one-time TOTP secret or the only
// button that moves the listener into server mode. They deliberately omit the
// locale form because those responses are produced by POST and cannot be
// replayed safely after a locale redirect. The application-owned SecretString
// is zeroed after rendering, but the framework and network response buffers
// cannot be reliably zeroized.
fn page_without_locale_switcher<T: Template>(body: &T) -> String {
    render_page(body, None, false)
}

fn render_page<T: Template>(body: &T, token: Option<&str>, show_locale_switcher: bool) -> String {
    let locale = i18n::current_locale();
    let rendered_body = body
        .render()
        .expect("the setup fragment template writes only to an in-memory string");
    let body = SetupRenderedHtml(i18n::render_markers(locale, &rendered_body));
    SetupPageTemplate {
        locale_code: locale.code(),
        title: i18n::text(locale, i18n::SETUP_TITLE),
        skip_to_content: i18n::text(locale, i18n::SKIP_TO_CONTENT),
        brand_html: TrustedMarkup::brand(i18n::text(locale, i18n::BRAND_TAGLINE)),
        show_locale_switcher,
        language_label: i18n::text(locale, i18n::LANGUAGE),
        return_to: setup_return_to(token),
        german: locale == Locale::De,
        english: locale == Locale::En,
        body: &body,
    }
    .render()
    .expect("the setup page template writes only to an in-memory string")
}

const SETUP_JAVASCRIPT: &str = include_str!("../../assets/web/setup.js");
