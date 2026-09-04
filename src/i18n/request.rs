pub const LOCALE_COOKIE: &str = "vaultlink_locale";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Locale {
    De,
    En,
}

impl Locale {
    pub const fn code(self) -> &'static str {
        match self {
            Self::De => "de",
            Self::En => "en",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        let language = value.trim().split(['-', '_']).next()?;
        if language.eq_ignore_ascii_case("de") {
            Some(Self::De)
        } else if language.eq_ignore_ascii_case("en") {
            Some(Self::En)
        } else {
            None
        }
    }

    pub fn resolve(headers: &HeaderMap) -> Self {
        named_cookie(headers, LOCALE_COOKIE)
            .and_then(Self::parse)
            .unwrap_or(Self::En)
    }
}

#[derive(Clone, Debug)]
struct RequestI18n {
    locale: Locale,
    return_to: String,
}

tokio::task_local! {
    static REQUEST_I18N: RequestI18n;
}

pub async fn scope<F>(locale: Locale, return_to: String, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_I18N
        .scope(RequestI18n { locale, return_to }, future)
        .await
}

pub fn current_locale() -> Locale {
    REQUEST_I18N
        .try_with(|context| context.locale)
        .unwrap_or(Locale::En)
}

pub fn current_return_to() -> String {
    REQUEST_I18N
        .try_with(|context| context.return_to.clone())
        .unwrap_or_else(|_| "/".to_string())
}
