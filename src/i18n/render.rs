pub fn text(locale: Locale, key: MessageKey) -> &'static str {
    let entry = catalog_by_key()
        .get(key.id())
        .unwrap_or_else(|| panic!("unknown translation key: {}", key.id()));
    match locale {
        Locale::De => entry.de,
        Locale::En => entry.en,
    }
}

pub fn localized_text<'a>(locale: Locale, source: &'a str) -> Cow<'a, str> {
    catalog_by_source()
        .get(source)
        .and_then(|entry| entry.for_locale(locale))
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Borrowed(source))
}

/// Compatibility helper for older UI assembly code. New non-UI feedback uses
/// English source strings and calls [`localized_text`] at the HTML boundary.
pub fn text_from_german<'a>(locale: Locale, source: &'a str) -> Cow<'a, str> {
    localized_text(locale, source)
}

fn catalog_by_key() -> &'static HashMap<&'static str, &'static CatalogEntry> {
    static INDEX: OnceLock<HashMap<&'static str, &'static CatalogEntry>> = OnceLock::new();
    INDEX.get_or_init(|| {
        CATALOG
            .iter()
            .map(|entry| (entry.key.id(), entry))
            .collect()
    })
}

#[derive(Clone, Copy)]
enum SourceResolution {
    Unique(&'static str),
    Ambiguous,
}

impl SourceResolution {
    fn merge(&mut self, candidate: &'static str) {
        if matches!(self, Self::Unique(current) if *current != candidate) {
            *self = Self::Ambiguous;
        }
    }

    const fn resolved(self) -> Option<&'static str> {
        match self {
            Self::Unique(value) => Some(value),
            Self::Ambiguous => None,
        }
    }
}

#[derive(Clone, Copy)]
struct SourceTranslations {
    de: SourceResolution,
    en: SourceResolution,
}

impl SourceTranslations {
    const fn new(entry: &'static CatalogEntry) -> Self {
        Self {
            de: SourceResolution::Unique(entry.de),
            en: SourceResolution::Unique(entry.en),
        }
    }

    fn merge(&mut self, entry: &'static CatalogEntry) {
        self.de.merge(entry.de);
        self.en.merge(entry.en);
    }

    const fn for_locale(self, locale: Locale) -> Option<&'static str> {
        match locale {
            Locale::De => self.de.resolved(),
            Locale::En => self.en.resolved(),
        }
    }
}

fn catalog_by_source() -> &'static HashMap<&'static str, SourceTranslations> {
    static INDEX: OnceLock<HashMap<&'static str, SourceTranslations>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = HashMap::new();
        for entry in CATALOG {
            for source in [entry.de, entry.en] {
                index
                    .entry(source)
                    .and_modify(|translations: &mut SourceTranslations| translations.merge(entry))
                    .or_insert_with(|| SourceTranslations::new(entry));
            }
        }
        index
    })
}

/// Replace only explicit internal translation markers. Dynamic values must be
/// HTML-escaped before interpolation, which makes it impossible for them to
/// introduce a literal marker element.
pub fn render_markers(locale: Locale, source: &str) -> String {
    const PREFIX: &str = r#"<vl-i18n key=""#;
    const SUFFIX: &str = r#""/>"#;

    let mut remainder = source;
    let mut rendered = String::with_capacity(source.len());
    while let Some(start) = remainder.find(PREFIX) {
        rendered.push_str(&remainder[..start]);
        let key_and_rest = &remainder[start + PREFIX.len()..];
        let Some(end) = key_and_rest.find(SUFFIX) else {
            rendered.push_str(&remainder[start..]);
            return rendered;
        };
        let key = &key_and_rest[..end];
        let entry = catalog_by_key()
            .get(key)
            .unwrap_or_else(|| panic!("unknown translation marker: {key}"));
        rendered.push_str(match locale {
            Locale::De => entry.de,
            Locale::En => entry.en,
        });
        remainder = &key_and_rest[end + SUFFIX.len()..];
    }
    rendered.push_str(remainder);
    rendered
}
