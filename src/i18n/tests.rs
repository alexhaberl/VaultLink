mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    #[test]
    fn locale_cookie_selects_german_or_english() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=de"),
        );
        headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.8"),
        );
        assert_eq!(Locale::resolve(&headers), Locale::De);
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_locale=en"),
        );
        assert_eq!(Locale::resolve(&headers), Locale::En);
    }

    #[test]
    fn accept_language_is_ignored_without_a_locale_cookie() {
        assert_eq!(Locale::resolve(&HeaderMap::new()), Locale::En);
        for value in [
            "de",
            "de-AT,de;q=0.9",
            "en-US,en;q=0.8",
            "fr, de;q=0.8",
            "*",
            "de;q=broken",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT_LANGUAGE,
                HeaderValue::from_str(value).unwrap(),
            );
            assert_eq!(Locale::resolve(&headers), Locale::En, "{value}");
        }
    }

    #[test]
    fn catalog_keys_are_unique() {
        let mut keys = CATALOG
            .iter()
            .map(|entry| entry.key.id())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), CATALOG.len());
    }

    #[test]
    fn literal_lookup_translates_only_unambiguous_sources() {
        assert_eq!(localized_text(Locale::De, "Preview"), "Vorschau");
        assert_eq!(
            localized_text(Locale::En, "Dateien durchsuchen"),
            "Dateien durchsuchen"
        );
        assert_eq!(localized_text(Locale::De, "Sign in"), "Sign in");
        assert_eq!(localized_text(Locale::De, "Storage"), "Storage");
        assert_eq!(
            localized_text(Locale::De, "not a catalog message"),
            "not a catalog message"
        );
    }

    #[test]
    fn marker_rendering_does_not_translate_dynamic_label_shaped_values() {
        let source =
            r#"<p><vl-i18n key="nav.files"/></p><code>Dateien</code><code>Abmelden</code>"#;
        assert_eq!(
            render_markers(Locale::En, source),
            "<p>Files</p><code>Dateien</code><code>Abmelden</code>"
        );
    }

    #[test]
    fn active_error_literals_have_english_translations() {
        for german in [
            "CSRF-Nachweis muss vor der Datei übermittelt werden",
            "CSRF-Nachweis wurde mehrfach oder zu spät übermittelt",
            "Dieser Link ist nicht mehr aktiv",
            "Eigene MFA kann hier nicht zurückgesetzt werden",
            "Eigener Admin kann nicht stillgelegt werden",
            "Eigenes Passwort kann hier nicht zurückgesetzt werden",
            "Freigabepasswort entspricht nicht der Richtlinie",
            "Überschreiben ist nur für Ordnerlinks mit Uploadrecht erlaubt",
            "Ungültige Upload-Konfliktstrategie",
            "Uploadoption wurde mehrfach oder zu spät übermittelt",
            "Uploadoption wurde mehrfach übermittelt",
            "Uploadpfad muss vor der Datei übermittelt werden",
            "Uploadpfad wurde mehrfach oder zu spät übermittelt",
            "Vorschau-Limit erreicht",
            "ZIP-Erstellung fehlgeschlagen",
            "ZIP-Limit erreicht",
            "ZIP-Quelle nicht verfügbar",
            "Ungültiges ZIP-Limit",
            "Ungültiges Preview-Limit",
            "Ungültiges Media-Preview-Limit",
            "Datei existiert bereits.",
            "Datei fehlt",
        ] {
            assert_ne!(text_from_german(Locale::En, german), german);
        }
    }
}
