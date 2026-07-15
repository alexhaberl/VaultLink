use std::future::Future;

use axum::http::{header, HeaderMap};

use crate::http_auth::named_cookie;

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
            .or_else(|| preferred_from_accept_language(headers))
            .unwrap_or(Self::En)
    }
}

fn preferred_from_accept_language(headers: &HeaderMap) -> Option<Locale> {
    let value = headers.get(header::ACCEPT_LANGUAGE)?.to_str().ok()?;
    let mut best: Option<(Locale, f32, usize)> = None;
    for (position, item) in value.split(',').enumerate() {
        let mut parts = item.trim().split(';');
        let Some(locale) = parts.next().and_then(Locale::parse) else {
            continue;
        };
        let mut quality = 1.0_f32;
        for parameter in parts {
            if let Some(raw) = parameter.trim().strip_prefix("q=") {
                let Some(parsed) = raw.parse::<f32>().ok().filter(|q| (0.0..=1.0).contains(q))
                else {
                    quality = 0.0;
                    break;
                };
                quality = parsed;
            }
        }
        if quality == 0.0 {
            continue;
        }
        if best.is_none_or(|(_, best_quality, best_position)| {
            quality > best_quality || (quality == best_quality && position < best_position)
        }) {
            best = Some((locale, quality, position));
        }
    }
    best.map(|(locale, _, _)| locale)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MessageKey(&'static str);

impl MessageKey {
    pub const fn id(self) -> &'static str {
        self.0
    }
}

#[derive(Clone, Copy)]
struct CatalogEntry {
    key: MessageKey,
    de: &'static str,
    en: &'static str,
}

macro_rules! catalog {
    ($( $name:ident, $id:literal, $de:literal, $en:literal; )+ ) => {
        $(pub const $name: MessageKey = MessageKey($id);)+

        const CATALOG: &[CatalogEntry] = &[
            $(CatalogEntry { key: $name, de: $de, en: $en },)+
        ];
    };
}

catalog! {
    BRAND_TAGLINE, "brand.tagline", "Secure file sharing", "Secure file sharing";
    SKIP_TO_CONTENT, "shell.skip_to_content", "Zum Inhalt springen", "Skip to content";
    MAIN_NAVIGATION, "shell.main_navigation", "Hauptnavigation", "Main navigation";
    VAULTLINK_AVAILABLE, "shell.available", "VaultLink erreichbar", "VaultLink available";
    VAULTLINK_ADMIN, "shell.admin", "VaultLink Admin", "VaultLink Admin";
    CREATE_LINK, "action.create_link", "Link erstellen", "Create link";
    LOG_OUT, "action.log_out", "Abmelden", "Log out";
    LANGUAGE, "action.language", "Sprache", "Language";
    SWITCH_TO_GERMAN, "action.switch_to_german", "Auf Deutsch wechseln", "Switch to German";
    SWITCH_TO_ENGLISH, "action.switch_to_english", "Auf Englisch wechseln", "Switch to English";
    NAV_FILES, "nav.files", "Dateien", "Files";
    NAV_LINKS, "nav.links", "Links", "Links";
    NAV_ADMINS, "nav.admins", "Admins", "Admins";
    NAV_SETTINGS, "nav.settings", "Einstellungen", "Settings";
    NAV_AUDIT, "nav.audit", "Audit", "Audit";
    TITLE_PREVIEW, "title.preview", "Vorschau", "Preview";
    TITLE_DELETE_CONFIRM, "title.delete_confirm", "Löschen bestätigen", "Confirm deletion";
    TITLE_ADMIN_CREATED, "title.admin_created", "Admin erstellt", "Admin created";
    TITLE_MFA_RESET, "title.mfa_reset", "MFA zurückgesetzt", "MFA reset";
    TITLE_AUDIT_SECURITY, "title.audit_security", "Audit & Sicherheit", "Audit & Security";
    ERROR, "common.error", "Fehler", "Error";
    ACCOUNT, "account.title", "Mein Konto", "My account";
    ACCOUNT_LINK, "account.link", "Mein Konto", "My account";
    CURRENT_USER, "account.current_user", "Aktueller Benutzer", "Current user";
    CHANGE_PASSWORD, "account.change_password", "Passwort ändern", "Change password";
    CURRENT_PASSWORD, "account.current_password", "Aktuelles Passwort", "Current password";
    NEW_PASSWORD, "account.new_password", "Neues Passwort", "New password";
    CONFIRM_PASSWORD, "account.confirm_password", "Passwort bestätigen", "Confirm password";
    CHANGE_MFA, "account.change_mfa", "MFA ändern", "Change MFA";
    CURRENT_MFA_CODE, "account.current_mfa_code", "Aktueller MFA-Code", "Current MFA code";
    NEW_MFA_TEST_CODE, "account.new_mfa_test_code", "Neuer MFA-Testcode", "New MFA test code";
    MFA_ENROLLMENT_FLOW, "account.mfa_enrollment_flow", "Neue MFA einrichten", "Set up new MFA";
    OLD_MFA_REMAINS_VALID, "account.old_mfa_valid", "Die bisherige MFA bleibt bis zur erfolgreichen Bestätigung gültig.", "The existing MFA remains valid until the new one is confirmed successfully.";
    ACCOUNT_PASSWORD_CHANGED, "account.password_changed", "Passwort wurde geändert.", "Password changed.";
    ACCOUNT_MFA_CHANGED, "account.mfa_changed", "MFA wurde geändert.", "MFA changed.";
    ACCOUNT_CHANGE_FAILED, "account.change_failed", "Kontoänderung fehlgeschlagen.", "Account change failed.";

    SECURITY_KEYS, "account.security_keys", "Sicherheitsschlüssel (YubiKey/FIDO2)", "Security keys (YubiKey/FIDO2)";
    SECURITY_KEYS_HELP, "account.security_keys_help", "Schlüssel werden an diese Domain gebunden. WebAuthn wird erst mit mindestens zwei registrierten Schlüsseln aktiviert; TOTP bleibt als Wiederherstellung verfügbar.", "Keys are bound to this domain. WebAuthn is enabled only after at least two keys are registered; TOTP remains available for recovery.";
    SECURITY_KEYS_EMPTY, "account.security_keys_empty", "Noch kein Sicherheitsschlüssel registriert.", "No security key registered yet.";
    SECURITY_KEY_LABEL, "account.security_key_label", "Schlüsselname", "Key name";
    SECURITY_KEY_ADD, "account.security_key_add", "Sicherheitsschlüssel hinzufügen", "Add security key";

    LOGIN_TITLE, "auth.login_title", "Login", "Sign in";
    ADMIN_LOGIN, "auth.admin_login", "Admin Login", "Admin sign in";
    USERNAME, "auth.username", "Benutzername", "Username";
    PASSWORD, "auth.password", "Passwort", "Password";
    SIGN_IN, "auth.sign_in", "Anmelden", "Sign in";
    SECOND_FACTOR, "auth.second_factor", "Zweiter Faktor", "Second factor";
    SIX_DIGIT_TOTP, "auth.six_digit_totp", "6-stelliger TOTP-Code", "6-digit TOTP code";
    VERIFY, "auth.verify", "Verifizieren", "Verify";
    SECURITY_KEY_USE, "auth.security_key_use", "Mit Sicherheitsschlüssel bestätigen", "Verify with security key";
    SECURITY_KEY_WAIT, "auth.security_key_wait", "Sicherheitsschlüssel berühren und gegebenenfalls PIN eingeben …", "Touch the security key and enter its PIN if requested…";
    SECURITY_KEY_FAILED, "auth.security_key_failed", "Sicherheitsschlüssel-Vorgang fehlgeschlagen oder abgebrochen.", "Security key operation failed or was cancelled.";
    PROTECTED_SHARE_TITLE, "public.protected_title", "Geschützte Freigabe", "Protected share";
    ENTER_SHARE_PASSWORD, "public.enter_share_password", "Gib das Freigabepasswort ein, um fortzufahren.", "Enter the share password to continue.";
    UNLOCK, "public.unlock", "Entsperren", "Unlock";
    TOO_MANY_LOGIN_ATTEMPTS, "error.too_many_login", "Zu viele Anmeldeversuche", "Too many sign-in attempts";
    INVALID_CREDENTIALS, "error.invalid_credentials", "Ungültige Zugangsdaten", "Invalid credentials";
    TOO_MANY_MFA_ATTEMPTS, "error.too_many_mfa", "Zu viele MFA-Versuche", "Too many MFA attempts";
    INVALID_MFA_CODE, "error.invalid_mfa", "Ungültiger MFA-Code", "Invalid MFA code";
    SIGN_IN_REQUIRED, "error.sign_in_required", "Anmeldung erforderlich", "Sign-in required";
    MFA_REQUIRED, "error.mfa_required", "MFA-Verifikation erforderlich", "MFA verification required";
    INTERNAL_ERROR, "error.internal", "Interner Fehler", "Internal error";
    INVALID_LANGUAGE, "error.invalid_language", "Ungültige Sprache", "Invalid language";

    SETUP_TITLE, "setup.title", "VaultLink Setup", "VaultLink Setup";
    SETUP_INITIAL_SETUP, "setup.initial_setup", "Ersteinrichtung", "Initial setup";
    SETUP_LOCAL_BOOTSTRAP, "setup.local_bootstrap", "Lokaler Bootstrap für die initiale Konfiguration und den ersten Admin. Setup bindet ausschließlich an Loopback.", "Local bootstrap for the initial configuration and first administrator. Setup listens only on loopback.";
    SETUP_SECURITY, "setup.security", "Sicherheit", "Security";
    SETUP_ACME_PROXY_HELP, "setup.acme_proxy_help", "Built-in Let&apos;s Encrypt funktioniert nur, wenn VaultLink selbst Port 443 öffentlich erreicht. Hinter Nginx/Caddy bitte Reverse Proxy verwenden.", "Built-in Let&apos;s Encrypt works only when VaultLink itself is publicly reachable on port 443. Use reverse proxy mode behind Nginx or Caddy.";
    SETUP_SERVER, "setup.server", "Server", "Server";
    SETUP_MODE, "setup.mode", "Modus", "Mode";
    SETUP_SERVICE_ADDRESS, "setup.service_address", "VaultLink-Dienstadresse nach dem Setup", "VaultLink service address after setup";
    SETUP_SERVICE_ADDRESS_HELP, "setup.service_address_help", "Hier lauscht der spätere VaultLink-Dienst. Die lokale Setup-Adresse bleibt davon unabhängig und ausschließlich auf Loopback.", "The VaultLink service will listen here after setup. The local setup address remains separate and loopback-only.";
    SETUP_PUBLIC_BASE_URL, "setup.public_base_url", "Public Base URL", "Public base URL";
    SETUP_LOG_LEVEL, "setup.log_level", "Log Level", "Log level";
    SETUP_STORAGE, "setup.storage", "Storage", "Storage";
    SETUP_ROOT_MOUNT_PATH, "setup.root_mount_path", "Root-Mount-Pfad", "Root mount path";
    SETUP_BROWSE, "setup.browse", "Durchsuchen", "Browse";
    SETUP_DATA_DIRECTORY, "setup.data_directory", "Datenverzeichnis", "Data directory";
    SETUP_INTERNAL_DIRECTORY, "setup.internal_directory", "Privates internes Verzeichnis", "Private internal directory";
    SETUP_EXPECTED_FILESYSTEM_TYPE, "setup.expected_filesystem_type", "Erwarteter Dateisystemtyp", "Expected filesystem type";
    SETUP_EXPECTED_MOUNT_SOURCE, "setup.expected_mount_source", "Erwartete Mount-Quelle", "Expected mount source";
    SETUP_REQUIRE_MOUNT, "setup.require_mount", "Explizites Mount erzwingen", "Require explicit mount";
    SETUP_REQUIRE_MOUNT_HELP, "setup.require_mount_help", "In Production immer aktiv. VaultLink startet nur mit exakt passender aktiver Mount-Identität.", "Always enabled in production. VaultLink starts only with the exact active mount identity.";
    SETUP_EXTERNAL_WRITERS, "setup.external_writers", "Externe SMB-Schreiber", "External SMB writers";
    SETUP_EXTERNAL_WRITERS_HELP, "setup.external_writers_help", "Standard-SMB-Clients schreiben direkt auf denselben CIFS/SMB3-Server; Replace-Uploads werden deaktiviert.", "Standard SMB clients write directly to the same CIFS/SMB3 server; replacement uploads are disabled.";
    SETUP_MAX_UPLOAD_MB, "setup.max_upload_mb", "Max. Upload MB", "Max upload MB";
    SETUP_BLOCKED_EXTENSIONS, "setup.blocked_extensions", "Blockierte Endungen", "Blocked extensions";
    SETUP_ZIP_SEARCH_PREVIEW, "setup.zip_search_preview", "ZIP, Suche und Preview", "ZIP, search, and preview";
    SETUP_ZIP_MAX_GB, "setup.zip_max_gb", "Max. Quelldaten pro ZIP in GB (0 = kein separates Limit)", "Max source data per ZIP in GB (0 = no separate limit)";
    SETUP_ZIP_MAX_FILES, "setup.zip_max_files", "Max. Dateien pro ZIP (0 = kein separates Limit)", "Max files per ZIP (0 = no separate limit)";
    SETUP_SEARCH_MAX_ENTRIES, "setup.search_max_entries", "Suche Max. Einträge", "Search max entries";
    SETUP_SEARCH_MAX_RESULTS, "setup.search_max_results", "Suche Max. Treffer", "Search max results";
    SETUP_TEXT_PREVIEW_MAX_MB, "setup.text_preview_max_mb", "Text-Preview Max. MB", "Text preview max MB";
    SETUP_TEXT_PREVIEW_EXTENSIONS, "setup.text_preview_extensions", "Text-Preview-Endungen", "Text preview extensions";
    SETUP_MEDIA_PREVIEW_MAX_MB, "setup.media_preview_max_mb", "Media-Preview Max. MB", "Media preview max MB";
    SETUP_IMAGE_PREVIEW_EXTENSIONS, "setup.image_preview_extensions", "Bild-Preview-Endungen", "Image preview extensions";
    SETUP_PDF_PREVIEW_ENABLED, "setup.pdf_preview_enabled", "PDF-Preview aktiv", "Enable PDF preview";
    SETUP_PDF_PREVIEW_HELP, "setup.pdf_preview_help", "PDFs werden inline mit sicheren Headern angezeigt.", "PDFs are displayed inline with secure headers.";
    SETUP_PROXY_TLS, "setup.proxy_tls", "Proxy und TLS", "Proxy and TLS";
    SETUP_TRUSTED_PROXIES, "setup.trusted_proxies", "Vertrauenswürdige Proxys", "Trusted proxies";
    SETUP_CERTIFICATE_SOURCE, "setup.certificate_source", "Zertifikatsquelle", "Certificate source";
    SETUP_PEM_FILES, "setup.pem_files", "PEM-Dateien", "PEM files";
    SETUP_LETSENCRYPT_AUTO, "setup.letsencrypt_auto", "Let&apos;s Encrypt Auto", "Let&apos;s Encrypt auto";
    SETUP_TLS_CERT_FILE, "setup.tls_cert_file", "TLS-Zertifikatsdatei", "TLS certificate file";
    SETUP_TLS_KEY_FILE, "setup.tls_key_file", "TLS-Schlüsseldatei", "TLS key file";
    SETUP_LETSENCRYPT_EMAIL, "setup.letsencrypt_email", "Let&apos;s-Encrypt-Kontakt-E-Mail", "Let&apos;s Encrypt contact email";
    SETUP_ACME_CACHE_DIRECTORY, "setup.acme_cache_directory", "ACME-Cache-Verzeichnis", "ACME cache directory";
    SETUP_LETSENCRYPT_STAGING, "setup.letsencrypt_staging", "Let&apos;s-Encrypt-Staging", "Let&apos;s Encrypt staging";
    SETUP_LETSENCRYPT_STAGING_HELP, "setup.letsencrypt_staging_help", "Für erste Tests ohne Rate-Limit-Risiko.", "Use for initial tests without rate-limit risk.";
    SETUP_HSTS_ENABLED, "setup.hsts_enabled", "HSTS aktiv", "Enable HSTS";
    SETUP_HSTS_HELP, "setup.hsts_help", "Nur bei finalem vertrauenswürdigem HTTPS aktivieren.", "Enable only with final, trusted HTTPS.";
    SETUP_AUDIT_PRIVACY, "setup.audit_privacy", "Audit und Datenschutz", "Audit and privacy";
    SETUP_AUDIT_IP, "setup.audit_ip", "Client-IP im Audit speichern", "Store client IP in the audit log";
    SETUP_AUDIT_IP_HELP, "setup.audit_ip_help", "Standardmäßig aus. Bei Aktivierung werden vollständige IP-Adressen unbegrenzt in SQLite gespeichert.", "Off by default. When enabled, complete IP addresses are stored indefinitely in SQLite.";
    SETUP_FIRST_ADMIN, "setup.first_admin", "Erster Admin", "First administrator";
    SETUP_WRITE, "setup.write", "Setup schreiben", "Save setup";
    SETUP_CHOOSE_DIRECTORY, "setup.choose_directory", "Verzeichnis auswählen", "Choose directory";
    SETUP_USE_DIRECTORY, "setup.use_directory", "Dieses Verzeichnis übernehmen", "Use this directory";
    SETUP_SERVER_DIRECTORIES_HELP, "setup.server_directories_help", "Es werden nur Verzeichnisse im Dateisystem des VaultLink-Servers angezeigt.", "Only directories in the VaultLink server file system are shown.";
    SETUP_DIRECTORY_UNREADABLE, "setup.directory_unreadable", "Verzeichnis kann nicht gelesen werden.", "Directory cannot be read.";
    SETUP_NO_FILES_OR_DIRECTORIES, "setup.no_files_or_directories", "Keine Dateien oder Unterverzeichnisse.", "No files or subdirectories.";
    SETUP_NO_SUBDIRECTORIES, "setup.no_subdirectories", "Keine Unterverzeichnisse.", "No subdirectories.";
    SETUP_CHOOSE_FILE, "setup.choose_file", "Datei auswählen", "Choose file";
    SETUP_CERTIFICATE_FILES_HELP, "setup.certificate_files_help", "Es werden nur PEM-, CRT- und CER-Zertifikatsdateien angezeigt.", "Only PEM, CRT, and CER certificate files are shown.";
    SETUP_PRIVATE_KEY_FILES_HELP, "setup.private_key_files_help", "Es werden nur PEM- und KEY-Dateien für den Private Key angezeigt.", "Only PEM and KEY private-key files are shown.";
    SETUP_TOKEN_INVALID, "setup.token_invalid", "Setup-Token fehlt oder ist ungültig.", "The setup token is missing or invalid.";
    SETUP_ALREADY_COMPLETED, "setup.already_completed", "Setup wurde bereits abgeschlossen.", "Setup has already been completed.";
    SETUP_COMPLETED, "setup.completed", "Setup abgeschlossen", "Setup complete";
    SETUP_CONFIG_ADMIN_CREATED, "setup.config_admin_created", "Die Konfiguration wurde geschrieben und der erste Admin wurde angelegt.", "The configuration was written and the first administrator was created.";
    SETUP_TOTP_RECOVERY_HELP, "setup.totp_recovery_help", "Das TOTP-Secret bleibt bis zur ausdrücklichen Bestätigung über diesen lokalen Setup-Flow wiederherstellbar. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.", "The TOTP secret remains recoverable through this local setup flow until you confirm it explicitly. Scan the QR code with an authenticator app or enter the secret manually.";
    SETUP_TOTP_QR_CODE, "setup.totp_qr_code", "TOTP-QR-Code", "TOTP QR code";
    SETUP_SECRET_SAVED, "setup.secret_saved", "Secret sicher gespeichert", "Secret stored safely";
    SETUP_TOTP_ALREADY_CLOSED, "setup.totp_already_closed", "Die TOTP-Wiederherstellung ist bereits geschlossen.", "TOTP recovery has already been closed.";
    SETUP_CONFIG_LOAD_FAILED, "setup.config_load_failed", "Konfiguration kann nicht geladen werden:", "Configuration could not be loaded:";
    SETUP_TOTP_CLOSED, "setup.totp_closed", "Die TOTP-Wiederherstellung wurde geschlossen.", "TOTP recovery was closed.";
    SETUP_CONFIRMATION_FAILED, "setup.confirmation_failed", "Setup-Bestätigung fehlgeschlagen:", "Setup confirmation failed:";
    SETUP_CONFIRMED, "setup.confirmed", "Setup bestätigt", "Setup confirmed";
    SETUP_CONFIGURED_FOR_MODE, "setup.configured_for_mode", "VaultLink ist für den Modus", "VaultLink is configured for mode";
    SETUP_START_NOW, "setup.start_now", "VaultLink jetzt starten", "Start VaultLink now";
    SETUP_SERVICE_START_HELP, "setup.service_start_help", "Für den dauerhaften Produktivbetrieb sollte VaultLink anschließend weiterhin über den konfigurierten Systemdienst gestartet werden.", "For permanent production operation, continue to start VaultLink through the configured system service.";
    SETUP_TOTP_CONFIRM_FIRST, "setup.totp_confirm_first", "Das TOTP-Secret muss zuerst bestätigt werden.", "Confirm the TOTP secret first.";
    SETUP_START_ALREADY_REQUESTED, "setup.start_already_requested", "Der Serverstart wurde bereits angefordert.", "The server start has already been requested.";
    SETUP_STARTING, "setup.starting", "VaultLink wird gestartet", "VaultLink is starting";
    SETUP_LISTENER_TRANSITION, "setup.listener_transition", "Der lokale Setup-Listener wird beendet und VaultLink übernimmt mit der gespeicherten Konfiguration.", "The local setup listener is stopping and VaultLink is taking over with the saved configuration.";
    SETUP_OPEN_VAULTLINK, "setup.open_vaultlink", "VaultLink öffnen", "Open VaultLink";
    SETUP_START_DELAY, "setup.start_delay", "Der Start kann abhängig von TLS und Let&apos;s Encrypt einen Moment dauern.", "Startup may take a moment depending on TLS and Let&apos;s Encrypt.";
    SETUP_INVALID_SERVER_MODE, "setup.invalid_server_mode", "Ungültiger Servermodus.", "Invalid server mode.";
    SETUP_INVALID_CERTIFICATE_SOURCE, "setup.invalid_certificate_source", "Ungültige TLS-Zertifikatsquelle.", "Invalid TLS certificate source.";
    SETUP_INVALID_TRUSTED_PROXIES, "setup.invalid_trusted_proxies", "Trusted Proxies enthalten ungültige IPs.", "Trusted proxies contain invalid IP addresses.";
    SETUP_INVALID_EXTENSIONS, "setup.invalid_extensions", "Eine Endungsliste enthält ungültige Werte.", "An extension list contains invalid values.";
    SETUP_INVALID_CONFIGURATION, "setup.invalid_configuration", "Die Setup-Eingaben ergeben keine gültige VaultLink-Konfiguration. Bitte Adressen, URLs, Pfade, Limits und TLS-Angaben prüfen.", "The setup values do not form a valid VaultLink configuration. Check addresses, URLs, paths, limits, and TLS settings.";
    SETUP_CONFIG_EXISTS, "setup.config_exists", "Konfigurationsdatei existiert bereits und wird nicht überschrieben.", "The configuration file already exists and will not be overwritten.";
    SETUP_INITIAL_ADMIN_EXISTS, "setup.initial_admin_exists", "Die Datenbank enthält bereits Admins; Setup legt nur den ersten Admin an.", "The database already contains administrators; setup creates only the first administrator.";
    SETUP_RECOVERY_UNAVAILABLE, "setup.recovery_unavailable", "Die Wiederherstellung des initialen Setups ist nicht verfügbar.", "Initial setup recovery is unavailable.";
    SETUP_PENDING_OTHER_ADMIN, "setup.pending_other_admin", "Das ausstehende initiale Setup gehört zu einem anderen Administrator.", "The pending initial setup belongs to a different administrator.";

    BACK, "common.back", "Zurück", "Back";
    CONTINUE, "common.continue", "Weiter", "Next";
    CANCEL, "common.cancel", "Abbrechen", "Cancel";
    CLOSE, "common.close", "Schließen", "Close";
    COPY, "common.copy", "Kopieren", "Copy";
    COPIED, "common.copied", "Kopiert", "Copied";
    COPY_FAILED, "common.copy_failed", "Kopieren fehlgeschlagen", "Copy failed";
    SEARCH, "common.search", "Suchen", "Search";
    FILTER, "common.filter", "Filtern", "Filter";
    SAVE, "common.save", "Speichern", "Save";
    DELETE, "common.delete", "Löschen", "Delete";
    REMOVE, "common.remove", "Entfernen", "Remove";
    CREATE, "common.create", "Erstellen", "Create";
    RENAME, "common.rename", "Umbenennen", "Rename";
    OPEN, "common.open", "Öffnen", "Open";
    VIEW, "common.view", "Ansehen", "View";
    DOWNLOAD, "common.download", "Herunterladen", "Download";
    APPLY, "common.apply", "Übernehmen", "Apply";
    SET, "common.set", "Setzen", "Set";
    CONFIRM, "common.confirm", "Bestätigen", "Confirm";
    ACTIVE, "common.active", "Aktiv", "Active";
    INACTIVE, "common.inactive", "Deaktiviert", "Inactive";
    DEACTIVATE_COMMON, "common.deactivate", "Deaktivieren", "Deactivate";
    PROTECTED, "common.protected", "Geschützt", "Protected";
    ENABLED, "common.enabled", "aktiv", "enabled";
    DISABLED, "common.disabled", "deaktiviert", "disabled";
    UNLIMITED, "common.unlimited", "Unbegrenzt", "Unlimited";
    EXPIRED, "common.expired", "Abgelaufen", "Expired";
    NONE, "common.none", "Keine", "None";
    NAME, "common.name", "Name", "Name";
    TYPE, "common.type", "Typ", "Type";
    SIZE, "common.size", "Größe", "Size";
    CHANGED, "common.changed", "Geändert", "Modified";
    CREATED, "common.created", "Erstellt", "Created";
    ACTION, "common.action", "Aktion", "Action";
    ACTIONS, "common.actions", "Aktionen", "Actions";
    STATUS, "common.status", "Status", "Status";
    TIME, "common.time", "Zeit", "Time";
    OBJECT, "common.object", "Objekt", "Object";
    DETAIL, "common.detail", "Detail", "Detail";
    PATH, "common.path", "Pfad", "Path";
    TARGET, "common.target", "Ziel", "Target";
    WARNING, "common.warning", "Warnung:", "Warning:";
    FREE, "common.free", "frei", "free";
    USED, "common.used", "belegt", "used";

    FILE_BROWSER, "files.browser", "Dateibrowser", "File browser";
    FILE, "files.file", "Datei", "file";
    FOLDER, "files.folder", "Ordner", "folder";
    BROWSE_FILES, "files.browse", "Dateien durchsuchen", "Browse files";
    SEARCH_FILES_PLACEHOLDER, "files.search_placeholder", "Dateien durchsuchen", "Search files";
    NEW_FOLDER, "files.new_folder", "Neuer Ordner", "New folder";
    FOLDER_NAME, "files.folder_name", "Ordnername", "Folder name";
    CREATE_FOLDER, "files.create_folder", "Ordner erstellen", "Create folder";
    NEW_NAME, "files.new_name", "Neuer Name", "New name";
    FILE_NAME, "files.file_name", "Dateiname", "File name";
    UP, "files.up", "Hoch", "Up";
    PREVIEW, "files.preview", "Vorschau", "Preview";
    IMAGE_PREVIEW_ALT, "files.preview_alt", "Vorschau", "Preview";
    PDF_PREVIEW_TITLE, "files.pdf_preview", "PDF-Vorschau", "PDF preview";
    FILE_SIZE_LABEL, "files.size_label", "Größe", "Size";
    MODIFIED_LABEL, "files.modified_label", "geändert", "modified";
    RAW_TOKEN_EXPIRES, "files.raw_token", "Raw-Token läuft nach wenigen Minuten ab.", "The raw token expires after a few minutes.";
    BACK_TO_FOLDER, "files.back_to_folder", "Zurück zum Ordner", "Back to folder";
    VIEW_IN_BROWSER, "files.view_browser", "Im Browser ansehen", "View in browser";
    DOWNLOAD_FILE, "files.download_file", "Datei herunterladen", "Download file";
    FOLDER_AS_ZIP, "files.folder_zip", "Ordner als ZIP", "Download folder as ZIP";
    FILE_UPLOADED, "files.uploaded", "Datei wurde erfolgreich hochgeladen.", "File uploaded successfully.";
    FOLDER_CREATED, "files.folder_created", "Ordner wurde erstellt.", "Folder created.";
    ENTRY_RENAMED, "files.entry_renamed", "Eintrag wurde umbenannt.", "Item renamed.";
    ENTRY_DELETED, "files.entry_deleted", "Eintrag wurde permanent gelöscht.", "Item permanently deleted.";
    ENTRY_REMOVED_CLEANUP, "files.entry_removed_cleanup", "Eintrag wurde entfernt; die Bereinigung läuft im Hintergrund.", "Item removed; cleanup is running in the background.";
    DELETE_IRREVERSIBLE, "files.delete_irreversible", "Diese Aktion kann nicht rückgängig gemacht werden.", "This action cannot be undone.";
    FOLDER_NOT_EMPTY, "files.folder_not_empty", "Dieser Ordner ist nicht leer. Sein gesamter Inhalt wird permanent gelöscht.", "This folder is not empty. All of its contents will be permanently deleted.";
    AFFECTED_SHARES, "files.affected_shares", "Betroffene aktive Freigaben:", "Affected active shares:";
    PERMANENT_DELETE, "files.permanent_delete", "Permanent löschen", "Delete permanently";
    DELETE_PERMANENTLY_QUESTION, "files.delete_permanently_question", "permanent löschen?", "permanently?";
    CONFIRM_FOLDER_NAME, "files.confirm_folder_name", "Zur Bestätigung den Ordnernamen", "To confirm, enter the folder name";
    ENTER, "files.enter", "eingeben", "";
    SELECTED, "files.selected", "ausgewählt", "selected";
    ENTRIES_PER_PAGE, "files.entries_page", "100 Einträge pro Seite. Die Suche bleibt auf den aktuellen Ordner begrenzt.", "100 items per page. Search remains limited to the current folder.";
    ENTRIES_PAGE_LIMITED, "files.entries_page_limited", "100 Einträge pro Seite. Suche ist limitiert und läuft innerhalb des aktuellen Ordners.", "100 items per page. Search is limited and runs within the current folder.";
    SCAN_LIMIT, "files.scan_limit", "Verzeichnis-Scanlimit erreicht; weitere Einträge werden aus Sicherheitsgründen nicht gelesen.", "Directory scan limit reached; additional items are not read for security reasons.";
    FILE_PAGES, "files.pages_aria", "Dateiseiten", "File pages";
    PAGE_NAVIGATION, "common.page_navigation", "Seitennavigation", "Page navigation";
    SORTING, "files.sorting", "Sortierung", "Sort order";
    NEWEST_FIRST, "files.newest_first", "Neueste zuerst", "Newest first";
    OLDEST_FIRST, "files.oldest_first", "Älteste zuerst", "Oldest first";
    ALL, "common.all", "Alle", "All";

    UPLOAD, "upload.upload", "Upload", "Upload";
    ADMIN_UPLOAD, "upload.admin", "Admin-Upload", "Admin upload";
    DROP_FILE_HERE, "upload.drop_here", "Datei hier ablegen", "Drop file here";
    UPLOAD_FILE, "upload.file", "Datei hochladen", "Upload a file";
    UPLOAD_FILES_PUBLIC, "upload.files_public", "Dateien hochladen", "Upload files";
    UPLOAD_SECURELY, "upload.securely", "Sicher hochladen", "Upload securely";
    OR_CHOOSE_FILE, "upload.or_choose", "oder über den Dateidialog auswählen", "or choose it in the file dialog";
    OR_ADD_SELECTION, "upload.or_add", "Oder über die Dateiauswahl hinzufügen.", "Or add files using the file picker.";
    UPLOAD_SEQUENTIAL, "upload.sequential", "Dateien werden nacheinander und atomar veröffentlicht.", "Files are published sequentially and atomically.";
    START_UPLOAD, "upload.start", "Upload starten", "Start upload";
    NO_FILE_SELECTED, "upload.none_selected", "Noch keine Datei ausgewählt.", "No file selected yet.";
    REMOVED_FROM_QUEUE, "upload.removed_queue", "Datei aus der Warteschlange entfernt.", "File removed from the queue.";
    READY, "upload.ready", "Bereit", "Ready";
    RETRY, "upload.retry", "Erneut versuchen", "Retry";
    REMOVE_FROM_LIST, "upload.remove_list", "Aus Liste entfernen", "Remove from list";
    UPLOADING, "upload.uploading", "Wird hochgeladen …", "Uploading…";
    UPLOADED, "upload.uploaded", "Hochgeladen", "Uploaded";
    REPLACED, "upload.replaced", "Ersetzt", "Replaced";
    UPLOAD_PERSIST_PENDING, "upload.persist_pending", "Hochgeladen – Persistenzbestätigung ausstehend", "Uploaded – persistence confirmation pending";
    REPLACE_PERSIST_PENDING, "upload.replace_pending", "Ersetzt – Persistenzbestätigung ausstehend", "Replaced – persistence confirmation pending";
    INVALID_SERVER_RESPONSE, "upload.invalid_response", "Ungültige Serverantwort", "Invalid server response";
    UPLOAD_FAILED, "upload.failed", "Upload fehlgeschlagen", "Upload failed";
    SUCCESSFUL, "upload.successful", "erfolgreich", "successful";
    FAILED_RETRY, "upload.failed_retry", "fehlgeschlagen – einzeln erneut versuchen", "failed – retry individually";
    ALL_ALREADY_UPLOADED, "upload.already_done", "Alle ausgewählten Dateien wurden bereits hochgeladen.", "All selected files have already been uploaded.";
    SELECT_AT_LEAST_ONE, "upload.select_one", "Bitte mindestens eine Datei auswählen.", "Select at least one file.";
    FILE_WAS_ADDED, "upload.file_added", "Datei wurde hinzugefügt.", "file added.";
    FILES_WERE_ADDED, "upload.files_added", "Dateien wurden hinzugefügt.", "files added.";

    SHARE, "share.share", "Freigabe", "Share";
    SECURE_SHARE, "share.secure", "Sichere Freigabe", "Secure share";
    SHARES, "share.shares", "Freigaben", "Shares";
    DEFAULT_SHARE_NAME, "share.default_name", "Freigabe", "Share";
    CREATE_SECURE_LINK, "share.create_secure", "Sicheren Link erstellen", "Create secure link";
    SHARE_CURRENT_FOLDER, "share.current_folder", "Aktuellen Ordner freigeben", "Share current folder";
    SHARE_CURRENT_FOLDER_HELP, "share.current_help", "Aktuellen Ordner sicher freigeben oder per Suche eingrenzen.", "Share the current folder securely or narrow it using search.";
    CREATE_LINK_FOR_SELECTION, "share.selection", "Link für Auswahl erstellen", "Create link for selection";
    SELECT_TARGET_FIRST, "share.select_target", "Wähle zuerst ein Ziel aus", "Select a target first";
    OPEN_BROWSER_SELECT, "share.open_browser", "Öffne den Dateibrowser und wähle eine Datei oder einen Ordner für die Freigabe.", "Open the file browser and select a file or folder to share.";
    TO_FILE_BROWSER, "share.to_browser", "Zum Dateibrowser", "Go to file browser";
    CHOOSE_IN_BROWSER, "share.choose_browser", "Pfad im Dateibrowser auswählen", "Select path in file browser";
    CHOOSE_OTHER_PATH, "share.other_path", "Anderen Pfad im Dateibrowser auswählen", "Select another path in the file browser";
    CHANGE_TARGET, "share.change_target", "Ziel ändern", "Change target";
    SELECTED_TARGET, "share.selected_target", "Ausgewähltes Ziel", "Selected target";
    ONE_TARGET_SELECTED, "share.one_selected", "Ein Ziel ausgewählt", "One target selected";
    STEP_PERMISSION, "share.step_permission", "1. Berechtigung", "1. Permission";
    STEP_LINK_ACCESS, "share.step_link", "2. Link &amp; Zugriff", "2. Link &amp; access";
    STEP_PROTECTION, "share.step_protection", "3. Schutz", "3. Protection";
    STEP_UPLOAD_RULES, "share.step_upload", "4. Upload-Regeln", "4. Upload rules";
    PERMISSION, "share.permission", "Berechtigung", "Permission";
    PERMISSION_ARIA, "share.permission_aria", "Berechtigung", "Permission";
    DOWNLOAD_ONLY, "share.download_only", "Nur Download", "Download only";
    UPLOAD_ONLY, "share.upload_only", "Nur Upload", "Upload only";
    DOWNLOAD_UPLOAD, "share.download_upload", "Download + Upload", "Download + upload";
    UPLOAD_FOLDER_ONLY, "share.upload_folder_only", "Uploadrechte sind ausschließlich für Ordner verfügbar.", "Upload permission is available for folders only.";
    UPLOAD_LINK_FOLDER_ONLY, "share.upload_link_folder", "Upload-Rechte sind nur für Ordnerlinks verfügbar. Für Uploads bitte im Dateibrowser einen Zielordner auswählen.", "Upload permission is available for folder links only. Select a target folder in the file browser.";
    ALIAS_OPTIONAL, "share.alias_optional", "Alias (optional)", "Alias (optional)";
    SHORT_ALIAS, "share.short_alias", "Kurzer Alias", "Short alias";
    ALIAS_HELP, "share.alias_help", "Optional, 12–32 Zeichen.", "Optional, 12–32 characters.";
    MAX_DOWNLOADS, "share.max_downloads", "Max. Downloads", "Max. downloads";
    MAX_TRANSFERS, "share.max_transfers", "Max. gezählte Übertragungen", "Max. counted transfers";
    COUNTED_TRANSFERS, "share.counted_transfers", "gezählte Übertragungen", "counted transfers";
    TRANSFERS, "share.transfers", "Übertragungen", "transfers";
    UPLOAD_LIMIT_LABEL, "share.upload_limit_label", "Uploadlimit", "Upload limit";
    EMPTY_UNLIMITED, "share.empty_unlimited", "Leer bedeutet unbegrenzt.", "Leave empty for unlimited.";
    EXPIRES_OPTIONAL, "share.expires_optional", "Ablauf (optional)", "Expiration (optional)";
    NO_EXPIRY, "share.no_expiry", "Kein Ablauf", "No expiration";
    DATE_TIME_SELECT, "share.date_select", "Datum und Uhrzeit auswählen", "Select date and time";
    YEAR, "date.year", "Jahr", "Year";
    MONTH, "date.month", "Monat", "Month";
    DAY, "date.day", "Tag", "Day";
    HOUR, "date.hour", "Stunde", "Hour";
    MINUTE, "date.minute", "Minute", "Minute";
    DATE_FORMAT, "date.format", "Format: TT.MM.JJJJ HH:MM", "Format: YYYY-MM-DD HH:MM";
    DATE_PLACEHOLDER, "date.placeholder", "TT.MM.JJJJ HH:MM", "YYYY-MM-DD HH:MM";
    PASSWORD_OPTIONAL, "share.password_optional", "Passwort (optional)", "Password (optional)";
    PASSWORD_PROTECTION, "share.password_protection", "Passwortschutz", "Password protection";
    ENABLE_PASSWORD_FIELDS, "share.password_enable", "Aktiviert die beiden Passwortfelder.", "Enables both password fields.";
    WITHOUT_PASSWORD, "share.no_password", "Ohne Passwort", "Without password";
    PASSWORD_PROTECTED, "share.password_protected", "Passwort geschützt", "Password protected";
    PASSWORD_PROTECTED_LOWER, "share.password_protected_lower", "passwortgeschützt", "password protected";
    SHARE_OPTIONS, "share.options", "Freigabeoptionen", "Share options";
    REVIEW_SHARE, "share.review", "Freigabe prüfen", "Review share";
    URL_PREVIEW, "share.url_preview", "Vorschau der URL", "URL preview";
    CREATE_LOGGED, "share.audit_help", "Die Erstellung wird im Audit protokolliert.", "Creation is recorded in the audit log.";
    LIMITS_PROTECTION, "share.limits", "Limits und Schutz", "Limits and protection";
    LIMIT, "share.limit", "Limit", "Limit";
    LIMIT_REACHED, "share.limit_reached", "Limit erreicht", "Limit reached";
    RIGHTS, "share.rights", "Recht", "Permission";
    DOWNLOADS, "share.downloads", "Downloads", "Downloads";
    SEARCH_LINKS, "share.search_links", "Links durchsuchen", "Search links";
    MONTHLY_VALUES, "share.monthly_values", "Monatswerte in UTC, Erfassung seit", "Monthly values in UTC, recorded since";
    PAGE_OF, "common.page_of", "Seite", "Page";
    OF, "common.of", "von", "of";
    NO_LINKS, "share.no_links", "Keine Links gefunden", "No links found";
    ADJUST_FILTERS, "share.adjust_filters", "Passe Suche oder Filter an oder erstelle einen neuen Link.", "Adjust the search or filters, or create a new link.";
    LINK_OVERVIEW, "share.overview_aria", "Linkübersicht", "Link overview";
    COPY_LINK, "share.copy_aria", "Link kopieren", "Copy link";
    MORE_ACTIONS, "share.more_aria", "Weitere Aktionen", "More actions";
    UPLOAD_LIMIT_OPTIONAL, "share.upload_limit", "Uploadlimit GB (optional)", "Upload limit in GB (optional)";
    MAX_FILE_SIZE_GB, "share.max_file", "Max. Dateigröße in GB", "Max. file size in GB";
    EMPTY_GLOBAL_LIMIT, "share.empty_global", "Leer verwendet das globale Limit.", "Leave empty to use the global limit.";
    UPLOAD_RULES, "share.upload_rules", "Upload-Regeln", "Upload rules";
    ALLOW_OVERWRITE, "share.allow_overwrite", "Überschreiben erlauben", "Allow overwrite";
    ALLOW_UPLOAD_OVERWRITE, "share.allow_upload_overwrite", "Überschreiben für Uploads erlauben", "Allow overwrite for uploads";
    EXISTING_MAY_REPLACE, "share.existing_replace", "Bestehende Dateien dürfen ersetzt werden", "Existing files may be replaced";
    REPLACE_EXISTING_FILE, "share.replace_existing_file", "Bestehende Datei ersetzen", "Replace existing file";
    EXISTING_DEFAULT_NO_REPLACE, "share.no_replace_help", "Vorhandene Dateien werden standardmäßig nicht ersetzt. Erfolgreiche Uploads werden protokolliert.", "Existing files are not replaced by default. Successful uploads are recorded.";
    EXISTING_HIDDEN, "share.existing_hidden", "Vorhandene Dateien und Ordner bleiben verborgen.", "Existing files and folders remain hidden.";
    UPLOADER_CONFIRM_REPLACE, "share.uploader_confirm", "Uploader müssen jede Ersetzung zusätzlich bestätigen.", "Uploaders must additionally confirm every replacement.";
    UPLOADER_CONFIRM_UPLOAD, "share.uploader_confirm_upload", "Uploader müssen das Ersetzen pro Upload zusätzlich bestätigen.", "Uploaders must additionally confirm replacement for each upload.";
    UPLOADER_CONFIRM_EACH, "share.uploader_confirm_each", "Uploader bestätigen jedes Ersetzen zusätzlich.", "Uploaders additionally confirm every replacement.";
    REPLACE_CONFLICT_FILE, "share.replace_conflict", "Konfliktdatei ersetzen", "Replace conflicting file";
    REPLACE_CONCRETE_ONLY, "share.replace_concrete", "Nur für die konkrete Datei und nach ausdrücklicher Bestätigung.", "Only for the specific file and after explicit confirmation.";
    USE_AFTER_CONFLICT, "share.after_conflict", "Nur nach einem konkreten Namenskonflikt verwenden.", "Use only after a specific naming conflict.";
    CAN_DISABLE_AGAIN, "share.disable_again", "Kann jederzeit wieder deaktiviert werden.", "Can be disabled again at any time.";
    BACK_TO_SHARE, "share.back", "Zurück zur Freigabe", "Back to share";
    PROVIDED_BY, "public.provided_by", "Bereitgestellt über", "Provided by";
    READY_FOR, "public.ready_for", "Bereit für", "Ready for";
    VALID_UNTIL, "public.valid_until", "Gültig bis", "Valid until";
    TRANSFERS_USED_PREFIX, "public.transfers_used_prefix", "von", "of";
    TRANSFERS_USED_SUFFIX, "public.transfers_used_suffix", "gezählten Übertragungen verwendet", "counted transfers used";
    HTTPS_SECURE, "public.https_secure", "HTTPS · sicher übertragen", "HTTPS · securely transferred";
    LOCAL_HTTP, "public.local_http", "Lokale HTTP-Verbindung", "Local HTTP connection";
    FILE_REPLACED_SUCCESS, "public.file_replaced", "Datei erfolgreich ersetzt.", "File replaced successfully.";
    UPLOAD_COMPLETED, "public.upload_completed", "Upload erfolgreich abgeschlossen.", "Upload completed successfully.";
    UPLOAD_STORAGE_UNCONFIRMED, "public.upload_unconfirmed", "Upload veröffentlicht; die dauerhafte Speicherung konnte nicht bestätigt werden.", "Upload published; durable storage could not be confirmed.";
    REPLACE_STORAGE_UNCONFIRMED, "public.replace_unconfirmed", "Datei ersetzt; die dauerhafte Speicherung konnte nicht bestätigt werden.", "File replaced; durable storage could not be confirmed.";
    TARGET_FOLDER_WITHIN, "public.target_folder", "Zielordner innerhalb der Freigabe", "Target folder within the share";
    SHARE_TARGET_UNAVAILABLE, "error.share_target", "Freigabeziel nicht verfügbar", "Share target unavailable";
    SHARE_FILE_UNAVAILABLE, "error.share_file", "Freigabedatei nicht verfügbar", "Shared file unavailable";
    PREVIEW_NOT_ALLOWED, "error.preview_not_allowed", "Vorschau nicht erlaubt", "Preview not allowed";
    FILE_PATH_MISSING, "error.file_path_missing", "Dateipfad fehlt", "File path missing";

    AUDIT_DURABILITY_UNCERTAIN, "files.audit_durability_uncertain", "Die Dateioperation wurde ausgefuehrt, aber ihre Audit-Dauerhaftigkeit ist unklar. Nicht erneut ausfuehren; die Wiederherstellung schliesst sie sicher ab.", "The file operation completed, but its audit durability is uncertain. Do not retry it; recovery will finish it safely.";

    CURRENT_ADMIN, "admins.current", "Aktueller Admin", "Current admin";
    ACTIVE_ADMINS, "admins.active", "Aktive Admins", "Active admins";
    INACTIVE_ADMINS, "admins.inactive", "Stillgelegte Admins", "Inactive admins";
    NO_ACTIVE_ADMINS, "admins.no_active", "Keine aktiven Admins.", "No active admins.";
    NO_INACTIVE_ADMINS, "admins.no_inactive", "Keine stillgelegten Admins.", "No inactive admins.";
    CREATE_ADMIN, "admins.create", "Admin erstellen", "Create admin";
    DEACTIVATE, "admins.deactivate", "Stilllegen", "Deactivate";
    ACTIVATE, "admins.activate", "Aktivieren", "Activate";
    RESET_MFA, "admins.reset_mfa", "MFA zurücksetzen", "Reset MFA";
    SET_PASSWORD, "admins.set_password", "Passwort setzen", "Set password";
    PASSWORD_WAS_SET, "admins.password_set", "Passwort wurde gesetzt. Bestehende Sessions dieses Admins wurden beendet.", "Password was set. Existing sessions for this admin were ended.";
    ADMIN_SECRET_ONCE, "admins.secret_once", "Dieses TOTP-Secret wird nur jetzt angezeigt. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.", "This TOTP secret is shown only now. Scan the QR code with an authenticator app or enter the secret manually.";
    ADMIN_NEW_SECRET_ONCE, "admins.new_secret_once", "Dieses neue TOTP-Secret wird nur jetzt angezeigt. QR-Code mit der Authenticator-App scannen oder Secret manuell eintragen.", "This new TOTP secret is shown only now. Scan the QR code with an authenticator app or enter the secret manually.";
    TO_ADMIN_LIST, "admins.to_list", "Zur Adminliste", "Back to admin list";

    RUNTIME_SETTINGS, "settings.runtime", "Runtime-Einstellungen", "Runtime settings";
    RUNTIME_POLICY_HELP, "settings.runtime_help", "Runtime-Policy wird in SQLite gespeichert. Servermodus, Bind-Adresse, TLS-Dateien, Trusted Proxies, Root-Mount und Data-Dir bleiben file-/restart-basiert.", "Runtime policy is stored in SQLite. Server mode, bind address, TLS files, trusted proxies, root mount, and data directory remain file- and restart-based.";
    SETTINGS_SAVED, "settings.saved", "Einstellungen gespeichert.", "Settings saved.";
    GLOBAL_UPLOAD_LIMIT, "settings.upload_limit", "Globales Uploadlimit GB", "Global upload limit in GB";
    BLOCKED_EXTENSIONS, "settings.blocked", "Blockierte Endungen", "Blocked extensions";
    SHARE_PASSWORD_MIN, "settings.password_min", "Share-Passwort Min. Zeichen", "Share password min. characters";
    SHARE_PASSWORD_MAX, "settings.password_max", "Share-Passwort Max. Zeichen", "Share password max. characters";
    UNLOCK_MINUTES, "settings.unlock_minutes", "Unlock Minuten", "Unlock minutes";
    ZIP_MAX_GB, "settings.zip_gb", "Max. Quelldaten pro ZIP in GB (0 = kein separates Limit)", "Max source data per ZIP in GB (0 = no separate limit)";
    ZIP_MAX_FILES, "settings.zip_files", "Max. Dateien pro ZIP (0 = kein separates Limit)", "Max files per ZIP (0 = no separate limit)";
    SEARCH_MAX_ENTRIES, "settings.search_entries", "Suche Max. Einträge", "Search max. entries";
    SEARCH_MAX_RESULTS, "settings.search_results", "Suche Max. Treffer", "Search max. results";
    TEXT_PREVIEW_MAX, "settings.text_preview", "Text-Preview Max. MB", "Text preview max. MB";
    TEXT_PREVIEW_EXTENSIONS, "settings.text_extensions", "Text-Preview-Endungen", "Text preview extensions";
    MEDIA_PREVIEW_MAX, "settings.media_preview", "Media-Preview Max. MB", "Media preview max. MB";
    IMAGE_PREVIEW_EXTENSIONS, "settings.image_extensions", "Bild-Preview-Endungen", "Image preview extensions";
    PDF_PREVIEW_ACTIVE, "settings.pdf_active", "PDF-Preview aktiv", "Enable PDF preview";
    PDF_SAFE_HEADERS, "settings.pdf_help", "PDFs werden inline mit sicheren Headern angezeigt.", "PDFs are displayed inline with secure headers.";
    CAPTURE_AUDIT_IP, "settings.audit_ip", "Client-IP im Audit erfassen", "Capture client IP in audit";
    AUDIT_IP_HELP, "settings.audit_ip_help", "Standardmäßig aus. Bei Aktivierung wird die aufgelöste vollständige IP in SQLite gespeichert, nicht zusätzlich ins Serverlog geschrieben.", "Off by default. When enabled, the resolved full IP address is stored in SQLite and is not additionally written to the server log.";
    DELETE_AUDIT_IPS, "settings.delete_ips", "gespeicherte IP-Adressen löschen", "delete stored IP addresses";
    DELETE_AUDIT_IP_DATA, "settings.delete_ip_data", "Audit-IP-Daten löschen?", "Delete audit IP data?";
    DELETE_IP_VALUES, "settings.delete_ip_values", "gespeicherte Client-IP-Werte permanent entfernt. Andere Auditdaten bleiben erhalten.", "stored client IP values will be permanently removed. Other audit data remains.";
    VALUES_PREFIX, "settings.values_prefix", "Es werden", "The following";
    ENTER_TO_CONFIRM, "settings.enter_confirm", "Zur Bestätigung", "To confirm, enter";
    DELETE_IP_DATA_ACTION, "settings.delete_ip_action", "IP-Daten löschen", "Delete IP data";

    TRACEABILITY, "audit.traceability", "Nachvollziehbarkeit", "Traceability";
    AUDIT_EVENTS, "audit.events", "Audit-Ereignisse", "Audit events";
    ACTION_FILTER, "audit.action_filter", "Action-Filter", "Action filter";
    FILTER_ACTION, "audit.filter_action", "Action filtern", "Filter action";
    AUDIT_PAGES, "audit.pages", "Audit-Seiten", "Audit pages";
    SECURITY_STATUS, "audit.security_status", "Security-Status", "Security status";
    PROVEN_CONFIGURATION, "audit.proven_config", "Belegte Konfiguration", "Verified configuration";
    ADMIN_MFA_REQUIRED, "audit.mfa_required", "Für Admin-Sitzungen verpflichtend", "Required for admin sessions";
    SERVER_MODE, "audit.server_mode", "Servermodus", "Server mode";
    PUBLIC_URL_SCHEME, "audit.url_scheme", "Öffentliches URL-Schema", "Public URL scheme";
    AUDIT_IP_CAPTURE, "audit.ip_capture", "Audit-IP-Erfassung", "Audit IP capture";
    LOGGING, "audit.logging", "Protokollierung", "Logging";
    STRUCTURED_LOGGING, "audit.structured", "SQLite + strukturiertes Serverlog", "SQLite + structured server log";
    UNKNOWN, "common.unknown", "unbekannt", "unknown";
    STORAGE_OVERVIEW, "audit.storage_aria", "Speicherübersicht", "Storage overview";
    STORAGE, "audit.storage", "Speicher", "Storage";

    INVALID_PATH, "error.invalid_path", "Ungültiger Pfad", "Invalid path";
    INVALID_TARGET_PATH, "error.invalid_target_path", "Ungültiger Zielpfad", "Invalid target path";
    INVALID_NAME, "error.invalid_name", "Ungültiger Name", "Invalid name";
    NOT_FOUND, "error.not_found", "Nicht gefunden", "Not found";
    LINK_NOT_FOUND, "error.link_not_found", "Link nicht gefunden", "Link not found";
    ALIAS_NOT_FOUND, "error.alias_not_found", "Alias nicht gefunden", "Alias not found";
    INVALID_PASSWORD, "error.invalid_password", "Ungültiges Passwort", "Invalid password";
    TOO_MANY_PASSWORD_ATTEMPTS, "error.password_attempts", "Zu viele Passwortversuche", "Too many password attempts";
    INVALID_CSRF, "error.invalid_csrf", "Ungültiges CSRF-Token", "Invalid CSRF token";
    CSRF_MISSING, "error.csrf_missing", "CSRF-Token fehlt", "CSRF token missing";
    INVALID_MULTIPART, "error.invalid_multipart", "Ungültiger Multipart-Upload", "Invalid multipart upload";
    INVALID_SETTING, "error.invalid_setting", "Ungültige Einstellung", "Invalid setting";
    SHARE_INACTIVE, "error.share_inactive", "Freigabe ist deaktiviert", "Share is inactive";
    SHARE_EXPIRED, "error.share_expired", "Freigabe ist abgelaufen", "Share has expired";
    DOWNLOAD_LIMIT_REACHED, "error.download_limit", "Downloadlimit erreicht", "Download limit reached";
    UPLOAD_PATH_MISSING, "error.upload_path", "Uploadpfad fehlt", "Upload path missing";
    ONE_FILE_REQUIRED, "error.one_file", "Pro Request ist genau eine Datei erforderlich", "Exactly one file is required per request";
    FILE_EXISTS_CONFIRM, "error.file_exists", "Datei existiert bereits; Ersetzen muss für diese Datei bestätigt werden", "File already exists; replacement must be confirmed for this file";
    CONFIRMATION_REQUIRED, "error.confirmation", "Bestätigung erforderlich", "Confirmation required";
    TARGET_NOT_FOUND, "error.target_not_found", "Ziel nicht gefunden", "Target not found";
    TARGET_EXISTS, "error.target_exists", "Zielname ist bereits vorhanden", "Target name already exists";
    EXACT_FOLDER_CONFIRM, "error.exact_folder", "Der exakte Ordnername muss bestätigt werden", "The exact folder name must be confirmed";
    SHARE_ACTION, "files.share_action", "Freigeben", "Share";
    RELATIVE_PATH, "files.relative_path", "Relativer Pfad", "Relative path";
    ACTIVE_LINKS, "share.active_links", "aktive Links", "active links";
    UPLOAD_FILES, "upload.files", "Dateien hochladen", "Upload files";
    TRANSFER_LIMIT_REACHED, "error.transfer_limit", "Übertragungslimit erreicht", "Transfer limit reached";
    SHARE_UNAVAILABLE, "error.share_unavailable", "Freigabe nicht verfügbar", "Share unavailable";
    FILE_NAME_MISSING, "error.file_name_missing", "Dateiname fehlt", "File name missing";
    INVALID_FILE_NAME, "error.invalid_file_name", "Ungültiger Dateiname", "Invalid file name";
    RESERVED_FILE_NAME, "error.reserved_file_name", "Dateiname ist für interne Uploadfragmente reserviert", "File name is reserved for internal upload fragments";
    BLOCKED_FILE_TYPE, "error.blocked_type", "Dateityp blockiert", "File type blocked";
    TARGET_FOLDER_UNAVAILABLE, "error.target_folder", "Zielordner nicht verfügbar", "Target folder unavailable";
    UPLOAD_ABORTED, "error.upload_aborted", "Upload abgebrochen", "Upload aborted";
    UPLOAD_TOO_LARGE, "error.upload_large", "Upload ist zu groß", "Upload is too large";
    UPLOAD_BUSY, "error.upload_busy", "Zu viele gleichzeitige Uploads", "Too many concurrent uploads";
    INSUFFICIENT_STORAGE, "error.storage", "Nicht genug freier Speicher", "Not enough free storage";
    INVALID_UPLOAD, "error.invalid_upload", "Ungültiger Upload", "Invalid upload";
    TOO_MANY_MULTIPART_FIELDS, "error.multipart_fields", "Zu viele Multipart-Felder", "Too many multipart fields";
    INVALID_UPLOAD_PATH, "error.invalid_upload_path", "Ungültiger Uploadpfad", "Invalid upload path";
    INVALID_CSRF_PROOF, "error.invalid_csrf_proof", "Ungültiger CSRF-Nachweis", "Invalid CSRF proof";
    INVALID_UPLOAD_OPTION, "error.invalid_upload_option", "Ungültige Uploadoption", "Invalid upload option";
    ONE_FILE_ALLOWED, "error.one_file_allowed", "Pro Request ist genau eine Datei erlaubt", "Exactly one file is allowed per request";
    UNKNOWN_MULTIPART_FIELD, "error.multipart_unknown", "Unbekanntes Multipart-Feld", "Unknown multipart field";
    CSRF_PROOF_MISSING, "error.csrf_proof_missing", "CSRF-Nachweis fehlt", "CSRF proof missing";
    INVALID_EXPIRY, "error.invalid_expiry", "Ungültiges Ablaufdatum", "Invalid expiration date";
    INVALID_PERMISSION, "error.invalid_permission", "Ungültige Berechtigung", "Invalid permission";
    ERROR_UPLOAD_LINK_FOLDER_ONLY, "error.upload_link_folder_only", "Uploads sind nur für Ordnerlinks erlaubt", "Uploads are available for folder links only";
    INVALID_ALIAS, "error.invalid_alias", "Ungültiger Alias", "Invalid alias";
    EXPIRY_PAST, "error.expiry_past", "Ablaufdatum liegt in der Vergangenheit", "Expiration date is in the past";
    PASSWORD_REQUIRED, "error.password_required", "Passwort und Bestätigung sind für den Passwortschutz verpflichtend", "Password and confirmation are required for password protection";
    PASSWORD_MISMATCH, "error.password_mismatch", "Passwörter stimmen nicht überein", "Passwords do not match";
    INVALID_TRANSFER_LIMIT, "error.transfer_invalid", "Ungültiges Übertragungslimit", "Invalid transfer limit";
    TRANSFER_LIMIT_MIN, "error.transfer_min", "Das Übertragungslimit muss mindestens 1 sein", "The transfer limit must be at least 1";
    INVALID_UPLOAD_LIMIT, "error.upload_limit", "Ungültiges Uploadlimit", "Invalid upload limit";
    UPLOAD_LIMIT_MIN, "error.upload_min", "Uploadlimit muss mindestens 1 Byte sein", "Upload limit must be at least 1 byte";
    TOKEN_ALIAS_EXISTS, "error.token_alias", "Token oder Alias bereits vorhanden", "Token or alias already exists";
    USERNAME_POLICY, "error.username_policy", "Benutzername muss 3-64 sichere ASCII-Zeichen enthalten", "Username must contain 3-64 safe ASCII characters";
    PASSWORD_POLICY, "error.password_policy", "Passwort muss mindestens 14 Zeichen und darf höchstens 1024 Byte enthalten", "Password must contain at least 14 characters and at most 1024 bytes";
    USERNAME_EXISTS, "error.username_exists", "Benutzername existiert bereits", "Username already exists";
    ADMIN_NOT_FOUND, "error.admin_not_found", "Admin nicht gefunden", "Admin not found";
    LAST_ADMIN, "error.last_admin", "Letzter aktiver Admin kann nicht stillgelegt werden", "The final active admin cannot be deactivated";
    PRODUCTION_HTTPS, "error.production_https", "Production public_base_url muss HTTPS verwenden", "Production public_base_url must use HTTPS";
    IP_CAPTURE_DISABLE, "error.ip_capture_disable", "IP-Erfassung muss vor dem Löschen deaktiviert werden", "IP capture must be disabled before deletion";
    EXACT_IP_CONFIRM, "error.ip_confirm", "Exakte Bestätigung IP-DATEN LÖSCHEN erforderlich", "Exact confirmation IP-DATEN LÖSCHEN required";
    SHARE_LOCKED, "error.share_locked", "Freigabe ist gesperrt", "Share is locked";
    FILE_UNAVAILABLE, "error.file_unavailable", "Datei nicht verfügbar", "File unavailable";
    PREVIEW_TOKEN_MISSING, "error.preview_token_missing", "Preview-Token fehlt", "Preview token missing";
    PREVIEW_TOKEN_INVALID, "error.preview_token_invalid", "Preview-Token ungueltig oder abgelaufen", "Preview token is invalid or expired";
    ZIP_DOWNLOAD_FORBIDDEN, "error.zip_forbidden", "ZIP-Download nicht erlaubt", "ZIP download not allowed";
    INVALID_ZIP_PATH, "error.zip_path", "Ungültiger ZIP-Pfad", "Invalid ZIP path";
    DOWNLOAD_FORBIDDEN, "error.download_forbidden", "Download nicht erlaubt", "Download not allowed";
    INVALID_FILE_PATH, "error.file_path", "Ungültiger Dateipfad", "Invalid file path";
    NO_FILE, "error.no_file", "Keine Datei", "Not a file";
    UPLOAD_FORBIDDEN, "error.upload_forbidden", "Upload nicht erlaubt", "Upload not allowed";
    PREVIEW_TOO_LARGE, "error.preview_large", "Datei ist größer als das Preview-Limit.", "File exceeds the preview limit.";
    CSRF_PROOF_BEFORE_FILE, "error.csrf_before_file", "CSRF-Nachweis muss vor der Datei übermittelt werden", "CSRF proof must be submitted before the file";
    CSRF_PROOF_DUPLICATE_OR_LATE, "error.csrf_duplicate_late", "CSRF-Nachweis wurde mehrfach oder zu spät übermittelt", "CSRF proof was submitted more than once or too late";
    LINK_NO_LONGER_ACTIVE, "error.link_no_longer_active", "Dieser Link ist nicht mehr aktiv", "This link is no longer active";
    OWN_MFA_RESET_FORBIDDEN, "error.own_mfa_reset", "Eigene MFA kann hier nicht zurückgesetzt werden", "Your own MFA cannot be reset here";
    OWN_ADMIN_DEACTIVATION_FORBIDDEN, "error.own_admin_deactivation", "Eigener Admin kann nicht stillgelegt werden", "Your own administrator account cannot be deactivated";
    OWN_PASSWORD_RESET_FORBIDDEN, "error.own_password_reset", "Eigenes Passwort kann hier nicht zurückgesetzt werden", "Your own password cannot be reset here";
    SHARE_PASSWORD_POLICY, "error.share_password_policy", "Freigabepasswort entspricht nicht der Richtlinie", "Share password does not meet the policy";
    OVERWRITE_FOLDER_UPLOAD_ONLY, "error.overwrite_folder_upload", "Überschreiben ist nur für Ordnerlinks mit Uploadrecht erlaubt", "Overwrite is available only for folder shares with upload permission";
    INVALID_UPLOAD_CONFLICT, "error.upload_conflict", "Ungültige Upload-Konfliktstrategie", "Invalid upload conflict strategy";
    UPLOAD_OPTION_DUPLICATE_OR_LATE, "error.upload_option_duplicate_late", "Uploadoption wurde mehrfach oder zu spät übermittelt", "Upload option was submitted more than once or too late";
    UPLOAD_OPTION_DUPLICATE, "error.upload_option_duplicate", "Uploadoption wurde mehrfach übermittelt", "Upload option was submitted more than once";
    UPLOAD_PATH_BEFORE_FILE, "error.upload_path_before_file", "Uploadpfad muss vor der Datei übermittelt werden", "Upload path must be submitted before the file";
    UPLOAD_PATH_DUPLICATE_OR_LATE, "error.upload_path_duplicate_late", "Uploadpfad wurde mehrfach oder zu spät übermittelt", "Upload path was submitted more than once or too late";
    PREVIEW_LIMIT_REACHED, "error.preview_limit_reached", "Vorschau-Limit erreicht", "Preview limit reached";
    ZIP_CREATION_FAILED, "error.zip_creation", "ZIP-Erstellung fehlgeschlagen", "ZIP creation failed";
    ZIP_LIMIT_REACHED, "error.zip_limit_reached", "ZIP-Limit erreicht", "ZIP limit reached";
    ZIP_SOURCE_UNAVAILABLE, "error.zip_source", "ZIP-Quelle nicht verfügbar", "ZIP source unavailable";
    INVALID_ZIP_LIMIT, "error.invalid_zip_limit", "Ungültiges ZIP-Limit", "Invalid ZIP limit";
    INVALID_PREVIEW_LIMIT, "error.invalid_preview_limit", "Ungültiges Preview-Limit", "Invalid preview limit";
    INVALID_MEDIA_PREVIEW_LIMIT, "error.invalid_media_preview_limit", "Ungültiges Media-Preview-Limit", "Invalid media preview limit";
    FILE_ALREADY_EXISTS, "error.file_already_exists", "Datei existiert bereits.", "File already exists.";
    FILE_MISSING, "error.file_missing", "Datei fehlt", "File is missing";
}

pub fn text(locale: Locale, key: MessageKey) -> &'static str {
    let entry = CATALOG
        .iter()
        .find(|entry| entry.key == key)
        .unwrap_or_else(|| panic!("unknown translation key: {}", key.id()));
    match locale {
        Locale::De => entry.de,
        Locale::En => entry.en,
    }
}

pub fn text_from_german(locale: Locale, source: &str) -> String {
    CATALOG
        .iter()
        .find(|entry| entry.de == source)
        .map(|entry| match locale {
            Locale::De => entry.de,
            Locale::En => entry.en,
        })
        .unwrap_or(source)
        .to_string()
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
        let entry = CATALOG
            .iter()
            .find(|entry| entry.key.id() == key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cookie_wins_over_accept_language() {
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
    }

    #[test]
    fn accept_language_honors_quality_and_region() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de-AT;q=0.4, en-GB;q=0.9"),
        );
        assert_eq!(Locale::resolve(&headers), Locale::En);
    }

    #[test]
    fn unsupported_or_missing_language_falls_back_to_english() {
        assert_eq!(Locale::resolve(&HeaderMap::new()), Locale::En);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("fr, it;q=0.8"),
        );
        assert_eq!(Locale::resolve(&headers), Locale::En);
    }

    #[test]
    fn invalid_quality_does_not_hide_later_supported_languages() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("de;q=broken, en;q=0.8"),
        );
        assert_eq!(Locale::resolve(&headers), Locale::En);
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
