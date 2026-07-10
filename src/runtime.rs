use crate::config::Config;

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeSettings {
    pub public_base_url: String,
    pub max_upload_size: u64,
    pub blocked_extensions: Vec<String>,
    pub share_password_min_length: usize,
    pub share_password_max_length: usize,
    pub share_unlock_minutes: i64,
    pub max_zip_size: u64,
    pub max_zip_files: usize,
    pub max_search_entries: usize,
    pub max_search_results: usize,
    pub max_preview_size: u64,
    pub preview_extensions: Vec<String>,
    pub image_preview_extensions: Vec<String>,
    pub pdf_preview_enabled: bool,
    pub max_media_preview_size: u64,
    pub audit_client_ip_enabled: bool,
}

impl RuntimeSettings {
    pub fn changed_keys(&self, other: &Self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        macro_rules! changed {
            ($field:ident) => {
                if self.$field != other.$field {
                    keys.push(stringify!($field));
                }
            };
        }
        changed!(public_base_url);
        changed!(max_upload_size);
        changed!(blocked_extensions);
        changed!(share_password_min_length);
        changed!(share_password_max_length);
        changed!(share_unlock_minutes);
        changed!(max_zip_size);
        changed!(max_zip_files);
        changed!(max_search_entries);
        changed!(max_search_results);
        changed!(max_preview_size);
        changed!(preview_extensions);
        changed!(image_preview_extensions);
        changed!(pdf_preview_enabled);
        changed!(max_media_preview_size);
        changed!(audit_client_ip_enabled);
        keys
    }

    pub fn from_config(config: &Config) -> Self {
        Self {
            public_base_url: config.server.public_base_url.clone(),
            max_upload_size: config.storage.max_upload_size,
            blocked_extensions: normalize_extensions(&config.storage.blocked_extensions),
            share_password_min_length: config.security.share_password_min_length,
            share_password_max_length: config.security.share_password_max_bytes,
            share_unlock_minutes: config.security.share_unlock_minutes,
            max_zip_size: config.storage.max_zip_size,
            max_zip_files: config.storage.max_zip_files,
            max_search_entries: config.storage.max_search_entries,
            max_search_results: config.storage.max_search_results,
            max_preview_size: config.storage.max_preview_size,
            preview_extensions: normalize_extensions(&config.storage.preview_extensions),
            image_preview_extensions: normalize_extensions(
                &config.storage.image_preview_extensions,
            ),
            pdf_preview_enabled: config.storage.pdf_preview_enabled,
            max_media_preview_size: config.storage.max_media_preview_size,
            audit_client_ip_enabled: config.security.audit_client_ip_enabled,
        }
    }

    pub fn apply(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.apply_many(std::iter::once((key, value)))
    }

    fn apply_field(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "public_base_url" => {
                let value = value.trim().trim_end_matches('/').to_string();
                if value.is_empty() || url::Url::parse(&value).is_err() {
                    return Err("public_base_url must be a valid absolute URL".into());
                }
                self.public_base_url = value;
            }
            "max_upload_size" => self.max_upload_size = parse_u64(key, value)?,
            "blocked_extensions" => {
                self.blocked_extensions = parse_extension_list(value)?;
            }
            "share_password_min_length" => {
                self.share_password_min_length = parse_usize(key, value)?;
            }
            "share_password_max_length" | "share_password_max_bytes" => {
                self.share_password_max_length = parse_usize(key, value)?;
            }
            "share_unlock_minutes" => {
                self.share_unlock_minutes = parse_i64(key, value)?;
            }
            "max_zip_size" => self.max_zip_size = parse_u64(key, value)?,
            "max_zip_files" => self.max_zip_files = parse_usize(key, value)?,
            "max_search_entries" => self.max_search_entries = parse_usize(key, value)?,
            "max_search_results" => self.max_search_results = parse_usize(key, value)?,
            "max_preview_size" => self.max_preview_size = parse_u64(key, value)?,
            "preview_extensions" => {
                let extensions = parse_extension_list(value)?;
                if extensions.is_empty() {
                    return Err("preview_extensions must not be empty".into());
                }
                self.preview_extensions = extensions;
            }
            "image_preview_extensions" => {
                self.image_preview_extensions = parse_extension_list(value)?;
            }
            "pdf_preview_enabled" => self.pdf_preview_enabled = parse_bool(key, value)?,
            "max_media_preview_size" => self.max_media_preview_size = parse_u64(key, value)?,
            "audit_client_ip_enabled" => {
                self.audit_client_ip_enabled = parse_bool(key, value)?;
            }
            _ => return Err(format!("unknown runtime setting: {key}")),
        }
        Ok(())
    }

    pub fn apply_many<'a>(
        &mut self,
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<(), String> {
        let mut next = self.clone();
        for (key, value) in entries {
            next.apply_field(key, value)?;
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        let raw_public_base_url = self.public_base_url.trim();
        if !raw_public_base_url.starts_with("http://")
            && !raw_public_base_url.starts_with("https://")
        {
            return Err("public_base_url must use canonical HTTP(S) authority syntax".into());
        }
        let public_base_url = url::Url::parse(raw_public_base_url)
            .map_err(|_| "public_base_url must be a valid absolute URL".to_string())?;
        if !matches!(public_base_url.scheme(), "http" | "https")
            || public_base_url.host_str().is_none()
            || public_base_url.query().is_some()
            || public_base_url.fragment().is_some()
            || !public_base_url.username().is_empty()
            || public_base_url.password().is_some()
        {
            return Err(
                "public_base_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
                    .into(),
            );
        }
        if self.max_upload_size == 0
            || self.max_zip_size == 0
            || self.max_zip_files == 0
            || self.max_search_entries == 0
            || self.max_search_results == 0
            || self.max_preview_size == 0
            || self.max_media_preview_size == 0
        {
            return Err("runtime limits must be positive".into());
        }
        if self.share_password_min_length < 8
            || self.share_password_max_length < self.share_password_min_length
            || self.share_unlock_minutes <= 0
        {
            return Err("invalid share password policy".into());
        }
        validate_extensions(&self.blocked_extensions)?;
        validate_extensions(&self.preview_extensions)?;
        validate_extensions(&self.image_preview_extensions)?;
        if self.preview_extensions.is_empty() {
            return Err("preview_extensions must not be empty".into());
        }
        if self.image_preview_extensions.iter().any(|extension| {
            matches!(
                extension
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
                    .as_str(),
                "svg" | "html" | "htm" | "xml" | "xhtml"
            )
        }) {
            return Err("image_preview_extensions must not include active content types".into());
        }
        Ok(())
    }

    pub fn validate_for_config(&self, config: &Config) -> Result<(), String> {
        self.validate()?;
        if config.server.production_mode
            && url::Url::parse(&self.public_base_url)
                .ok()
                .is_none_or(|url| url.scheme() != "https")
        {
            return Err("production public_base_url must use HTTPS".into());
        }
        Ok(())
    }

    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("public_base_url", self.public_base_url.clone()),
            ("max_upload_size", self.max_upload_size.to_string()),
            ("blocked_extensions", self.blocked_extensions.join(",")),
            (
                "share_password_min_length",
                self.share_password_min_length.to_string(),
            ),
            (
                "share_password_max_length",
                self.share_password_max_length.to_string(),
            ),
            (
                "share_unlock_minutes",
                self.share_unlock_minutes.to_string(),
            ),
            ("max_zip_size", self.max_zip_size.to_string()),
            ("max_zip_files", self.max_zip_files.to_string()),
            ("max_search_entries", self.max_search_entries.to_string()),
            ("max_search_results", self.max_search_results.to_string()),
            ("max_preview_size", self.max_preview_size.to_string()),
            ("preview_extensions", self.preview_extensions.join(",")),
            (
                "image_preview_extensions",
                self.image_preview_extensions.join(","),
            ),
            ("pdf_preview_enabled", self.pdf_preview_enabled.to_string()),
            (
                "max_media_preview_size",
                self.max_media_preview_size.to_string(),
            ),
            (
                "audit_client_ip_enabled",
                self.audit_client_ip_enabled.to_string(),
            ),
        ]
    }
}

fn parse_u64(key: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{key} must be an unsigned integer"))
}

fn parse_usize(key: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("{key} must be an unsigned integer"))
}

fn parse_i64(key: &str, value: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("{key} must be an integer"))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("{key} must be a boolean")),
    }
}

pub fn parse_extension_list(value: &str) -> Result<Vec<String>, String> {
    let extensions = value
        .split([',', '\n', '\r', ' ', '\t'])
        .filter_map(|part| {
            let cleaned = part.trim().trim_start_matches('.').to_ascii_lowercase();
            (!cleaned.is_empty()).then_some(cleaned)
        })
        .collect::<Vec<_>>();
    validate_extensions(&extensions)?;
    Ok(extensions)
}

pub fn extension_is_blocked(name: &str, blocked: &[String]) -> bool {
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    blocked.iter().any(|value| {
        value
            .trim_start_matches('.')
            .eq_ignore_ascii_case(extension)
    })
}

fn normalize_extensions(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| {
            let cleaned = value.trim().trim_start_matches('.').to_ascii_lowercase();
            (!cleaned.is_empty()).then_some(cleaned)
        })
        .collect()
}

fn validate_extensions(values: &[String]) -> Result<(), String> {
    if values.iter().any(|extension| {
        extension.is_empty()
            || extension.contains('/')
            || extension.contains('\\')
            || extension.contains('\0')
            || extension.chars().any(char::is_control)
    }) {
        return Err("extensions must be safe extension names without path separators".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
    };

    fn config() -> Config {
        Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: ".".into(),
                data_directory: ".".into(),
                max_upload_size: 10,
                max_zip_size: 20,
                max_zip_files: 30,
                max_search_entries: 40,
                max_search_results: 5,
                max_preview_size: 6,
                preview_extensions: vec!["txt".into(), ".MD".into()],
                image_preview_extensions: vec!["jpg".into(), "png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1024,
                blocked_extensions: vec!["exe".into()],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security::default(),
            logging: Logging::default(),
        }
    }

    #[test]
    fn settings_overlay_validates_lists_and_numbers() {
        let mut settings = RuntimeSettings::from_config(&config());
        settings.apply("max_upload_size", "50").unwrap();
        settings
            .apply("preview_extensions", ".txt, log\njson")
            .unwrap();
        assert_eq!(settings.max_upload_size, 50);
        assert_eq!(settings.preview_extensions, ["txt", "log", "json"]);
        assert!(settings.apply("blocked_extensions", "../x").is_err());
        assert!(settings.apply("max_zip_files", "0").is_err());
        let blocked = parse_extension_list("exe,.SH").unwrap();
        assert!(extension_is_blocked("payload.ExE", &blocked));
        assert!(extension_is_blocked("script.sh", &blocked));
        assert!(!extension_is_blocked("report.pdf", &blocked));
        assert!(!settings.audit_client_ip_enabled);
        settings.apply("audit_client_ip_enabled", "true").unwrap();
        assert!(settings.audit_client_ip_enabled);
        settings.apply("audit_client_ip_enabled", "off").unwrap();
        assert!(!settings.audit_client_ip_enabled);
        let original = settings.clone();
        assert!(settings
            .apply("audit_client_ip_enabled", "sometimes")
            .is_err());
        assert_eq!(settings, original);
        assert!(settings
            .pairs()
            .contains(&("audit_client_ip_enabled", "false".to_string())));
    }

    #[test]
    fn changed_keys_reports_each_runtime_field_by_its_persisted_name() {
        let original = RuntimeSettings::from_config(&config());
        let mut changed = original.clone();
        changed.max_upload_size += 1;
        changed.blocked_extensions.push("bat".into());
        changed.audit_client_ip_enabled = true;
        assert_eq!(
            original.changed_keys(&changed),
            [
                "max_upload_size",
                "blocked_extensions",
                "audit_client_ip_enabled"
            ]
        );
        assert!(original.changed_keys(&original).is_empty());
    }

    #[test]
    fn settings_batch_validates_only_the_complete_candidate() {
        let mut settings = RuntimeSettings::from_config(&config());

        // Database rows are sorted alphabetically, so max is loaded before min.
        settings
            .apply_many([
                ("share_password_max_length", "8"),
                ("share_password_min_length", "8"),
            ])
            .unwrap();
        assert_eq!(settings.share_password_min_length, 8);
        assert_eq!(settings.share_password_max_length, 8);

        // The web form supplies min before max. Raising both must also be valid.
        settings
            .apply_many([
                ("share_password_min_length", "12"),
                ("share_password_max_length", "12"),
            ])
            .unwrap();
        assert_eq!(settings.share_password_min_length, 12);
        assert_eq!(settings.share_password_max_length, 12);
    }

    #[test]
    fn failed_settings_batch_does_not_mutate_the_original() {
        let mut settings = RuntimeSettings::from_config(&config());
        let original = settings.clone();

        assert!(settings
            .apply_many([
                ("max_upload_size", "999"),
                ("share_password_max_length", "8"),
            ])
            .is_err());
        assert_eq!(settings, original);

        assert!(settings
            .apply_many([("max_upload_size", "999"), ("max_zip_files", "invalid")])
            .is_err());
        assert_eq!(settings, original);
    }

    #[test]
    fn direct_runtime_candidates_cannot_bypass_url_validation() {
        let mut settings = RuntimeSettings::from_config(&config());
        settings.public_base_url.clear();
        assert!(settings.validate().is_err());
        settings.public_base_url = "file:///tmp/vaultlink".into();
        assert!(settings.validate().is_err());
        settings.public_base_url = "https://example.test?next=/admin".into();
        assert!(settings.validate().is_err());
        settings.public_base_url = "https://example.test/#section".into();
        assert!(settings.validate().is_err());
        settings.public_base_url = "https://user:secret@example.test".into();
        assert!(settings.validate().is_err());
        settings.public_base_url = "http:/missing-host".into();
        assert!(settings.validate().is_err());
    }
}
