fn local_readiness_peer_ip(listen_ip: IpAddr) -> IpAddr {
    match listen_ip {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let value = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&value)?;
        config.validate()?;
        Ok(config)
    }

    pub fn local_readiness_target(&self) -> Result<LocalReadinessTarget, ConfigError> {
        let listen: SocketAddr = self.server.listen_address.parse().map_err(|_| {
            ConfigError::Invalid("listen_address must be an IP socket address".into())
        })?;
        let local_ip = local_readiness_peer_ip(listen.ip());
        let local = SocketAddr::new(local_ip, listen.port());

        if self.server.mode != ServerMode::StandaloneTls {
            return Ok(LocalReadinessTarget {
                url: format!("http://{local}/api/v2/health/ready"),
                connect_to: None,
                insecure: false,
            });
        }

        let mut public_url = Url::parse(&self.server.public_base_url)
            .map_err(|error| ConfigError::Invalid(format!("public_base_url: {error}")))?;
        let public_host = public_url
            .host_str()
            .ok_or_else(|| ConfigError::Invalid("public_base_url must contain a host".into()))?
            .to_string();
        let public_port = public_url.port_or_known_default().ok_or_else(|| {
            ConfigError::Invalid("public_base_url must contain a known port".into())
        })?;
        public_url.set_path("/api/v2/health/ready");
        public_url.set_query(None);
        public_url.set_fragment(None);

        Ok(LocalReadinessTarget {
            url: public_url.to_string(),
            connect_to: Some(format!(
                "{}:{public_port}:{}:{}",
                curl_connect_host(&public_host),
                curl_connect_host(&local.ip().to_string()),
                local.port()
            )),
            insecure: true,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let url = validate_public_base_url(self)?;
        validate_server_mode(self, &url)?;
        validate_tls_security_policy(self)?;
        validate_storage_config(self)?;
        validate_security_config(self)?;
        validate_admission(&self.admission)?;
        Ok(())
    }
}

fn validate_public_base_url(config: &Config) -> Result<Url, ConfigError> {
    if !config.server.public_base_url.starts_with("http://")
        && !config.server.public_base_url.starts_with("https://")
    {
        return Err(ConfigError::Invalid(
            "public_base_url must use canonical HTTP(S) authority syntax".into(),
        ));
    }
    let url = Url::parse(&config.server.public_base_url)
        .map_err(|e| ConfigError::Invalid(format!("public_base_url: {e}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ConfigError::Invalid(
            "public_base_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
                .into(),
        ));
    }
    let authority_start = config
        .server
        .public_base_url
        .find("://")
        .map(|index| index + 3)
        .unwrap_or_default();
    if url.path() != "/" || config.server.public_base_url[authority_start..].contains(['/', '\\']) {
        return Err(ConfigError::Invalid(
            "public_base_url must use the root path and omit the trailing slash".into(),
        ));
    }
    Ok(url)
}

fn validate_server_mode(config: &Config, url: &Url) -> Result<(), ConfigError> {
    let listen: std::net::SocketAddr =
        config.server.listen_address.parse().map_err(|_| {
            ConfigError::Invalid("listen_address must be an IP socket address".into())
        })?;
    match config.server.mode {
        ServerMode::Development => {
            if config.server.production_mode {
                return Err(ConfigError::Invalid(
                    "development mode cannot be production_mode".into(),
                ));
            }
            if !listen.ip().is_loopback() {
                return Err(ConfigError::Invalid(
                    "development mode must bind to localhost".into(),
                ));
            }
            if url.scheme() != "http" {
                return Err(ConfigError::Invalid(
                    "development public_base_url must use http".into(),
                ));
            }
            if config.tls.enabled {
                return Err(ConfigError::Invalid(
                    "development mode must not enable application TLS".into(),
                ));
            }
        }
        ServerMode::ReverseProxy => {
            if !config.server.production_mode || url.scheme() != "https" {
                return Err(ConfigError::Invalid(
                    "reverse_proxy mode requires production_mode and HTTPS public_base_url".into(),
                ));
            }
            if !config.reverse_proxy.enabled || config.reverse_proxy.trusted_proxies.is_empty() {
                return Err(ConfigError::Invalid(
                    "reverse_proxy mode requires enabled=true and trusted_proxies".into(),
                ));
            }
            if !config.reverse_proxy.trust_x_forwarded_headers {
                return Err(ConfigError::Invalid(
                    "reverse_proxy mode requires trust_x_forwarded_headers=true".into(),
                ));
            }
            if !listen.ip().is_loopback() && !config.reverse_proxy.allow_non_loopback {
                return Err(ConfigError::Invalid(
                    "non-loopback reverse proxy binding requires allow_non_loopback=true".into(),
                ));
            }
            if !listen.ip().is_loopback()
                && !config
                    .reverse_proxy
                    .trusted_proxies
                    .iter()
                    .copied()
                    .map(crate::proxy::canonical_peer_ip)
                    .any(|proxy| !proxy.is_loopback())
            {
                return Err(ConfigError::Invalid(
                    "non-loopback binding requires a non-loopback trusted proxy".into(),
                ));
            }
            let readiness_peer = local_readiness_peer_ip(listen.ip());
            if !crate::proxy::is_trusted_proxy_peer(
                readiness_peer,
                &config.reverse_proxy.trusted_proxies,
            ) {
                return Err(ConfigError::Invalid(format!(
                    "reverse_proxy trusted_proxies must include the local readiness peer {readiness_peer}"
                )));
            }
            if config.tls.enabled {
                return Err(ConfigError::Invalid(
                    "reverse_proxy mode must not enable application TLS".into(),
                ));
            }
            if config.tls.certificate_source == CertificateSource::LetsEncrypt {
                return Err(ConfigError::Invalid(
                    "letsencrypt certificate_source is valid only in standalone_tls mode".into(),
                ));
            }
        }
        ServerMode::StandaloneTls => {
            if !config.server.production_mode || url.scheme() != "https" || !config.tls.enabled {
                return Err(ConfigError::Invalid(
                    "standalone_tls requires production_mode, HTTPS URL and TLS enabled".into(),
                ));
            }
            match config.tls.certificate_source {
                CertificateSource::Files => validate_tls_files(&config.tls)?,
                CertificateSource::LetsEncrypt => {
                    validate_letsencrypt(url, &config.storage, &config.tls)?
                }
            }
            if config.tls.reload_on_cert_change
                && config.tls.certificate_source != CertificateSource::Files
            {
                return Err(ConfigError::Invalid(
                    "reload_on_cert_change is valid only for certificate_source=\"files\"".into(),
                ));
            }
            if config.reverse_proxy.enabled {
                return Err(ConfigError::Invalid(
                    "standalone_tls cannot enable reverse proxy trust".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_tls_security_policy(config: &Config) -> Result<(), ConfigError> {
    if config.tls.certificate_source == CertificateSource::LetsEncrypt
        && !matches!(config.server.mode, ServerMode::StandaloneTls)
    {
        return Err(ConfigError::Invalid(
            "letsencrypt certificate_source is valid only in standalone_tls mode".into(),
        ));
    }
    if config.server.production_mode && !config.security.secure_cookie {
        return Err(ConfigError::Invalid(
            "secure_cookie is mandatory in production".into(),
        ));
    }
    if config.tls.hsts_enabled && matches!(config.server.mode, ServerMode::Development) {
        return Err(ConfigError::Invalid(
            "HSTS is invalid in development mode".into(),
        ));
    }
    if config.tls.hsts_enabled
        && config.tls.certificate_source == CertificateSource::LetsEncrypt
        && config.tls.letsencrypt_staging
    {
        return Err(ConfigError::Invalid(
            "HSTS must be disabled while letsencrypt_staging is true".into(),
        ));
    }
    if config.tls.reload_on_cert_change && !matches!(config.server.mode, ServerMode::StandaloneTls)
    {
        return Err(ConfigError::Invalid(
            "reload_on_cert_change is valid only in standalone_tls mode".into(),
        ));
    }
    Ok(())
}

fn validate_storage_config(config: &Config) -> Result<(), ConfigError> {
    if config.storage.max_upload_size == 0 {
        return Err(ConfigError::Invalid(
            "max_upload_size must be positive".into(),
        ));
    }
    if config.storage.max_upload_size > MAX_UPLOAD_SIZE {
        return Err(ConfigError::Invalid(format!(
            "max_upload_size must not exceed {MAX_UPLOAD_SIZE} bytes"
        )));
    }
    if config.storage.max_search_entries == 0
        || config.storage.max_search_results == 0
        || config.storage.max_preview_size == 0
        || config.storage.max_media_preview_size == 0
    {
        return Err(ConfigError::Invalid(
            "storage limits must be positive".into(),
        ));
    }
    if config.storage.max_preview_size > MAX_TEXT_PREVIEW_SIZE {
        return Err(ConfigError::Invalid(format!(
            "max_preview_size must not exceed {MAX_TEXT_PREVIEW_SIZE} bytes"
        )));
    }
    validate_mount_policy(&config.storage, config.server.production_mode)?;
    if config.storage.preview_extensions.is_empty() {
        return Err(ConfigError::Invalid(
            "preview_extensions must not be empty".into(),
        ));
    }
    validate_extensions("preview_extensions", &config.storage.preview_extensions)?;
    validate_extensions(
        "image_preview_extensions",
        &config.storage.image_preview_extensions,
    )?;
    if config
        .storage
        .image_preview_extensions
        .iter()
        .any(|extension| {
            matches!(
                extension
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
                    .as_str(),
                "svg" | "html" | "htm" | "xml" | "xhtml"
            )
        })
    {
        return Err(ConfigError::Invalid(
            "image_preview_extensions must not include active content types".into(),
        ));
    }
    Ok(())
}

fn validate_security_config(config: &Config) -> Result<(), ConfigError> {
    if !(1..=MAX_SESSION_HOURS).contains(&config.security.session_hours) {
        return Err(ConfigError::Invalid(format!(
            "session_hours must be between 1 and {MAX_SESSION_HOURS}"
        )));
    }
    if !(MIN_SESSION_IDLE_MINUTES..=config.security.session_hours * 60)
        .contains(&config.security.session_idle_minutes)
    {
        return Err(ConfigError::Invalid(format!(
            "session_idle_minutes must be between {MIN_SESSION_IDLE_MINUTES} and session_hours * 60"
        )));
    }
    if !(1..=MAX_AUTH_ATTEMPTS).contains(&config.security.login_attempts) {
        return Err(ConfigError::Invalid(format!(
            "login_attempts must be between 1 and {MAX_AUTH_ATTEMPTS}"
        )));
    }
    if !(1..=MAX_AUTH_ATTEMPTS).contains(&config.security.account_login_attempts) {
        return Err(ConfigError::Invalid(format!(
            "account_login_attempts must be between 1 and {MAX_AUTH_ATTEMPTS}"
        )));
    }
    if !(1..=MAX_LOGIN_WINDOW_SECONDS).contains(&config.security.login_window_seconds) {
        return Err(ConfigError::Invalid(format!(
            "login_window_seconds must be between 1 and {MAX_LOGIN_WINDOW_SECONDS}"
        )));
    }
    if config.security.share_password_min_length < 8
        || config.security.share_password_max_length < config.security.share_password_min_length
        || config.security.share_password_max_length > MAX_SHARE_PASSWORD_LENGTH
        || !(1..=MAX_SHARE_UNLOCK_MINUTES).contains(&config.security.share_unlock_minutes)
        || !(1..=MAX_AUTH_ATTEMPTS).contains(&config.security.share_password_attempts)
    {
        return Err(ConfigError::Invalid("invalid share password policy".into()));
    }
    Ok(())
}

fn validate_admission(admission: &Admission) -> Result<(), ConfigError> {
    if !(1..=MAX_PUBLIC_UPLOADS_CEILING).contains(&admission.max_public_uploads) {
        return Err(ConfigError::Invalid(format!(
            "admission.max_public_uploads must be between 1 and {MAX_PUBLIC_UPLOADS_CEILING}"
        )));
    }
    if !(1..=MAX_UPLOADS_PER_SHARE_CEILING).contains(&admission.max_uploads_per_share) {
        return Err(ConfigError::Invalid(format!(
            "admission.max_uploads_per_share must be between 1 and {MAX_UPLOADS_PER_SHARE_CEILING}"
        )));
    }
    if admission.upload_min_bytes_per_second < UPLOAD_MIN_BYTES_PER_SECOND_FLOOR {
        return Err(ConfigError::Invalid(format!(
            "admission.upload_min_bytes_per_second must be at least {UPLOAD_MIN_BYTES_PER_SECOND_FLOOR}"
        )));
    }
    if !(1..=UPLOAD_MAX_DURATION_SECONDS_CEILING).contains(&admission.upload_max_duration_seconds) {
        return Err(ConfigError::Invalid(format!(
            "admission.upload_max_duration_seconds must be between 1 and {UPLOAD_MAX_DURATION_SECONDS_CEILING}"
        )));
    }
    if !(1..=MAX_PUBLIC_STREAMS_CEILING).contains(&admission.max_public_streams) {
        return Err(ConfigError::Invalid(format!(
            "admission.max_public_streams must be between 1 and {MAX_PUBLIC_STREAMS_CEILING}"
        )));
    }
    if !(1..=MAX_STREAMS_PER_SHARE_CEILING).contains(&admission.max_streams_per_share) {
        return Err(ConfigError::Invalid(format!(
            "admission.max_streams_per_share must be between 1 and {MAX_STREAMS_PER_SHARE_CEILING}"
        )));
    }
    if admission.stream_min_bytes_per_second < STREAM_MIN_BYTES_PER_SECOND_FLOOR {
        return Err(ConfigError::Invalid(format!(
            "admission.stream_min_bytes_per_second must be at least {STREAM_MIN_BYTES_PER_SECOND_FLOOR}"
        )));
    }
    if !(1..=STREAM_MAX_DURATION_SECONDS_CEILING).contains(&admission.stream_max_duration_seconds) {
        return Err(ConfigError::Invalid(format!(
            "admission.stream_max_duration_seconds must be between 1 and {STREAM_MAX_DURATION_SECONDS_CEILING}"
        )));
    }
    Ok(())
}

impl Storage {
    pub fn replacements_allowed(&self) -> bool {
        !self.external_writers || self.allow_external_writer_replace
    }

    pub fn internal_directory_is_nested(&self) -> bool {
        self.require_mount
            && self.internal_directory.as_ref().is_some_and(|internal| {
                internal == &self.root_mount_path.join(DEFAULT_INTERNAL_DIRECTORY_NAME)
            })
    }

    pub fn forbid_user_symlinks(&self) -> bool {
        self.external_writers || self.internal_directory_is_nested()
    }
}

fn validate_mount_policy(storage: &Storage, production_mode: bool) -> Result<(), ConfigError> {
    let internal_directory = storage.internal_directory.as_deref().ok_or_else(|| {
        ConfigError::Invalid(
            "storage.internal_directory must be configured explicitly; VaultLink no longer infers a private storage boundary"
                .into(),
        )
    })?;
    if production_mode && !storage.require_mount {
        return Err(ConfigError::Invalid(
            "production_mode=true requires require_mount=true and an explicit fail-closed mount identity"
                .into(),
        ));
    }
    if storage.external_writers && !storage.require_mount {
        return Err(ConfigError::Invalid(
            "external_writers=true requires require_mount=true and an explicit mount identity"
                .into(),
        ));
    }
    if storage.allow_external_writer_replace && !storage.external_writers {
        return Err(ConfigError::Invalid(
            "allow_external_writer_replace=true requires external_writers=true".into(),
        ));
    }
    if !storage.require_mount {
        let canonical_lock_domain = storage
            .root_mount_path
            .join(DEFAULT_INTERNAL_DIRECTORY_NAME);
        if internal_directory != canonical_lock_domain {
            return Err(ConfigError::Invalid(format!(
                "internal_directory must explicitly use the canonical development lock domain {}",
                canonical_lock_domain.display()
            )));
        }
    }
    if storage.require_mount && !internal_directory.is_absolute() {
        return Err(ConfigError::Invalid(
            "require_mount=true requires an absolute internal_directory".into(),
        ));
    }
    let nested_internal = storage.internal_directory_is_nested();
    if storage.require_mount {
        let paths_overlap = internal_directory.starts_with(&storage.root_mount_path)
            || storage.root_mount_path.starts_with(internal_directory);
        if paths_overlap && !nested_internal {
            return Err(ConfigError::Invalid(
                "internal_directory must be either the canonical private sibling or the direct reserved child of a CIFS root_mount_path".into(),
            ));
        }
        if nested_internal
            && !matches!(
                storage.expected_filesystem_type.as_deref(),
                Some("cifs" | "smb3")
            )
        {
            return Err(ConfigError::Invalid(
                "an internal_directory nested below root_mount_path is supported only by the audited cifs/smb3 mount policy".into(),
            ));
        }
    }
    if !storage.require_mount {
        if storage.expected_filesystem_type.is_some() || storage.expected_mount_source.is_some() {
            return Err(ConfigError::Invalid(
                "expected_filesystem_type and expected_mount_source require require_mount=true"
                    .into(),
            ));
        }
        return Ok(());
    }

    if !storage.root_mount_path.is_absolute() || !storage.data_directory.is_absolute() {
        return Err(ConfigError::Invalid(
            "require_mount=true requires absolute root_mount_path and data_directory paths".into(),
        ));
    }
    let canonical_lock_domain = if nested_internal {
        storage
            .root_mount_path
            .join(DEFAULT_INTERNAL_DIRECTORY_NAME)
    } else {
        storage
            .root_mount_path
            .parent()
            .map(|parent| parent.join(DEFAULT_INTERNAL_DIRECTORY_NAME))
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "root_mount_path needs a parent directory for the private lock domain".into(),
                )
            })?
    };
    if internal_directory != canonical_lock_domain {
        return Err(ConfigError::Invalid(format!(
            "internal_directory must be the canonical private lock domain {} so one storage root cannot use multiple lock domains",
            canonical_lock_domain.display()
        )));
    }
    for (name, path) in [
        ("root_mount_path", storage.root_mount_path.as_path()),
        ("data_directory", storage.data_directory.as_path()),
        ("internal_directory", internal_directory),
    ] {
        if path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(ConfigError::Invalid(format!(
                "{name} must not contain '.' or '..' components when require_mount=true"
            )));
        }
    }
    if storage.data_directory.starts_with(&storage.root_mount_path) {
        return Err(ConfigError::Invalid(
            "data_directory must not be inside root_mount_path when require_mount=true".into(),
        ));
    }

    let filesystem_type = storage.expected_filesystem_type.as_deref().ok_or_else(|| {
        ConfigError::Invalid("require_mount=true requires expected_filesystem_type".into())
    })?;
    if filesystem_type.is_empty()
        || !filesystem_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ConfigError::Invalid(
            "expected_filesystem_type must be a non-empty Linux filesystem type".into(),
        ));
    }
    if storage.external_writers && !matches!(filesystem_type, "cifs" | "smb3") {
        return Err(ConfigError::Invalid(
            "external_writers=true is supported only with the audited cifs/smb3 mount policy"
                .into(),
        ));
    }

    let mount_source = storage.expected_mount_source.as_deref().ok_or_else(|| {
        ConfigError::Invalid("require_mount=true requires expected_mount_source".into())
    })?;
    if mount_source.is_empty() || mount_source.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "expected_mount_source must be non-empty and contain no control characters".into(),
        ));
    }

    Ok(())
}

fn validate_extensions(name: &str, values: &[String]) -> Result<(), ConfigError> {
    if values.iter().any(|extension| {
        extension.is_empty()
            || extension.contains('/')
            || extension.contains('\\')
            || extension.contains('\0')
            || extension.chars().any(char::is_control)
    }) {
        return Err(ConfigError::Invalid(format!(
            "{name} must contain safe extensions"
        )));
    }
    Ok(())
}
