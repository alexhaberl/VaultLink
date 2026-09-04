struct SetupResult {
    totp_secret: SecretString,
    otpauth: SecretString,
}

fn one_time_otpauth(username: &str, secret: &SecretString) -> SecretString {
    SecretString::new(format!(
        "otpauth://totp/VaultLink:{username}?secret={}&issuer=VaultLink",
        secret.expose_secret()
    ))
}

enum SetupStorageValidation {
    Capabilities(storage_mount::ValidatedStorage),
    #[cfg(test)]
    TestBypass,
}

async fn build_and_store(config_path: &Path, form: SetupForm) -> Result<SetupResult, String> {
    build_and_store_with_mount_validator(config_path, form, |storage| {
        storage_mount::validate_and_open(storage)
            .map(SetupStorageValidation::Capabilities)
            .map_err(|error| error.to_string())
    })
    .await
}

struct PreparedSetup {
    config: Config,
    admin_username: String,
    admin_password: SecretString,
}

fn validate_setup_credentials(form: &SetupForm) -> Result<(), String> {
    if !form
        .admin_password
        .matches_confirmation(&form.admin_password_confirm)
    {
        return Err(i18n::text(i18n::current_locale(), i18n::PASSWORD_MISMATCH).into());
    }
    if !auth::valid_admin_password(form.admin_password.expose_secret()) {
        return Err(i18n::text(i18n::current_locale(), i18n::PASSWORD_POLICY).into());
    }
    if !auth::valid_admin_username(&form.admin_username) {
        return Err(i18n::text(i18n::current_locale(), i18n::USERNAME_POLICY).into());
    }
    Ok(())
}

fn parse_setup_form(form: SetupForm) -> Result<PreparedSetup, String> {
    validate_setup_credentials(&form)?;
    // Confirmation is needed only for the comparison above. Drop it before
    // parsing configuration and performing storage I/O.
    drop(form.admin_password_confirm);
    let mode = match form.server_mode.as_str() {
        "development" => ServerMode::Development,
        "reverse_proxy" => ServerMode::ReverseProxy,
        "standalone_tls" => ServerMode::StandaloneTls,
        _ => {
            return Err(i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_SERVER_MODE).into())
        }
    };
    let standalone_tls = matches!(mode, ServerMode::StandaloneTls);
    let reverse_proxy_mode = matches!(mode, ServerMode::ReverseProxy);
    let production_mode = !matches!(mode, ServerMode::Development);
    let external_writers = form.external_writers.is_some();
    let allow_external_writer_replace = form.allow_external_writer_replace.is_some();
    let require_mount = production_mode || form.require_mount.is_some() || external_writers;
    let optional_mount_value = |value: String| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    };
    let internal_directory = optional_mount_value(form.internal_directory).map(PathBuf::from);
    let expected_filesystem_type = optional_mount_value(form.expected_filesystem_type);
    let expected_mount_source = optional_mount_value(form.expected_mount_source);
    let certificate_source = match form.certificate_source.as_str() {
        "files" => CertificateSource::Files,
        "letsencrypt" => CertificateSource::LetsEncrypt,
        _ => {
            return Err(i18n::text(
                i18n::current_locale(),
                i18n::SETUP_INVALID_CERTIFICATE_SOURCE,
            )
            .into())
        }
    };
    let invalid_extensions =
        || i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_EXTENSIONS).to_string();
    let preview_extensions = runtime::parse_extension_list(&form.preview_extensions)
        .map_err(|_| invalid_extensions())?;
    let image_preview_extensions = runtime::parse_extension_list(&form.image_preview_extensions)
        .map_err(|_| invalid_extensions())?;
    let blocked_extensions = runtime::parse_extension_list(&form.blocked_extensions)
        .map_err(|_| invalid_extensions())?;
    let trusted_proxies = form
        .trusted_proxies
        .split([',', '\n', '\r', ' ', '\t'])
        .filter_map(|value| {
            let value = value.trim();
            (!value.is_empty()).then_some(value.parse())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_TRUSTED_PROXIES).to_string()
        })?;
    let config = Config {
        server: Server {
            mode,
            listen_address: form.listen_address,
            public_base_url: form.public_base_url,
            production_mode,
        },
        storage: Storage {
            root_mount_path: form.root_mount_path.into(),
            data_directory: form.data_directory.into(),
            internal_directory,
            require_mount,
            external_writers,
            allow_external_writer_replace,
            expected_filesystem_type,
            expected_mount_source,
            max_upload_size: parse_unit_to_bytes(
                "max_upload_size_mb",
                &form.max_upload_size_mb,
                MB,
            )?,
            max_zip_size: parse_unit_to_bytes("max_zip_size_gb", &form.max_zip_size_gb, GB)?,
            max_zip_files: parse_usize("max_zip_files", &form.max_zip_files)?,
            max_search_entries: parse_usize("max_search_entries", &form.max_search_entries)?,
            max_search_results: parse_usize("max_search_results", &form.max_search_results)?,
            max_preview_size: parse_unit_to_bytes(
                "max_preview_size_mb",
                &form.max_preview_size_mb,
                MB,
            )?,
            preview_extensions,
            image_preview_extensions,
            pdf_preview_enabled: form.pdf_preview_enabled.is_some(),
            max_media_preview_size: parse_unit_to_bytes(
                "max_media_preview_size_mb",
                &form.max_media_preview_size_mb,
                MB,
            )?,
            blocked_extensions,
        },
        reverse_proxy: ReverseProxy {
            enabled: reverse_proxy_mode,
            allow_non_loopback: false,
            trusted_proxies,
            trust_x_forwarded_headers: reverse_proxy_mode,
        },
        tls: Tls {
            enabled: standalone_tls,
            certificate_source,
            cert_file: form.tls_cert_file.into(),
            key_file: form.tls_key_file.into(),
            hsts_enabled: form.hsts_enabled.is_some(),
            reload_on_cert_change: standalone_tls && form.certificate_source == "files",
            letsencrypt_contact_email: form.letsencrypt_contact_email,
            letsencrypt_cache_dir: form.letsencrypt_cache_dir.into(),
            letsencrypt_staging: form.letsencrypt_staging.is_some(),
        },
        security: Security {
            secure_cookie: production_mode,
            audit_client_ip_enabled: form.audit_client_ip_enabled.is_some(),
            ..Default::default()
        },
        admission: Admission::default(),
        logging: Logging {
            level: if form.log_level.trim().is_empty() {
                "info".into()
            } else {
                form.log_level
            },
        },
    };
    config.validate().map_err(|error| {
        format!(
            "{}: {error}",
            i18n::text(i18n::current_locale(), i18n::SETUP_INVALID_CONFIGURATION)
        )
    })?;
    Ok(PreparedSetup {
        config,
        admin_username: form.admin_username,
        admin_password: form.admin_password,
    })
}

fn open_setup_database(
    config: &Config,
    validated_storage: Option<SetupStorageValidation>,
) -> Result<(Database, std::fs::File), String> {
    if !config.storage.require_mount {
        std::fs::create_dir_all(&config.storage.root_mount_path)
            .map_err(|error| error.to_string())?;
        std::fs::create_dir_all(&config.storage.data_directory)
            .map_err(|error| error.to_string())?;
    }
    let validated_storage = match validated_storage {
        Some(SetupStorageValidation::Capabilities(validated)) => {
            validated
                .verify_path_bindings(&config.storage)
                .map_err(|error| error.to_string())?;
            Some(validated)
        }
        #[cfg(test)]
        Some(SetupStorageValidation::TestBypass) => None,
        None => Some(
            storage_mount::validate_and_open(&config.storage).map_err(|error| error.to_string())?,
        ),
    };
    let data_directory = match validated_storage.as_ref() {
        Some(validated) => validated.data_file().map_err(|error| error.to_string())?,
        #[cfg(test)]
        None => std::fs::File::open(&config.storage.data_directory)
            .map_err(|error| error.to_string())?,
        #[cfg(not(test))]
        None => unreachable!("production setup validation always returns capabilities"),
    };
    let database = Database::open_in_directory(
        data_directory
            .try_clone()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok((database, data_directory))
}

async fn build_and_store_with_mount_validator<F>(
    config_path: &Path,
    form: SetupForm,
    validate_mount: F,
) -> Result<SetupResult, String>
where
    F: FnOnce(&Storage) -> Result<SetupStorageValidation, String>,
{
    let PreparedSetup {
        config,
        admin_username,
        admin_password,
    } = parse_setup_form(form)?;
    let validated_storage = if config.storage.require_mount {
        Some(validate_mount(&config.storage)?)
    } else {
        None
    };
    let serialized = toml::to_string_pretty(&config).map_err(|error| error.to_string())?;
    let recovering_existing_config = if config_path.exists() {
        let existing = Config::load(config_path).map_err(|error| {
            let prefix = match i18n::current_locale() {
                Locale::De => "Vorhandene Konfiguration kann nicht sicher fortgesetzt werden",
                Locale::En => "Existing configuration cannot be resumed safely",
            };
            format!("{prefix}: {error}")
        })?;
        let existing_serialized =
            toml::to_string_pretty(&existing).map_err(|error| error.to_string())?;
        if existing_serialized != serialized {
            return Err(i18n::text(i18n::current_locale(), i18n::SETUP_CONFIG_EXISTS).into());
        }
        true
    } else {
        false
    };
    let submitted_password =
        recovering_existing_config.then(|| admin_password.duplicate_for_verification());
    let password = admin_password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_secret_password(&password))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let (database, data_directory) = open_setup_database(&config, validated_storage)?;
    // Keep the descriptor alive for every pending-marker operation that uses
    // its procfs capability path. Dropping it here would make the path stale.
    let data_directory_path =
        PathBuf::from(format!("/proc/self/fd/{}", data_directory.as_raw_fd()));
    if database.admin_count().map_err(|error| error.to_string())? != 0 {
        if recovering_existing_config
            && read_initial_setup_pending(&data_directory_path)?.as_deref()
                == Some(admin_username.as_str())
        {
            let admin = database
                .admin(&admin_username)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    i18n::text(i18n::current_locale(), i18n::SETUP_RECOVERY_UNAVAILABLE).to_string()
                })?;
            let password_hash = admin.password_hash;
            let submitted_password = submitted_password
                .expect("recovering an existing setup retains one verification copy");
            let password_valid = tokio::task::spawn_blocking(move || {
                auth::verify_secret_password(&password_hash, &submitted_password)
            })
            .await
            .map_err(|error| error.to_string())?;
            if !password_valid {
                return Err(
                    i18n::text(i18n::current_locale(), i18n::SETUP_RECOVERY_UNAVAILABLE).into(),
                );
            }
            let totp_secret = admin.totp_secret;
            let otpauth = one_time_otpauth(&admin_username, &totp_secret);
            return Ok(SetupResult {
                totp_secret,
                otpauth,
            });
        }
        return Err(i18n::text(i18n::current_locale(), i18n::SETUP_INITIAL_ADMIN_EXISTS).into());
    }
    let totp_secret = auth::new_totp_secret_value();
    let wrote_config = if recovering_existing_config {
        false
    } else {
        write_config_atomic_new(config_path, &serialized).map_err(|error| error.to_string())?;
        true
    };
    if let Err(error) = ensure_initial_setup_pending(&data_directory_path, &admin_username) {
        if wrote_config {
            let _ = std::fs::remove_file(config_path);
            let _ = sync_parent(config_path);
        }
        return Err(error);
    }
    match database.create_initial_admin_and_audit(
        &admin_username,
        &hash,
        totp_secret.expose_secret(),
        &AuditContext::new("setup", None),
    ) {
        Ok(InitialAdminOutcome::Created) => {}
        Ok(InitialAdminOutcome::AlreadyInitialized) => {
            return Err(
                i18n::text(i18n::current_locale(), i18n::SETUP_INITIAL_ADMIN_EXISTS).into(),
            );
        }
        Err(error) => {
            if wrote_config {
                let _ = std::fs::remove_file(config_path);
                let _ = sync_parent(config_path);
            }
            return Err(error.to_string());
        }
    }
    let response_totp_secret = totp_secret.duplicate_for_one_time_response();
    drop(totp_secret);
    let otpauth = one_time_otpauth(&admin_username, &response_totp_secret);
    Ok(SetupResult {
        totp_secret: response_totp_secret,
        otpauth,
    })
}

fn initial_setup_pending_path(data_directory: &Path) -> PathBuf {
    data_directory.join(INITIAL_SETUP_PENDING_FILE)
}

fn read_initial_setup_pending(data_directory: &Path) -> Result<Option<String>, String> {
    let path = initial_setup_pending_path(data_directory);
    match std::fs::read_to_string(path) {
        Ok(username) => Ok(Some(username.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_initial_setup_pending(data_directory: &Path, username: &str) -> Result<(), String> {
    if let Some(existing) = read_initial_setup_pending(data_directory)? {
        return if existing == username {
            Ok(())
        } else {
            Err(i18n::text(i18n::current_locale(), i18n::SETUP_PENDING_OTHER_ADMIN).into())
        };
    }
    let path = initial_setup_pending_path(data_directory);
    write_config_atomic_new(&path, &format!("{username}\n")).map_err(|error| error.to_string())
}

fn clear_initial_setup_pending(data_directory: &Path) -> Result<(), String> {
    let path = initial_setup_pending_path(data_directory);
    match std::fs::remove_file(&path) {
        Ok(()) => sync_parent(&path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn clear_initial_setup_pending_for_storage(storage: &Storage) -> Result<(), String> {
    let validated = storage_mount::validate_and_open(storage).map_err(|error| error.to_string())?;
    validated
        .verify_path_bindings(storage)
        .map_err(|error| error.to_string())?;
    let data_directory = validated.data_file().map_err(|error| error.to_string())?;
    let data_directory_path =
        PathBuf::from(format!("/proc/self/fd/{}", data_directory.as_raw_fd()));
    clear_initial_setup_pending(&data_directory_path)
}

fn write_config_atomic_new(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn parse_unit_to_bytes(name: &str, value: &str, unit: u64) -> Result<u64, String> {
    let value = value
        .trim()
        .parse::<u64>()
        .map_err(|_| match i18n::current_locale() {
            Locale::De => format!("{name} muss eine positive ganze Zahl sein."),
            Locale::En => format!("{name} must be a positive integer."),
        })?;
    value
        .checked_mul(unit)
        .ok_or_else(|| match i18n::current_locale() {
            Locale::De => format!("{name} ist zu groß."),
            Locale::En => format!("{name} is too large."),
        })
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| match i18n::current_locale() {
            Locale::De => format!("{name} muss eine positive Zahl sein."),
            Locale::En => format!("{name} must be a positive number."),
        })
}

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;
