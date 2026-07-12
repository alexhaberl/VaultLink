use futures_util::StreamExt;
use serde::Deserialize;
use std::{env, path::PathBuf};
use vaultlink::{
    auth,
    config::{self, CertificateSource, Config, ServerMode},
    db::{AdminRecoveryOutcome, Database, InitialAdminOutcome},
    storage_mount, web, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|value| value == "--version") {
        if args.len() != 2 {
            return Err("--version does not accept additional arguments".into());
        }
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.get(1).is_some_and(|value| value == "recover-admin") {
        let options = RecoverAdminOptions::parse(&args).map_err(std::io::Error::other)?;
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .init();
        return recover_admin(&options);
    }
    let mode = command_mode(&args).map_err(std::io::Error::other)?;
    let config_path = arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    if mode == CommandMode::Setup {
        let listen = arg(&args, "--listen").unwrap_or("127.0.0.1:8090");
        let listen: std::net::SocketAddr = listen.parse()?;
        if !vaultlink::setup::run(config_path.clone(), listen).await? {
            return Ok(());
        }
    }
    let config = Config::load(&config_path)?;
    if mode == CommandMode::ReadinessTarget {
        let target = config.local_readiness_target()?;
        println!("{}", target.url);
        println!("{}", target.connect_to.as_deref().unwrap_or("-"));
        println!("{}", u8::from(target.insecure));
        return Ok(());
    }
    let filter = tracing_subscriber::EnvFilter::try_new(&config.logging.level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if mode == CommandMode::InitAdmin {
        return init_admin(&config, &args);
    }
    let state = AppState::new(config.clone())?;
    start_upload_fragment_cleanup(&state);
    let addr: std::net::SocketAddr = config.server.listen_address.parse()?;
    let app = web::router(state);
    tracing::info!(%addr,mode=?config.server.mode,"VaultLink starting");
    match config.server.mode {
        ServerMode::StandaloneTls => match config.tls.certificate_source {
            CertificateSource::Files => {
                let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &config.tls.cert_file,
                    &config.tls.key_file,
                )
                .await?;
                install_sighup_handler_for_files(&config, tls.clone());
                let handle = axum_server::Handle::new();
                install_server_shutdown(handle.clone());
                axum_server::bind_rustls(addr, tls)
                    .handle(handle)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await?;
            }
            CertificateSource::LetsEncrypt => {
                install_noop_sighup_handler("ACME manages certificate renewal internally");
                let public_url = url::Url::parse(&config.server.public_base_url)?;
                let domain = public_url
                    .host_str()
                    .ok_or("public_base_url must contain a DNS host")?
                    .to_string();
                let cache_dir = config::letsencrypt_cache_dir(&config.storage, &config.tls)?;
                std::fs::create_dir_all(&cache_dir)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700))?;
                let contact = format!("mailto:{}", config.tls.letsencrypt_contact_email);
                let mut acme_state = rustls_acme::AcmeConfig::new([domain.clone()])
                    .contact_push(contact)
                    .cache(rustls_acme::caches::DirCache::new(cache_dir))
                    .directory_lets_encrypt(!config.tls.letsencrypt_staging)
                    .state();
                let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());
                tokio::spawn(async move {
                    while let Some(event) = acme_state.next().await {
                        match event {
                            Ok(event) => tracing::info!(?event, "ACME event"),
                            Err(error) => tracing::error!(?error, "ACME error"),
                        }
                    }
                });
                tracing::info!(
                    %domain,
                    staging = config.tls.letsencrypt_staging,
                    "Standalone TLS uses Let's Encrypt ACME tls-alpn-01"
                );
                let handle = axum_server::Handle::new();
                install_server_shutdown(handle.clone());
                axum_server::bind(addr)
                    .acceptor(acceptor)
                    .handle(handle)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await?;
            }
        },
        _ => {
            install_noop_sighup_handler("no reloadable TLS configuration in this mode");
            let handle = axum_server::Handle::new();
            install_server_shutdown(handle.clone());
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandMode {
    Serve,
    Setup,
    InitAdmin,
    ReadinessTarget,
}

fn command_mode(args: &[String]) -> Result<CommandMode, String> {
    match args.get(1).map(String::as_str) {
        None => Ok(CommandMode::Serve),
        Some("--config") => {
            validate_value_options(args, 1, &["--config"])?;
            Ok(CommandMode::Serve)
        }
        Some("setup") => {
            validate_value_options(args, 2, &["--config", "--listen"])?;
            Ok(CommandMode::Setup)
        }
        Some("init-admin") => {
            validate_value_options(args, 2, &["--config", "--username"])?;
            Ok(CommandMode::InitAdmin)
        }
        Some("readiness-target") => {
            validate_value_options(args, 2, &["--config"])?;
            Ok(CommandMode::ReadinessTarget)
        }
        Some(option) if option.starts_with('-') => {
            Err(format!("unknown VaultLink option: {option}"))
        }
        Some(command) => Err(format!("unknown VaultLink command: {command}")),
    }
}

fn validate_value_options(args: &[String], start: usize, allowed: &[&str]) -> Result<(), String> {
    let mut seen = Vec::new();
    let mut index = start;
    while index < args.len() {
        let option = args[index].as_str();
        if !option.starts_with('-') {
            return Err(format!("unexpected positional argument: {option}"));
        }
        if !allowed.contains(&option) {
            return Err(format!("unknown option: {option}"));
        }
        if seen.contains(&option) {
            return Err(format!("{option} may only be provided once"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires one non-option value"))?;
        if value.is_empty() || value.starts_with('-') {
            return Err(format!("{option} requires one non-option value"));
        }
        seen.push(option);
        index += 2;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecoveryDatabaseSource {
    Config(PathBuf),
    Database(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverAdminOptions {
    source: RecoveryDatabaseSource,
    username: String,
    reset_password: bool,
    reset_mfa: bool,
}

impl RecoverAdminOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("recover-admin") {
            return Err("recover-admin parser requires the recover-admin command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut username = None;
        let mut reset_password = false;
        let mut reset_mfa = false;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            match option {
                "--config" | "--database" | "--username" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| format!("{option} requires one non-option value"))?;
                    if value.is_empty() || value.starts_with('-') {
                        return Err(format!("{option} requires one non-option value"));
                    }
                    let duplicate = match option {
                        "--config" => config_path.replace(PathBuf::from(value)).is_some(),
                        "--database" => database_path.replace(PathBuf::from(value)).is_some(),
                        "--username" => username.replace(value.clone()).is_some(),
                        _ => unreachable!(),
                    };
                    if duplicate {
                        return Err(format!("{option} may only be provided once"));
                    }
                    index += 2;
                }
                option if option.starts_with("--username=") => {
                    let value = option
                        .strip_prefix("--username=")
                        .expect("guard checked the prefix");
                    if value.is_empty() {
                        return Err("--username requires a non-empty value".into());
                    }
                    if username.replace(value.to_string()).is_some() {
                        return Err("--username may only be provided once".into());
                    }
                    index += 1;
                }
                "--reset-password" => {
                    if reset_password {
                        return Err("--reset-password may only be provided once".into());
                    }
                    reset_password = true;
                    index += 1;
                }
                "--reset-mfa" => {
                    if reset_mfa {
                        return Err("--reset-mfa may only be provided once".into());
                    }
                    reset_mfa = true;
                    index += 1;
                }
                unknown if unknown.starts_with('-') => {
                    return Err(format!("unknown recover-admin option: {unknown}"));
                }
                positional => {
                    return Err(format!(
                        "unexpected recover-admin positional argument: {positional}"
                    ));
                }
            }
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err("recover-admin requires exactly one of --config or --database".into())
            }
            (Some(_), Some(_)) => {
                return Err("recover-admin accepts only one of --config or --database".into())
            }
        };
        let username = username.ok_or_else(|| "recover-admin requires --username".to_string())?;
        if !reset_password && !reset_mfa {
            return Err("recover-admin requires --reset-password and/or --reset-mfa".into());
        }
        Ok(Self {
            source,
            username,
            reset_password,
            reset_mfa,
        })
    }
}

#[derive(Deserialize)]
struct RecoveryConfigFile {
    storage: RecoveryStorageConfig,
}

#[derive(Deserialize)]
struct RecoveryStorageConfig {
    data_directory: PathBuf,
}

fn recovery_database_path(
    source: &RecoveryDatabaseSource,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match source {
        RecoveryDatabaseSource::Database(path) => Ok(path.clone()),
        RecoveryDatabaseSource::Config(path) => {
            let serialized = std::fs::read_to_string(path)?;
            let config: RecoveryConfigFile = toml::from_str(&serialized)?;
            Ok(config.storage.data_directory.join("data.sqlite"))
        }
    }
}

fn init_admin(config: &Config, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let username = arg(args, "--username").ok_or("--username is required")?;
    validate_admin_username(username)?;
    if config.storage.require_mount {
        storage_mount::validate(&config.storage)?;
    }
    std::fs::create_dir_all(&config.storage.data_directory)?;
    let database = Database::open(config.storage.data_directory.join("data.sqlite"))?;
    if database.admin_count()? != 0 {
        return Err(
            "administrators already exist; init-admin is only available for initial setup".into(),
        );
    }
    let password = prompt_new_admin_password()?;
    let secret = auth::new_totp_secret();
    let hash = auth::hash_password(&password)
        .map_err(|error| std::io::Error::other(format!("password hashing failed: {error}")))?;
    match database.create_initial_admin(username, &hash, &secret)? {
        InitialAdminOutcome::Created => {
            println!("Administrator created. One-time credential output follows; save it now:\nSecret: {secret}\notpauth://totp/VaultLink:{username}?secret={secret}&issuer=VaultLink");
            Ok(())
        }
        InitialAdminOutcome::AlreadyInitialized => Err(
            "administrators already exist; init-admin is only available for initial setup".into(),
        ),
    }
}

fn recover_admin(options: &RecoverAdminOptions) -> Result<(), Box<dyn std::error::Error>> {
    validate_admin_username(&options.username)?;
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "VaultLink database not found at {}",
            database_path.display()
        )
        .into());
    }
    let database = Database::open(database_path)?;
    let password_hash =
        if options.reset_password {
            let password = prompt_new_admin_password()?;
            Some(auth::hash_password(&password).map_err(|error| {
                std::io::Error::other(format!("password hashing failed: {error}"))
            })?)
        } else {
            None
        };
    let totp_secret = options.reset_mfa.then(auth::new_totp_secret);
    match database.recover_admin(
        &options.username,
        password_hash.as_deref(),
        totp_secret.as_deref(),
    )? {
        AdminRecoveryOutcome::NotFound => {
            Err(format!("administrator not found: {}", options.username).into())
        }
        AdminRecoveryOutcome::Recovered {
            admin_id,
            username,
            active,
        } => {
            println!(
                "Administrator recovered: {username} (id {admin_id}). All sessions were revoked."
            );
            if !active {
                println!("Warning: this administrator remains inactive.");
            }
            if let Some(secret) = totp_secret {
                println!("One-time credential output follows; save it now:\nSecret: {secret}\notpauth://totp/VaultLink:{username}?secret={secret}&issuer=VaultLink");
            }
            Ok(())
        }
    }
}

fn validate_admin_username(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    if username.len() < 3
        || username.len() > 64
        || !username.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
    {
        return Err("username must contain 3-64 safe ASCII characters".into());
    }
    Ok(())
}

fn prompt_new_admin_password() -> Result<String, Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("New admin password: ")?;
    validate_admin_password(&password)?;
    let confirmation = rpassword::prompt_password("Confirm password: ")?;
    if password != confirmation {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

fn validate_admin_password(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 14 {
        return Err("password must contain at least 14 characters");
    }
    Ok(())
}

fn start_upload_fragment_cleanup(state: &AppState) {
    const CLEANUP_BATCH_ENTRIES: usize = 4096;

    let secure_root = state.secure_root.clone();
    let cleanup_lock = state.storage_cleanup.clone();
    let mut cleanup = match secure_root.start_upload_fragment_cleanup() {
        Ok(cleanup) => cleanup,
        Err(error) => {
            tracing::warn!(%error, "could not start stale upload fragment cleanup");
            return;
        }
    };
    tokio::spawn(async move {
        let mut cleanup_guard = Some(cleanup_lock.lock().await);
        let mut scanned = 0usize;
        let mut removed = 0usize;
        let mut failed = 0usize;
        loop {
            let result = tokio::task::spawn_blocking(move || {
                let batch = cleanup.run_batch(CLEANUP_BATCH_ENTRIES);
                (cleanup, batch)
            })
            .await;
            let (next_cleanup, batch) = match result {
                Ok(result) => result,
                Err(error) => {
                    tracing::warn!(%error, "stale upload fragment cleanup task failed");
                    return;
                }
            };
            cleanup = next_cleanup;
            let batch = match batch {
                Ok(batch) => batch,
                Err(error) => {
                    tracing::warn!(%error, "could not continue stale upload fragment cleanup");
                    return;
                }
            };
            scanned = scanned.saturating_add(batch.scanned);
            removed = removed.saturating_add(batch.removed);
            failed = failed.saturating_add(batch.failed);
            if batch.complete {
                if removed > 0 || failed > 0 {
                    tracing::info!(
                        scanned,
                        removed,
                        failed,
                        "stale upload fragment cleanup completed"
                    );
                }
                if failed == 0 {
                    return;
                }
                cleanup_guard.take();
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                cleanup_guard = Some(cleanup_lock.lock().await);
                let restart_root = secure_root.clone();
                cleanup = match tokio::task::spawn_blocking(move || {
                    restart_root.start_upload_fragment_cleanup()
                })
                .await
                {
                    Ok(Ok(cleanup)) => cleanup,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "could not restart stale storage cleanup");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "stale storage cleanup restart failed");
                        return;
                    }
                };
                scanned = 0;
                removed = 0;
                failed = 0;
                continue;
            }
            tokio::task::yield_now().await;
        }
    });
}

fn install_server_shutdown(handle: axum_server::Handle<std::net::SocketAddr>) {
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining active connections");
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(25)));
    });
}

async fn shutdown_signal() {
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "cannot install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

fn install_sighup_handler_for_files(config: &Config, tls: axum_server::tls_rustls::RustlsConfig) {
    if !config.tls.reload_on_cert_change {
        install_noop_sighup_handler("reload_on_cert_change is disabled");
        return;
    }
    let cert_file = config.tls.cert_file.clone();
    let key_file = config.tls.key_file.clone();
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::error!("cannot install SIGHUP handler");
            return;
        };
        while signal.recv().await.is_some() {
            match tls.reload_from_pem_file(&cert_file, &key_file).await {
                Ok(()) => tracing::info!("TLS certificate reloaded after SIGHUP"),
                Err(error) => {
                    tracing::error!(%error, "TLS certificate reload failed; previous certificate remains active")
                }
            }
        }
    });
}

fn install_noop_sighup_handler(reason: &'static str) {
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            tracing::error!("cannot install SIGHUP handler");
            return;
        };
        while signal.recv().await.is_some() {
            tracing::info!(reason, "SIGHUP received; no reload action configured");
        }
    });
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn recover_admin_parser_accepts_exactly_one_database_source() {
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--username",
                "admin",
                "--reset-password",
                "--reset-mfa",
            ]))
            .unwrap(),
            RecoverAdminOptions {
                source: RecoveryDatabaseSource::Config("config.toml".into()),
                username: "admin".into(),
                reset_password: true,
                reset_mfa: true,
            }
        );
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
            ]))
            .unwrap()
            .source,
            RecoveryDatabaseSource::Database("data.sqlite".into())
        );
        assert_eq!(
            RecoverAdminOptions::parse(&arguments(&[
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username=--ops",
                "--reset-mfa",
            ]))
            .unwrap()
            .username,
            "--ops"
        );
    }

    #[test]
    fn recover_admin_parser_rejects_ambiguous_or_unknown_arguments() {
        for invalid in [
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--username",
                "admin",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "one.toml",
                "--config",
                "two.toml",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--config",
                "config.toml",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--reset-mfa",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "--unknown",
                "--reset-mfa",
            ],
            vec![
                "vaultlink",
                "recover-admin",
                "--database",
                "data.sqlite",
                "--username",
                "admin",
                "positional",
                "--reset-mfa",
            ],
        ] {
            assert!(RecoverAdminOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn command_dispatch_rejects_typos_without_breaking_config_only_server_start() {
        assert_eq!(
            command_mode(&arguments(&["vaultlink"])).unwrap(),
            CommandMode::Serve
        );
        assert_eq!(
            command_mode(&arguments(&["vaultlink", "--config", "config.toml"])).unwrap(),
            CommandMode::Serve
        );
        assert_eq!(
            command_mode(&arguments(&[
                "vaultlink",
                "setup",
                "--listen",
                "127.0.0.1:8090"
            ]))
            .unwrap(),
            CommandMode::Setup
        );
        assert!(command_mode(&arguments(&["vaultlink", "recover-adminn"])).is_err());
        assert!(command_mode(&arguments(&["vaultlink", "--unknown"])).is_err());
        assert!(command_mode(&arguments(&[
            "vaultlink",
            "--config",
            "config.toml",
            "unexpected"
        ]))
        .is_err());
    }

    #[test]
    fn recovery_config_resolution_does_not_require_runtime_tls_validity() {
        let directory = tempfile::tempdir().unwrap();
        let data_directory = directory.path().join("data");
        let config_path = directory.path().join("recovery.toml");
        let mut config = Config::load("config/development.toml").unwrap();
        config.server.mode = ServerMode::StandaloneTls;
        config.server.listen_address = "127.0.0.1:8443".into();
        config.server.public_base_url = "https://files.example.test".into();
        config.server.production_mode = true;
        config.storage.root_mount_path = directory.path().join("shared");
        config.storage.data_directory = data_directory.clone();
        config.storage.internal_directory = Some(directory.path().join(".vaultlink-internal"));
        config.storage.require_mount = true;
        config.storage.expected_filesystem_type = Some("ext4".into());
        config.storage.expected_mount_source = Some("/dev/mapper/vaultlink-test".into());
        config.security.secure_cookie = true;
        config.tls.enabled = true;
        config.tls.certificate_source = CertificateSource::Files;
        config.tls.cert_file = directory.path().join("missing-cert.pem");
        config.tls.key_file = directory.path().join("missing-key.pem");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

        assert!(Config::load(&config_path).is_err());
        assert_eq!(
            recovery_database_path(&RecoveryDatabaseSource::Config(config_path)).unwrap(),
            data_directory.join("data.sqlite")
        );
    }

    #[test]
    fn recovery_config_accepts_a_minimal_storage_section() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("minimal.toml");
        let serialized = format!(
            "[storage]\ndata_directory = '{}'\n[tls]\ncert_file = 'missing.pem'\n",
            directory.path().display()
        );
        std::fs::write(&config_path, serialized).unwrap();

        assert_eq!(
            recovery_database_path(&RecoveryDatabaseSource::Config(config_path)).unwrap(),
            directory.path().join("data.sqlite")
        );
    }

    #[test]
    fn admin_password_minimum_counts_characters_instead_of_bytes() {
        assert!(validate_admin_password("äääääääääääää").is_err());
        assert!(validate_admin_password("ääääääääääääää").is_ok());
    }
}
