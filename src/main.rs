use futures_util::StreamExt;
use std::{env, path::PathBuf};
use vaultlink::{
    auth,
    config::{self, CertificateSource, Config, ServerMode},
    web, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let config_path = arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    if args.get(1).is_some_and(|value| value == "setup") {
        let listen = arg(&args, "--listen").unwrap_or("127.0.0.1:8090");
        let listen: std::net::SocketAddr = listen.parse()?;
        return vaultlink::setup::run(config_path, listen).await;
    }
    let config = Config::load(&config_path)?;
    let filter = tracing_subscriber::EnvFilter::try_new(&config.logging.level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let state = AppState::new(config.clone())?;
    if args.get(1).is_some_and(|v| v == "init-admin") {
        let username = arg(&args, "--username").ok_or("--username is required")?;
        if username.len() < 3
            || !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("username must be 3+ safe ASCII characters".into());
        }
        let password = rpassword::prompt_password("New admin password: ")?;
        if password.len() < 14 {
            return Err("password must contain at least 14 characters".into());
        }
        let confirm = rpassword::prompt_password("Confirm password: ")?;
        if password != confirm {
            return Err("passwords do not match".into());
        }
        let secret = auth::new_totp_secret();
        let hash = auth::hash_password(&password)
            .map_err(|error| std::io::Error::other(format!("password hashing failed: {error}")))?;
        state.db.create_admin(username, &hash, &secret)?;
        println!("Admin created. Add this secret to the authenticator exactly once:\n{secret}\notpauth://totp/VaultLink:{username}?secret={secret}&issuer=VaultLink");
        return Ok(());
    }
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
                #[cfg(unix)]
                install_sighup_handler_for_files(&config, tls.clone());
                axum_server::bind_rustls(addr, tls)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await?;
            }
            CertificateSource::LetsEncrypt => {
                #[cfg(unix)]
                install_noop_sighup_handler("ACME manages certificate renewal internally");
                let public_url = url::Url::parse(&config.server.public_base_url)?;
                let domain = public_url
                    .host_str()
                    .ok_or("public_base_url must contain a DNS host")?
                    .to_string();
                let cache_dir = config::letsencrypt_cache_dir(&config.storage, &config.tls)?;
                std::fs::create_dir_all(&cache_dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700))?;
                }
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
                axum_server::bind(addr)
                    .acceptor(acceptor)
                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .await?;
            }
        },
        _ => {
            #[cfg(unix)]
            install_noop_sighup_handler("no reloadable TLS configuration in this mode");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(unix)]
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

#[cfg(unix)]
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
