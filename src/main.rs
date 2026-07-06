use std::{env, path::PathBuf};
use vaultlink::{
    auth,
    config::{Config, ServerMode},
    web, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let config_path = arg(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
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
    let addr = config.server.listen_address.parse()?;
    let app = web::router(state);
    tracing::info!(%addr,mode=?config.server.mode,"VaultLink starting");
    match config.server.mode {
        ServerMode::StandaloneTls => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &config.tls.cert_file,
                &config.tls.key_file,
            )
            .await?;
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        _ => {
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
fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|v| v == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
