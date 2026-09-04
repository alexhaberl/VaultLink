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

fn rotate_secrets(options: &RotateSecretsOptions) -> Result<(), Box<dyn std::error::Error>> {
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "database does not exist or is not a regular file: {}",
            database_path.display()
        )
        .into());
    }
    Database::rotate_secrets(&database_path)?;
    tracing::info!(
        database = %EscapedLogPath::new(&database_path.display()),
        "secret rotation completed"
    );
    Ok(())
}

fn revoke_all_service_tokens(
    options: &RevokeAllServiceTokensOptions,
) -> Result<usize, Box<dyn std::error::Error>> {
    let database_path = recovery_database_path(&options.source)?;
    if !database_path.is_file() {
        return Err(format!(
            "VaultLink database not found at {}",
            database_path.display()
        )
        .into());
    }
    let database = Database::open(database_path)?;
    let revoked =
        database.revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))?;
    Ok(revoked)
}

fn verify_backup_database(
    options: &VerifyBackupDatabaseOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if !options.database_path.is_file() {
        return Err(format!(
            "backup database does not exist or is not a regular file: {}",
            options.database_path.display()
        )
        .into());
    }
    Database::verify_backup(&options.database_path)?;
    println!(
        "backup database and adjacent secrets.keyring verified: {}",
        options.database_path.display()
    );
    Ok(())
}

fn init_admin(config: &Config, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let username = arg(args, "--username").ok_or("--username is required")?;
    validate_admin_username(username)?;
    if !config.storage.require_mount {
        std::fs::create_dir_all(&config.storage.data_directory)?;
    }
    let validated_storage = storage_mount::validate_and_open(&config.storage)?;
    validated_storage.verify_path_bindings(&config.storage)?;
    let database = Database::open_in_directory(validated_storage.data_file()?)?;
    if database.admin_count()? != 0 {
        return Err(
            "administrators already exist; init-admin is only available for initial setup".into(),
        );
    }
    let password = prompt_new_admin_password()?;
    let secret = Zeroizing::new(auth::new_totp_secret());
    let hash = auth::hash_password(password.as_str())
        .map_err(|error| std::io::Error::other(format!("password hashing failed: {error}")))?;
    drop(password);
    match database.create_initial_admin_and_audit(
        username,
        &hash,
        secret.as_str(),
        &AuditContext::new("local_init", None),
    )? {
        InitialAdminOutcome::Created => {
            println!(
                "Administrator created. One-time credential output follows; save it now:\nSecret: {0}\notpauth://totp/VaultLink:{username}?secret={0}&issuer=VaultLink",
                secret.as_str()
            );
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
            Some(auth::hash_password(password.as_str()).map_err(|error| {
                std::io::Error::other(format!("password hashing failed: {error}"))
            })?)
        } else {
            None
        };
    let totp_secret = options
        .reset_mfa
        .then(|| Zeroizing::new(auth::new_totp_secret()));
    match database.recover_admin(
        &options.username,
        password_hash.as_deref(),
        totp_secret.as_ref().map(|secret| secret.as_str()),
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
                println!(
                    "One-time credential output follows; save it now:\nSecret: {0}\notpauth://totp/VaultLink:{username}?secret={0}&issuer=VaultLink",
                    secret.as_str()
                );
            }
            Ok(())
        }
    }
}
