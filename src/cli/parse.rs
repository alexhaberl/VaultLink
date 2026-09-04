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

#[derive(Clone, Debug, PartialEq, Eq)]
struct RotateSecretsOptions {
    source: RecoveryDatabaseSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RevokeAllServiceTokensOptions {
    source: RecoveryDatabaseSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyBackupDatabaseOptions {
    database_path: PathBuf,
}

impl VerifyBackupDatabaseOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("verify-backup-database") {
            return Err("verify-backup-database parser requires its command".into());
        }
        if args.len() != 4 || args.get(2).map(String::as_str) != Some("--database") {
            return Err("verify-backup-database requires exactly --database DATABASE_PATH".into());
        }
        let database_path = args[3].as_str();
        if database_path.is_empty() || database_path.starts_with('-') {
            return Err("--database requires one non-option value".into());
        }
        Ok(Self {
            database_path: PathBuf::from(database_path),
        })
    }
}

impl RotateSecretsOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("rotate-secrets") {
            return Err("rotate-secrets parser requires the rotate-secrets command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            if option != "--config" && option != "--database" {
                return Err(if option.starts_with('-') {
                    format!("unknown rotate-secrets option: {option}")
                } else {
                    format!("unexpected rotate-secrets positional argument: {option}")
                });
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires one non-option value"))?;
            if value.is_empty() || value.starts_with('-') {
                return Err(format!("{option} requires one non-option value"));
            }
            let duplicate = if option == "--config" {
                config_path.replace(PathBuf::from(value)).is_some()
            } else {
                database_path.replace(PathBuf::from(value)).is_some()
            };
            if duplicate {
                return Err(format!("{option} may only be provided once"));
            }
            index += 2;
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err("rotate-secrets requires exactly one of --config or --database".into())
            }
            (Some(_), Some(_)) => {
                return Err("rotate-secrets accepts only one of --config or --database".into())
            }
        };
        Ok(Self { source })
    }
}

impl RevokeAllServiceTokensOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.get(1).map(String::as_str) != Some("revoke-all-service-tokens") {
            return Err("revoke-all-service-tokens parser requires its command".into());
        }
        let mut config_path = None;
        let mut database_path = None;
        let mut confirmed = false;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            match option {
                "--config" | "--database" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| format!("{option} requires one non-option value"))?;
                    if value.is_empty() || value.starts_with('-') {
                        return Err(format!("{option} requires one non-option value"));
                    }
                    let duplicate = if option == "--config" {
                        config_path.replace(PathBuf::from(value)).is_some()
                    } else {
                        database_path.replace(PathBuf::from(value)).is_some()
                    };
                    if duplicate {
                        return Err(format!("{option} may only be provided once"));
                    }
                    index += 2;
                }
                "--all" => {
                    if confirmed {
                        return Err("--all may only be provided once".into());
                    }
                    confirmed = true;
                    index += 1;
                }
                option if option.starts_with('-') => {
                    return Err(format!(
                        "unknown revoke-all-service-tokens option: {option}"
                    ));
                }
                positional => {
                    return Err(format!(
                        "unexpected revoke-all-service-tokens positional argument: {positional}"
                    ));
                }
            }
        }
        if !confirmed {
            return Err("revoke-all-service-tokens requires --all".into());
        }
        let source = match (config_path, database_path) {
            (Some(path), None) => RecoveryDatabaseSource::Config(path),
            (None, Some(path)) => RecoveryDatabaseSource::Database(path),
            (None, None) => {
                return Err(
                    "revoke-all-service-tokens requires exactly one of --config or --database"
                        .into(),
                )
            }
            (Some(_), Some(_)) => {
                return Err(
                    "revoke-all-service-tokens accepts only one of --config or --database".into(),
                )
            }
        };
        Ok(Self { source })
    }
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
