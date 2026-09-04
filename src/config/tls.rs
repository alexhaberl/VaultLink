fn curl_connect_host(host: &str) -> String {
    let bare_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if matches!(bare_host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("[{bare_host}]")
    } else {
        bare_host.to_string()
    }
}

fn validate_tls_files(tls: &Tls) -> Result<(), ConfigError> {
    crate::tls_files::validate_tls_file_paths(&tls.cert_file, &tls.key_file)
        .map_err(|error| ConfigError::Invalid(error.to_string()))
}

pub fn letsencrypt_cache_dir(storage: &Storage, tls: &Tls) -> Result<PathBuf, ConfigError> {
    validate_acme_cache_path(&storage.data_directory, &tls.letsencrypt_cache_dir)?;
    if tls.letsencrypt_cache_dir.is_absolute() {
        Ok(tls.letsencrypt_cache_dir.clone())
    } else {
        Ok(storage.data_directory.join(&tls.letsencrypt_cache_dir))
    }
}

fn validate_letsencrypt(url: &Url, storage: &Storage, tls: &Tls) -> Result<(), ConfigError> {
    let host = url.host_str().ok_or_else(|| {
        ConfigError::Invalid("letsencrypt requires a public_base_url host".into())
    })?;
    if host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || host
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(ConfigError::Invalid(
            "letsencrypt requires a DNS domain in public_base_url".into(),
        ));
    }
    if !tls.letsencrypt_contact_email.contains('@')
        || tls.letsencrypt_contact_email.contains('\n')
        || tls.letsencrypt_contact_email.contains('\r')
        || tls.letsencrypt_contact_email.starts_with("mailto:")
    {
        return Err(ConfigError::Invalid(
            "letsencrypt_contact_email must be a plain email address".into(),
        ));
    }
    letsencrypt_cache_dir(storage, tls).map(|_| ())
}

fn validate_acme_cache_path(data_directory: &Path, cache_dir: &Path) -> Result<(), ConfigError> {
    if cache_dir.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(
            "letsencrypt_cache_dir must not be empty".into(),
        ));
    }
    if cache_dir
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ConfigError::Invalid(
            "letsencrypt_cache_dir must stay inside data_directory".into(),
        ));
    }
    if cache_dir.is_absolute() {
        if !data_directory.is_absolute() || !cache_dir.starts_with(data_directory) {
            return Err(ConfigError::Invalid(
                "absolute letsencrypt_cache_dir must be inside absolute data_directory".into(),
            ));
        }
    } else if cache_dir
        .components()
        .any(|component| matches!(component, Component::RootDir))
    {
        return Err(ConfigError::Invalid(
            "relative letsencrypt_cache_dir must not contain a root component".into(),
        ));
    }
    Ok(())
}
