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

fn validate_proxy_mtls_files(tls: &Tls, ca_file: &Path) -> Result<(), ConfigError> {
    use rustls_pki_types::pem::PemObject;
    let material = crate::tls_files::read_validated_tls_pem(&tls.cert_file, &tls.key_file)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let ca = crate::tls_files::read_validated_ca_pem(ca_file)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let certificates = rustls_pki_types::CertificateDer::pem_slice_iter(&material.certificate_chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(&material.private_key)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    let ca_certificates = rustls_pki_types::CertificateDer::pem_slice_iter(&ca)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    if certificates.is_empty() || ca_certificates.is_empty() || ca_certificates.len() > 8 {
        return Err(ConfigError::Invalid("mTLS certificate chain or proxy CA is empty or oversized".into()));
    }
    for certificate in ca_certificates {
        roots.add(certificate).map_err(|error| ConfigError::Invalid(error.to_string()))?;
    }
    rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
        .build().map_err(|error| ConfigError::Invalid(error.to_string()))?;
    rustls::ServerConfig::builder().with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    Ok(())
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
