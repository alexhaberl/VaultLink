#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_toml_examples_deserialize_with_current_parser() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let serialized = std::fs::read_to_string(&path).unwrap();
            toml::from_str::<Config>(&serialized)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        }
    }

    #[test]
    fn admission_defaults_preserve_existing_configuration_files() {
        let mut document: toml::Table = toml::from_str(&toml::to_string(&base()).unwrap()).unwrap();
        assert!(document.remove("admission").is_some());
        let parsed: Config = toml::from_str(&toml::to_string(&document).unwrap()).unwrap();
        assert_eq!(parsed.admission, Admission::default());
    }

    #[test]
    fn admission_policy_only_accepts_stricter_operator_limits() {
        let mut config = base();
        config.admission.max_public_uploads = 12;
        config.admission.max_uploads_per_share = 1;
        config.admission.upload_min_bytes_per_second = 131_072;
        config.admission.upload_max_duration_seconds = 3_600;
        config.admission.max_public_streams = 48;
        config.admission.max_streams_per_share = 8;
        config.admission.stream_min_bytes_per_second = 32_768;
        config.admission.stream_max_duration_seconds = 7_200;
        config.validate().unwrap();

        let mut unsafe_config = base();
        unsafe_config.admission.max_public_uploads = MAX_PUBLIC_UPLOADS_CEILING + 1;
        assert!(unsafe_config.validate().is_err());
        let mut unsafe_config = base();
        unsafe_config.admission.upload_min_bytes_per_second = UPLOAD_MIN_BYTES_PER_SECOND_FLOOR - 1;
        assert!(unsafe_config.validate().is_err());
        let mut unsafe_config = base();
        unsafe_config.admission.max_public_streams = MAX_PUBLIC_STREAMS_CEILING + 1;
        assert!(unsafe_config.validate().is_err());
        let mut unsafe_config = base();
        unsafe_config.admission.stream_min_bytes_per_second = STREAM_MIN_BYTES_PER_SECOND_FLOOR - 1;
        assert!(unsafe_config.validate().is_err());
    }

    fn base() -> Config {
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
                internal_directory: Some(PathBuf::from(".").join(DEFAULT_INTERNAL_DIRECTORY_NAME)),
                require_mount: false,
                external_writers: false,
                allow_external_writer_replace: false,
                expected_filesystem_type: None,
                expected_mount_source: None,
                max_upload_size: 10,
                max_zip_size: 1024,
                max_zip_files: 10,
                max_search_entries: 100,
                max_search_results: 10,
                max_preview_size: 1024,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["jpg".into(), "png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1024,
                blocked_extensions: vec![],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security {
                secure_cookie: false,
                ..Default::default()
            },
            admission: Admission::default(),
            logging: Logging::default(),
        }
    }

    fn configure_local_mount_policy(config: &mut Config) {
        config.storage.root_mount_path = "/srv/vaultlink/shared".into();
        config.storage.data_directory = "/var/lib/vaultlink".into();
        config.storage.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        config.storage.require_mount = true;
        config.storage.external_writers = false;
        config.storage.expected_filesystem_type = Some("ext4".into());
        config.storage.expected_mount_source = Some("/dev/mapper/vaultlink".into());
    }
    #[test]
    fn development_requires_loopback() {
        let mut c = base();
        c.server.listen_address = "0.0.0.0:8080".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_disables_zip_limits() {
        let mut c = base();
        c.storage.max_zip_size = 0;
        c.storage.max_zip_files = 0;
        c.validate().unwrap();
    }

    #[test]
    fn text_preview_extensions_must_not_be_empty() {
        let mut config = base();
        config.storage.preview_extensions.clear();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("preview_extensions must not be empty"));
    }

    #[test]
    fn storage_boundary_fields_are_required_in_0_5_0() {
        let serialized = toml::to_string(&base()).unwrap();
        for required in [
            "internal_directory",
            "require_mount",
            "external_writers",
            "allow_external_writer_replace",
        ] {
            let without_required = serialized
                .lines()
                .filter(|line| !line.starts_with(&format!("{required} =")))
                .collect::<Vec<_>>()
                .join("\n");
            let error = toml::from_str::<Config>(&without_required)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(required),
                "missing {required} produced: {error}"
            );
        }

        let mut in_memory = base();
        in_memory.storage.internal_directory = None;
        let error = in_memory.validate().unwrap_err().to_string();
        assert!(error.contains("storage.internal_directory must be configured explicitly"));
    }

    #[test]
    fn external_mount_policy_requires_complete_explicit_identity() {
        let mut config = base();
        config.storage.root_mount_path = "/mnt/vaultlink".into();
        config.storage.data_directory = "/var/lib/vaultlink".into();
        config.storage.require_mount = true;
        assert!(config.validate().is_err());

        config.storage.expected_filesystem_type = Some("cifs".into());
        assert!(config.validate().is_err());

        config.storage.expected_mount_source = Some("//nas.example/vaultlink".into());
        config.storage.internal_directory = Some("/mnt/.vaultlink-internal".into());
        config.storage.external_writers = true;
        config.validate().unwrap();
        config.storage.allow_external_writer_replace = true;
        config.validate().unwrap();

        let mut invalid = base();
        invalid.storage.allow_external_writer_replace = true;
        assert!(invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires external_writers=true"));
    }

    #[test]
    fn cifs_may_use_only_the_reserved_internal_child_below_the_visible_root() {
        let mut config = base();
        config.storage.root_mount_path = "/mnt/storage".into();
        config.storage.data_directory = "/var/lib/vaultlink".into();
        config.storage.internal_directory = Some("/mnt/storage/.vaultlink-internal".into());
        config.storage.require_mount = true;
        config.storage.expected_filesystem_type = Some("cifs".into());
        config.storage.expected_mount_source = Some("//nas.example/vaultlink".into());
        config.validate().unwrap();
        assert!(config.storage.internal_directory_is_nested());
        assert!(config.storage.forbid_user_symlinks());

        config.storage.expected_filesystem_type = Some("ext4".into());
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("supported only by the audited cifs/smb3"));

        config.storage.expected_filesystem_type = Some("cifs".into());
        config.storage.internal_directory = Some("/mnt/storage/data/.vaultlink-internal".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn storage_root_has_only_one_configurable_lock_domain() {
        let mut development = base();
        development.storage.root_mount_path = "/srv/vaultlink-dev".into();
        development.storage.data_directory = "/var/lib/vaultlink-dev".into();
        development.storage.internal_directory =
            Some("/srv/vaultlink-dev/.vaultlink-internal".into());
        development.validate().unwrap();
        development.storage.internal_directory = Some("/srv/another-private-dir".into());
        assert!(development
            .validate()
            .unwrap_err()
            .to_string()
            .contains("canonical development lock domain"));

        let mut production = base();
        configure_local_mount_policy(&mut production);
        production.validate().unwrap();
        production.storage.internal_directory =
            Some("/srv/vaultlink/.vaultlink-internal-alternate".into());
        assert!(production
            .validate()
            .unwrap_err()
            .to_string()
            .contains("one storage root cannot use multiple lock domains"));
    }

    #[test]
    fn production_requires_an_explicit_fail_closed_mount_identity() {
        let mut config = base();
        config.server.mode = ServerMode::ReverseProxy;
        config.server.production_mode = true;
        config.server.public_base_url = "https://vaultlink.example".into();
        config.security.secure_cookie = true;
        config.reverse_proxy.enabled = true;
        config.reverse_proxy.trust_x_forwarded_headers = true;
        config.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("production_mode=true requires require_mount=true"));
        configure_local_mount_policy(&mut config);
        config.validate().unwrap();
    }

    #[test]
    fn external_mount_policy_rejects_ignored_or_overlapping_settings() {
        let mut config = base();
        config.storage.external_writers = true;
        assert!(config.validate().is_err());
        config.storage.external_writers = false;
        config.storage.expected_filesystem_type = Some("cifs".into());
        assert!(config.validate().is_err());

        config.storage.require_mount = true;
        config.storage.root_mount_path = "/mnt/vaultlink".into();
        config.storage.data_directory = "/mnt/vaultlink/.state".into();
        config.storage.expected_mount_source = Some("//nas.example/vaultlink".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn required_mount_paths_reject_parent_directory_aliases() {
        let mut config = base();
        configure_local_mount_policy(&mut config);
        config.storage.data_directory = "/var/lib/vaultlink/../state".into();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("must not contain '.' or '..' components"));
    }

    #[test]
    fn public_base_url_rejects_ambiguous_suffixes_and_credentials() {
        let mut c = base();
        for value in [
            "http://localhost:8080/",
            "http://localhost:8080/base/path",
            "http://localhost:8080/.",
            "http://localhost:8080?next=/admin",
            "http://localhost:8080/#section",
            "http://user:secret@localhost:8080",
            "http:/missing-host",
            "mailto:admin@example.test",
        ] {
            c.server.public_base_url = value.into();
            assert!(c.validate().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn security_limits_are_positive_and_bounded() {
        let mut c = base();
        c.validate().unwrap();

        for invalid in [0, MAX_SESSION_HOURS + 1] {
            c.security.session_hours = invalid;
            assert!(c.validate().is_err(), "accepted session_hours={invalid}");
        }
        c.security.session_hours = default_session_hours();

        for invalid in [
            MIN_SESSION_IDLE_MINUTES - 1,
            c.security.session_hours * 60 + 1,
        ] {
            c.security.session_idle_minutes = invalid;
            assert!(
                c.validate().is_err(),
                "accepted session_idle_minutes={invalid}"
            );
        }
        c.security.session_idle_minutes = default_session_idle_minutes();

        for invalid in [0, MAX_AUTH_ATTEMPTS + 1] {
            c.security.login_attempts = invalid;
            assert!(c.validate().is_err(), "accepted login_attempts={invalid}");
        }
        c.security.login_attempts = default_attempts();

        for invalid in [0, MAX_LOGIN_WINDOW_SECONDS + 1] {
            c.security.login_window_seconds = invalid;
            assert!(
                c.validate().is_err(),
                "accepted login_window_seconds={invalid}"
            );
        }
        c.security.login_window_seconds = default_window();

        for invalid in [0, MAX_SHARE_UNLOCK_MINUTES + 1] {
            c.security.share_unlock_minutes = invalid;
            assert!(
                c.validate().is_err(),
                "accepted share_unlock_minutes={invalid}"
            );
        }
        c.security.share_unlock_minutes = default_share_unlock_minutes();

        c.security.share_password_max_length = MAX_SHARE_PASSWORD_LENGTH + 1;
        assert!(c.validate().is_err(), "accepted excessive password length");
        c.security.share_password_max_length = default_share_password_max();

        c.storage.max_preview_size = MAX_TEXT_PREVIEW_SIZE + 1;
        assert!(
            c.validate().is_err(),
            "accepted excessive text preview size"
        );
        c.storage.max_preview_size = MAX_TEXT_PREVIEW_SIZE;

        for invalid in [0, MAX_AUTH_ATTEMPTS + 1] {
            c.security.share_password_attempts = invalid;
            assert!(
                c.validate().is_err(),
                "accepted share_password_attempts={invalid}"
            );
        }
    }

    #[test]
    fn password_max_length_uses_only_the_canonical_key() {
        let serialized = toml::to_string(&base()).unwrap();
        assert!(serialized.contains("share_password_max_length = 256"));
        assert!(!serialized.contains("share_password_max_bytes"));

        let legacy = serialized.replace(
            "share_password_max_length = 256",
            "share_password_max_bytes = 256",
        );
        let error = toml::from_str::<Config>(&legacy).unwrap_err().to_string();
        assert!(error.contains("unknown field `share_password_max_bytes`"));
    }

    #[test]
    fn audit_client_ip_logging_is_opt_in_and_round_trips() {
        let serialized = toml::to_string(&base()).unwrap();
        let without_setting = serialized
            .lines()
            .filter(|line| !line.starts_with("audit_client_ip_enabled ="))
            .collect::<Vec<_>>()
            .join("\n");
        let defaulted: Config = toml::from_str(&without_setting).unwrap();
        assert!(!defaulted.security.audit_client_ip_enabled);
        defaulted.validate().unwrap();

        let mut enabled = base();
        enabled.security.audit_client_ip_enabled = true;
        enabled.validate().unwrap();
        let round_trip: Config = toml::from_str(&toml::to_string(&enabled).unwrap()).unwrap();
        assert!(round_trip.security.audit_client_ip_enabled);
        round_trip.validate().unwrap();
    }

    #[test]
    fn production_requires_secure_cookie() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.public_base_url = "https://example.test".into();
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn remote_reverse_proxy_requires_explicit_opt_in() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trust_x_forwarded_headers = true;
        c.reverse_proxy.trusted_proxies = vec!["192.0.2.10".parse().unwrap()];
        assert!(c.validate().is_err());
        c.reverse_proxy.allow_non_loopback = true;
        let error = c.validate().unwrap_err().to_string();
        assert!(error.contains("local readiness peer 127.0.0.1"));
        c.reverse_proxy
            .trusted_proxies
            .push("127.0.0.1".parse().unwrap());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn reverse_proxy_readiness_accepts_mapped_ipv4_allowlist_entry() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trust_x_forwarded_headers = true;
        c.reverse_proxy.allow_non_loopback = true;
        c.reverse_proxy.trusted_proxies = vec![
            "192.0.2.10".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        ];
        c.validate().unwrap();
    }
    #[test]
    fn hsts_rejected_in_development() {
        let mut c = base();
        c.tls.hsts_enabled = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn upload_limit_must_fit_inside_the_multipart_ceiling() {
        let mut c = base();
        c.storage.max_upload_size = MAX_UPLOAD_SIZE;
        assert!(c.validate().is_ok());
        c.storage.max_upload_size = MAX_UPLOAD_SIZE + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_tls_rejects_missing_files() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.public_base_url = "https://example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.cert_file = "missing-cert.pem".into();
        c.tls.key_file = "missing-key.pem".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn standalone_tls_accepts_only_documented_private_key_modes() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("private-key.pem");
        std::fs::write(&certificate, "certificate").unwrap();
        std::fs::write(&private_key, "private key").unwrap();
        let tls = Tls {
            cert_file: certificate,
            key_file: private_key.clone(),
            ..Tls::default()
        };

        for mode in [0o400, 0o440, 0o600, 0o640] {
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_tls_files(&tls).is_ok(), "rejected mode {mode:04o}");
        }
        for mode in [0o660, 0o620, 0o644, 0o700, 0o4640, 0o2640, 0o1640] {
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                validate_tls_files(&tls).is_err(),
                "accepted mode {mode:04o}"
            );
        }
    }

    #[test]
    fn standalone_letsencrypt_validates_domain_contact_and_mode() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        c.server.mode = ServerMode::ReverseProxy;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn letsencrypt_staging_rejects_hsts() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        c.tls.letsencrypt_staging = true;
        c.tls.hsts_enabled = true;
        assert!(c.validate().is_err());

        c.tls.hsts_enabled = false;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn certificate_source_accepts_documented_letsencrypt_value() {
        #[derive(Deserialize, Serialize)]
        struct Wrapper {
            certificate_source: CertificateSource,
        }

        let documented: Wrapper = toml::from_str("certificate_source = \"letsencrypt\"").unwrap();
        assert_eq!(
            documented.certificate_source,
            CertificateSource::LetsEncrypt
        );

        let serialized = toml::to_string(&documented).unwrap();
        assert!(serialized.contains("certificate_source = \"letsencrypt\""));
    }

    #[test]
    fn letsencrypt_rejects_localhost_and_unsafe_cache() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://localhost".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_err());
        c.server.public_base_url = "https://files.example.test".into();
        c.tls.letsencrypt_cache_dir = "../acme".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn readiness_target_uses_loopback_for_wildcard_reverse_proxy_bind() {
        let mut c = base();
        c.server.mode = ServerMode::ReverseProxy;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:8080".into();
        c.server.public_base_url = "https://vaultlink.example".into();
        c.security.secure_cookie = true;
        c.reverse_proxy.enabled = true;
        c.reverse_proxy.trust_x_forwarded_headers = true;
        c.reverse_proxy.allow_non_loopback = true;
        c.reverse_proxy.trusted_proxies =
            vec!["192.0.2.10".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "http://127.0.0.1:8080/api/v2/health/ready".into(),
                connect_to: None,
                insecure: false,
            }
        );
    }

    #[test]
    fn standalone_readiness_target_preserves_hostname() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "0.0.0.0:443".into();
        c.server.public_base_url = "https://files.example.test".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "https://files.example.test/api/v2/health/ready".into(),
                connect_to: Some("files.example.test:443:127.0.0.1:443".into()),
                insecure: true,
            }
        );
    }

    #[test]
    fn standalone_readiness_target_formats_ipv6_loopback_for_curl() {
        let mut c = base();
        c.server.mode = ServerMode::StandaloneTls;
        c.server.production_mode = true;
        configure_local_mount_policy(&mut c);
        c.server.listen_address = "[::]:8443".into();
        c.server.public_base_url = "https://files.example.test:8443".into();
        c.security.secure_cookie = true;
        c.tls.enabled = true;
        c.tls.certificate_source = CertificateSource::LetsEncrypt;
        c.tls.letsencrypt_contact_email = "admin@example.test".into();
        c.tls.letsencrypt_cache_dir = "acme".into();
        assert!(c.validate().is_ok());

        assert_eq!(
            c.local_readiness_target().unwrap(),
            LocalReadinessTarget {
                url: "https://files.example.test:8443/api/v2/health/ready".into(),
                connect_to: Some("files.example.test:8443:[::1]:8443".into()),
                insecure: true,
            }
        );
        assert_eq!(curl_connect_host("::1"), "[::1]");
        assert_eq!(curl_connect_host("[::1]"), "[::1]");
    }
}
