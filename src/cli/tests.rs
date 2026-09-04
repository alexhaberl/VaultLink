#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_and_shutdown_budgets_are_bounded() {
        assert_eq!(MAX_BLOCKING_THREADS, 64);
        assert_eq!(SERVER_DRAIN_TIMEOUT, Duration::from_secs(25));
        assert_eq!(CLEANUP_JOIN_TIMEOUT, Duration::from_secs(10));
        assert_eq!(
            SERVER_DRAIN_TIMEOUT + CLEANUP_JOIN_TIMEOUT,
            Duration::from_secs(35)
        );
    }

    #[tokio::test]
    async fn cleanup_join_returns_a_timed_out_error_at_its_deadline() {
        let error = wait_for_cleanup_shutdown(
            std::future::pending::<Result<(), tokio::task::JoinError>>(),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("storage cleanup worker exceeded its shutdown deadline"));
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn security_audit_retention_eviction_is_warned_with_counts() {
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_audit_retention_outcome(AuditRetentionOutcome {
                routine_deleted: 7,
                security_deleted: 2,
            });
        });
        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("WARN"));
        assert!(output.contains("audit retention removed security-priority events"));
        assert!(output.contains("routine_deleted=7"));
        assert!(output.contains("security_deleted=2"));
    }

    #[test]
    fn connection_limiter_recovers_after_lock_poisoning() {
        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let zero_peer = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let counts = Arc::new(Mutex::new(HashMap::from([
            (peer, usize::MAX),
            (zero_peer, 0usize),
        ])));
        let poisoned = counts.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("inject connection limiter poisoning");
        })
        .is_err());

        let recovered = connection_counts(&counts, 8);
        assert_eq!(recovered.get(&peer), Some(&8));
        assert!(!recovered.contains_key(&zero_peer));
        drop(recovered);
        assert!(!counts.is_poisoned());
    }

    #[derive(Clone)]
    struct PendingAcceptor;

    impl<S> Accept<tokio::net::TcpStream, S> for PendingAcceptor
    where
        S: Send + 'static,
    {
        type Stream = tokio::net::TcpStream;
        type Service = S;
        type Future = Pin<
            Box<
                dyn Future<Output = io::Result<(tokio::net::TcpStream, Self::Service)>>
                    + Send
                    + 'static,
            >,
        >;

        fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
            Box::pin(async move {
                let _held = (stream, service);
                std::future::pending::<io::Result<(tokio::net::TcpStream, S)>>().await
            })
        }
    }

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn seed_service_token_database(path: &std::path::Path, name: &str) {
        let database = Database::open(path).unwrap();
        let audit_context = AuditContext::new("recovery-test-admin", None);
        assert_eq!(
            database
                .create_initial_admin_and_audit(
                    "recovery-test-admin",
                    "password-hash",
                    &auth::new_totp_secret(),
                    &audit_context,
                )
                .unwrap(),
            InitialAdminOutcome::Created
        );
        drop(database);

        // This helper exercises the offline, explicitly non-session-bound
        // recovery command. Seed its fixture directly so production code does
        // not expose a raw-session-token service-token mutator as an escape
        // hatch around `MfaSessionProof`.
        let connection = rusqlite::Connection::open(path).unwrap();
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO service_tokens(
                         name,token_hash,scope_mask,created_by,created_at
                     ) VALUES(?1,?2,1,1,?3)",
                    rusqlite::params![name, "0".repeat(64), chrono::Utc::now().to_rfc3339()],
                )
                .unwrap(),
            1
        );
    }

    fn assert_revoke_all_audit(path: &std::path::Path) {
        let database = Database::open(path).unwrap();
        let events = database
            .list_audit(Some("service_tokens_revoked_all"), 10, 0)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "local_recovery");
        assert_eq!(events[0].object_id, None);
        assert_eq!(events[0].detail.as_deref(), Some("count=1"));
    }

    #[test]
    fn revoke_all_service_tokens_parser_requires_confirmation_and_one_source() {
        assert_eq!(
            RevokeAllServiceTokensOptions::parse(&arguments(&[
                "vaultlink",
                "revoke-all-service-tokens",
                "--config",
                "config.toml",
                "--all",
            ]))
            .unwrap(),
            RevokeAllServiceTokensOptions {
                source: RecoveryDatabaseSource::Config("config.toml".into()),
            }
        );
        assert_eq!(
            RevokeAllServiceTokensOptions::parse(&arguments(&[
                "vaultlink",
                "revoke-all-service-tokens",
                "--all",
                "--database",
                "data.sqlite",
            ]))
            .unwrap(),
            RevokeAllServiceTokensOptions {
                source: RecoveryDatabaseSource::Database("data.sqlite".into()),
            }
        );

        for invalid in [
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
            ],
            vec!["vaultlink", "revoke-all-service-tokens", "--all"],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--config",
                "config.toml",
                "--database",
                "data.sqlite",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
                "--all",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "--all",
            ],
            vec![
                "vaultlink",
                "revoke-all-service-tokens",
                "--database",
                "data.sqlite",
                "--unknown",
                "--all",
            ],
        ] {
            assert!(RevokeAllServiceTokensOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn revoke_all_service_tokens_targets_only_the_selected_database_and_audits_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let direct_database = directory.path().join("direct.sqlite");
        let untouched_database = directory.path().join("untouched.sqlite");
        let config_data_directory = directory.path().join("configured-data");
        std::fs::create_dir(&config_data_directory).unwrap();
        let configured_database = config_data_directory.join("data.sqlite");
        seed_service_token_database(&direct_database, "Direct target");
        seed_service_token_database(&untouched_database, "Untouched target");
        seed_service_token_database(&configured_database, "Config target");

        let direct_options = RevokeAllServiceTokensOptions {
            source: RecoveryDatabaseSource::Database(direct_database.clone()),
        };
        assert_eq!(revoke_all_service_tokens(&direct_options).unwrap(), 1);
        assert!(Database::open(&direct_database)
            .unwrap()
            .list_service_tokens()
            .unwrap()
            .is_empty());
        assert_eq!(
            Database::open(&untouched_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            Database::open(&configured_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_revoke_all_audit(&direct_database);

        let config_path = directory.path().join("recovery.toml");
        let serialized_data_directory =
            toml::Value::String(config_data_directory.to_string_lossy().into_owned()).to_string();
        std::fs::write(
            &config_path,
            format!("[storage]\ndata_directory = {serialized_data_directory}\n"),
        )
        .unwrap();
        let config_options = RevokeAllServiceTokensOptions {
            source: RecoveryDatabaseSource::Config(config_path),
        };
        assert_eq!(revoke_all_service_tokens(&config_options).unwrap(), 1);
        assert!(Database::open(&configured_database)
            .unwrap()
            .list_service_tokens()
            .unwrap()
            .is_empty());
        assert_eq!(
            Database::open(&untouched_database)
                .unwrap()
                .list_service_tokens()
                .unwrap()
                .len(),
            1
        );
        assert_revoke_all_audit(&configured_database);
        assert!(Database::open(&untouched_database)
            .unwrap()
            .list_audit(Some("service_tokens_revoked_all"), 10, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn verify_backup_database_parser_is_exact() {
        assert_eq!(
            VerifyBackupDatabaseOptions::parse(&arguments(&[
                "vaultlink",
                "verify-backup-database",
                "--database",
                "backup/data.sqlite",
            ]))
            .unwrap(),
            VerifyBackupDatabaseOptions {
                database_path: "backup/data.sqlite".into(),
            }
        );
        for invalid in [
            vec!["vaultlink", "verify-backup-database"],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--config",
                "config.toml",
            ],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--database",
                "--other",
            ],
            vec![
                "vaultlink",
                "verify-backup-database",
                "--database",
                "one.sqlite",
                "extra",
            ],
        ] {
            assert!(VerifyBackupDatabaseOptions::parse(&arguments(&invalid)).is_err());
        }
    }

    #[test]
    fn verify_backup_database_authenticates_encrypted_state() {
        let valid = tempfile::tempdir().unwrap();
        let valid_database = valid.path().join("data.sqlite");
        let database = Database::open(&valid_database).unwrap();
        assert_eq!(
            database
                .create_initial_admin_and_audit(
                    "admin",
                    "password-hash",
                    "JBSWY3DPEHPK3PXP",
                    &AuditContext::new("backup-verification-test", None),
                )
                .unwrap(),
            InitialAdminOutcome::Created
        );
        drop(database);
        std::fs::remove_file(valid.path().join("secrets.keyring.lock")).unwrap();

        let database_before = std::fs::read(&valid_database).unwrap();
        let keyring_path = valid.path().join("secrets.keyring");
        let keyring_before = std::fs::read(&keyring_path).unwrap();

        let options = VerifyBackupDatabaseOptions {
            database_path: valid_database.clone(),
        };
        verify_backup_database(&options).unwrap();
        assert_eq!(std::fs::read(&valid_database).unwrap(), database_before);
        assert_eq!(std::fs::read(&keyring_path).unwrap(), keyring_before);
        assert!(!valid.path().join("secrets.keyring.lock").exists());

        let unrelated = tempfile::tempdir().unwrap();
        let unrelated_database = unrelated.path().join("data.sqlite");
        drop(Database::open(&unrelated_database).unwrap());
        std::fs::copy(unrelated.path().join("secrets.keyring"), &keyring_path).unwrap();
        assert!(verify_backup_database(&options).is_err());
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
        assert!(validate_admin_password(&"x".repeat(auth::ADMIN_PASSWORD_MAX_CHARACTERS)).is_ok());
        assert!(
            validate_admin_password(&"x".repeat(auth::ADMIN_PASSWORD_MAX_CHARACTERS + 1)).is_err()
        );
    }

    #[tokio::test]
    async fn connection_limiter_rejects_excess_connections_and_releases_on_drop() {
        let limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(1)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 2,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_first_client, first_server) = tcp_pair().await;
        let (held_connection, ()) = limiter.accept(first_server, ()).await.unwrap();

        let (_second_client, second_server) = tcp_pair().await;
        let error = limiter
            .accept(second_server, ())
            .await
            .err()
            .expect("the second connection must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

        drop(held_connection);
        let (_third_client, third_server) = tcp_pair().await;
        assert!(limiter.accept(third_server, ()).await.is_ok());
    }

    #[tokio::test]
    async fn connection_limiter_enforces_and_releases_the_peer_budget() {
        let limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_first_client, first_server) = tcp_pair().await;
        let (held_connection, ()) = limiter.accept(first_server, ()).await.unwrap();

        let (_second_client, second_server) = tcp_pair().await;
        let error = limiter
            .accept(second_server, ())
            .await
            .err()
            .expect("the peer limit must reject the second connection");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);

        drop(held_connection);
        let (_third_client, third_server) = tcp_pair().await;
        assert!(limiter.accept(third_server, ()).await.is_ok());
    }

    #[tokio::test]
    async fn connection_limiter_times_out_stalled_tls_accept_and_releases_budgets() {
        let limiter = ConnectionLimitAcceptor {
            inner: PendingAcceptor,
            permits: Arc::new(Semaphore::new(1)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: None,
            max_connections_per_peer: 1,
            accept_timeout: Duration::from_millis(20),
        };
        let (_client, server) = tcp_pair().await;
        let error = tokio::time::timeout(Duration::from_millis(250), limiter.accept(server, ()))
            .await
            .expect("the connection accept deadline must wake the task")
            .err()
            .expect("a stalled connection accept must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(limiter.permits.available_permits(), 1);
        assert!(limiter.peer_connections.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reverse_proxy_acceptor_accepts_only_an_explicit_tcp_peer() {
        let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let trusted_limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: Some(Arc::new(HashSet::from([loopback]))),
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_trusted_client, trusted_server) = tcp_pair().await;
        assert!(trusted_limiter.accept(trusted_server, ()).await.is_ok());

        let untrusted_limiter = ConnectionLimitAcceptor {
            inner: axum_server::accept::DefaultAcceptor::new(),
            permits: Arc::new(Semaphore::new(2)),
            peer_connections: Arc::new(Mutex::new(HashMap::new())),
            trusted_proxy_peers: Some(Arc::new(HashSet::from(["192.0.2.10".parse().unwrap()]))),
            max_connections_per_peer: 1,
            accept_timeout: CONNECTION_ACCEPT_TIMEOUT,
        };
        let (_direct_client, direct_server) = tcp_pair().await;
        let error = untrusted_limiter
            .accept(direct_server, ())
            .await
            .err()
            .expect("an unlisted direct peer must be rejected before HTTP");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(untrusted_limiter.permits.available_permits(), 2);
        assert!(untrusted_limiter
            .peer_connections
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn connection_peer_keys_group_ipv6_prefixes_and_mapped_ipv4() {
        assert_eq!(
            vaultlink::proxy::client_limit_key("2001:db8:1234:5678::1".parse().unwrap()),
            "2001:db8:1234:5678::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            vaultlink::proxy::client_limit_key("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn only_exact_trusted_proxy_peers_receive_the_global_budget() {
        let trusted_peer = "192.0.2.10".parse::<IpAddr>().unwrap();
        let trusted_proxy_peers = HashSet::from([trusted_peer]);
        assert_eq!(
            peer_connection_limit(
                trusted_peer,
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS
        );
        assert_eq!(
            peer_connection_limit(
                "192.0.2.11".parse().unwrap(),
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS_PER_PEER
        );
        assert_eq!(
            peer_connection_limit(
                "::ffff:192.0.2.10".parse().unwrap(),
                Some(&trusted_proxy_peers),
                MAX_ACTIVE_CONNECTIONS_PER_PEER,
            ),
            MAX_ACTIVE_CONNECTIONS
        );
    }

    #[tokio::test]
    async fn connection_io_times_out_when_response_writes_make_no_progress() {
        use tokio::io::AsyncWriteExt as _;

        let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let peer_connections = Arc::new(Mutex::new(HashMap::from([(peer, 1)])));
        let global = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let (_client, server) = tokio::io::duplex(1);
        let mut limited = ConnectionLimitedIo {
            inner: server,
            _permit: ConnectionPermit {
                _global: global,
                peer_connections,
                peer,
                maximum: 1,
            },
            write_timeout: None,
            write_idle_timeout: Duration::from_millis(20),
            connection_deadline: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
        };
        limited.write_all(b"x").await.unwrap();
        let error = tokio::time::timeout(Duration::from_millis(250), limited.write_all(b"y"))
            .await
            .expect("write deadline must wake the task")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }
}
