#[cfg(not(target_os = "linux"))]
compile_error!("VaultLink supports Linux only");

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod file_ops;
pub mod http_auth;
pub mod i18n;
pub mod multipart_guard;
pub mod path_security;
pub mod policy;
pub mod proxy;
pub mod range;
#[cfg(test)]
mod route_inventory_tests;
pub mod runtime;
pub mod secure_fs;
pub(crate) mod sensitive;
pub(crate) mod services;
pub mod setup;
pub mod storage_mount;
#[cfg(test)]
mod template_policy_tests;
pub mod ui;
pub mod web;
pub mod webauthn;

use std::{
    collections::HashMap,
    fs::File,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};

use config::{CertificateSource, Config, ServerMode, Storage, DEFAULT_INTERNAL_DIRECTORY_NAME};
use db::Database;
use runtime::RuntimeSettings;
use rustix::fs::{FlockOperation, Mode, OFlags, ResolveFlags};
use thiserror::Error;

const STORAGE_INSTANCE_LOCK_NAME: &str = ".vaultlink-instance.lock";

pub const MAX_IN_FLIGHT_RESPONSES: usize = 256;
pub const MAX_IN_FLIGHT_STREAMS: usize = 128;
pub const TEXT_PREVIEW_RENDER_BUDGET_PERMITS: usize = 64;
pub const MAX_CONCURRENT_ZIP_GENERATIONS: usize = 4;
pub const MAX_CONCURRENT_SEARCHES: usize = 8;
pub const MAX_CONCURRENT_ARGON2_OPERATIONS: usize = 8;
pub const MAX_IN_FLIGHT_STREAMS_PER_CLIENT: usize = 16;
pub const MAX_IN_FLIGHT_UPLOADS_PER_CLIENT: usize = 4;
pub const MAX_IN_FLIGHT_BUFFERED_RESPONSES: usize = 128;
pub const MAX_IN_FLIGHT_BUFFERED_RESPONSES_PER_CLIENT: usize = 16;
pub const MAX_EXPENSIVE_OPERATIONS_PER_CLIENT: usize = 2;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub secure_root: secure_fs::SecureRoot,
    pub limiter: auth::LoginLimiter,
    pub share_limiter: auth::LoginLimiter,
    pub alias_limiter: auth::LoginLimiter,
    pub public_transfer_limiter: auth::LoginLimiter,
    pub preview_token_limiter: auth::LoginLimiter,
    pub runtime: Arc<RwLock<RuntimeSettings>>,
    pub webauthn: Arc<RwLock<webauthn::WebAuthnService>>,
    pub security_settings_mutation: Arc<tokio::sync::Mutex<()>>,
    pub storage_mutation: Arc<tokio::sync::Mutex<()>>,
    pub storage_cleanup: Arc<tokio::sync::Mutex<()>>,
    pub upload_admission: Arc<tokio::sync::Semaphore>,
    pub response_admission: Arc<tokio::sync::Semaphore>,
    pub stream_admission: Arc<tokio::sync::Semaphore>,
    pub preview_render_admission: Arc<tokio::sync::Semaphore>,
    pub zip_generation_admission: Arc<tokio::sync::Semaphore>,
    pub search_admission: Arc<tokio::sync::Semaphore>,
    pub argon2_admission: Arc<tokio::sync::Semaphore>,
    pub stream_peer_admission: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub upload_peer_admission: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub buffered_response_admission: Arc<tokio::sync::Semaphore>,
    pub buffered_peer_admission: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub expensive_peer_admission: Arc<Mutex<HashMap<IpAddr, usize>>>,
    // The descriptor owns the kernel lock. Keeping it in every AppState clone
    // prevents another serving process from entering storage recovery or
    // cleanup for this private storage domain.
    _storage_instance_lock: Arc<StorageInstanceLock>,
    #[cfg(test)]
    pub upload_directory_sync_failure: Arc<std::sync::Mutex<Option<std::io::ErrorKind>>>,
}

#[derive(Debug)]
struct StorageInstanceLock {
    _file: File,
    root: File,
    internal: File,
}

#[derive(Debug, Error)]
enum StorageInstanceLockError {
    #[error("cannot prepare storage instance lock directory {path}: {source}")]
    Prepare {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot open storage instance lock {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("storage instance lock {path} is already held or the backend denied the exclusive lock; another VaultLink serving process may be using the same canonical storage root")]
    Contended { path: PathBuf },
    #[error("storage instance lock {path} is unsafe: {reason}")]
    Unsafe { path: PathBuf, reason: String },
    #[error("storage backend does not enforce exclusive non-blocking locks for {path}; refusing recovery and cleanup")]
    Unsupported { path: PathBuf },
    #[error("cannot verify storage instance lock {path}: {source}")]
    Verify {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        if !config.storage.require_mount {
            std::fs::create_dir_all(&config.storage.data_directory)?;
        }
        let validated_storage = storage_mount::validate_and_open(&config.storage)?;
        validated_storage.verify_path_bindings(&config.storage)?;
        // SecureRoot startup performs mutation probes and recovery. Acquire the
        // cross-process lifetime lock first so two instances can never process
        // the same upload fragments or journals concurrently.
        let storage_instance_lock = Arc::new(acquire_storage_instance_lock(
            &config.storage,
            &validated_storage,
        )?);
        validated_storage.verify_path_bindings(&config.storage)?;
        let secure_root = secure_fs::SecureRoot::open_configured_with_locked_internal(
            &config.storage.root_mount_path,
            config.storage.internal_directory.as_deref(),
            config.storage.require_mount,
            config.storage.external_writers,
            storage_instance_lock.clone(),
        )
        .map_err(|error| {
            format!(
                "cannot initialize secure storage access (openat2 is required on Linux): {error}"
            )
        })?;
        validated_storage.verify_path_bindings(&config.storage)?;
        let db = Database::open_in_directory(validated_storage.data_file()?)?;
        let persisted_runtime = db.runtime_settings()?;
        let runtime = runtime_settings_from_persisted(&config, &persisted_runtime)
            .map_err(|error| format!("invalid persisted runtime settings: {error}"))?;
        let webauthn = webauthn::WebAuthnService::from_public_base_url(&runtime.public_base_url)
            .map_err(|error| format!("invalid WebAuthn configuration: {error}"))?;
        Ok(Self {
            limiter: auth::LoginLimiter::new(
                config.security.login_attempts,
                std::time::Duration::from_secs(config.security.login_window_seconds),
            ),
            share_limiter: auth::LoginLimiter::new(
                config.security.share_password_attempts,
                std::time::Duration::from_secs(300),
            ),
            alias_limiter: auth::LoginLimiter::new(120, std::time::Duration::from_secs(60)),
            public_transfer_limiter: auth::LoginLimiter::new(
                120,
                std::time::Duration::from_secs(60),
            ),
            preview_token_limiter: auth::LoginLimiter::new(60, std::time::Duration::from_secs(60)),
            config: Arc::new(config),
            db,
            secure_root,
            runtime: Arc::new(RwLock::new(runtime)),
            webauthn: Arc::new(RwLock::new(webauthn)),
            security_settings_mutation: Arc::new(tokio::sync::Mutex::new(())),
            storage_mutation: Arc::new(tokio::sync::Mutex::new(())),
            storage_cleanup: Arc::new(tokio::sync::Mutex::new(())),
            upload_admission: Arc::new(tokio::sync::Semaphore::new(32)),
            response_admission: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_RESPONSES)),
            stream_admission: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_STREAMS)),
            preview_render_admission: Arc::new(tokio::sync::Semaphore::new(
                TEXT_PREVIEW_RENDER_BUDGET_PERMITS,
            )),
            zip_generation_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_ZIP_GENERATIONS,
            )),
            search_admission: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SEARCHES)),
            argon2_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_ARGON2_OPERATIONS,
            )),
            stream_peer_admission: Arc::new(Mutex::new(HashMap::new())),
            upload_peer_admission: Arc::new(Mutex::new(HashMap::new())),
            buffered_response_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_IN_FLIGHT_BUFFERED_RESPONSES,
            )),
            buffered_peer_admission: Arc::new(Mutex::new(HashMap::new())),
            expensive_peer_admission: Arc::new(Mutex::new(HashMap::new())),
            _storage_instance_lock: storage_instance_lock,
            #[cfg(test)]
            upload_directory_sync_failure: Arc::new(std::sync::Mutex::new(None)),
        })
    }
}

fn acquire_storage_instance_lock(
    storage: &Storage,
    validated_storage: &storage_mount::ValidatedStorage,
) -> Result<StorageInstanceLock, StorageInstanceLockError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let display_root = validated_storage.root_path().to_path_buf();
    let root = validated_storage
        .root_file()
        .map_err(|source| StorageInstanceLockError::Open {
            path: display_root.clone(),
            source,
        })?;
    let internal_path = if storage.require_mount {
        display_root
            .parent()
            .map(|parent| parent.join(DEFAULT_INTERNAL_DIRECTORY_NAME))
            .ok_or_else(|| StorageInstanceLockError::Unsafe {
                path: display_root.clone(),
                reason: "canonical storage root has no parent lock domain".into(),
            })?
    } else {
        display_root.join(DEFAULT_INTERNAL_DIRECTORY_NAME)
    };
    let internal = if storage.require_mount {
        let validated_internal_path =
            validated_storage
                .internal_path()
                .ok_or_else(|| StorageInstanceLockError::Unsafe {
                    path: internal_path.clone(),
                    reason: "required mount has no validated internal_directory capability".into(),
                })?;
        if validated_internal_path != internal_path {
            return Err(StorageInstanceLockError::Unsafe {
                path: validated_internal_path.to_path_buf(),
                reason: format!(
                    "validated internal_directory does not resolve to canonical lock domain {}",
                    internal_path.display()
                ),
            });
        }
        validated_storage
            .internal_file()
            .map_err(|source| StorageInstanceLockError::Open {
                path: internal_path.clone(),
                source,
            })?
            .ok_or_else(|| StorageInstanceLockError::Unsafe {
                path: internal_path.clone(),
                reason: "required mount has no validated internal_directory capability".into(),
            })?
    } else {
        match rustix::fs::mkdirat(&root, DEFAULT_INTERNAL_DIRECTORY_NAME, Mode::RWXU) {
            Ok(()) => root
                .sync_all()
                .map_err(|source| StorageInstanceLockError::Prepare {
                    path: display_root.clone(),
                    source,
                })?,
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(StorageInstanceLockError::Prepare {
                    path: internal_path.clone(),
                    source: errno_error(error),
                });
            }
        }
        rustix::fs::openat2(
            &root,
            DEFAULT_INTERNAL_DIRECTORY_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(|error| StorageInstanceLockError::Open {
            path: internal_path.clone(),
            source: errno_error(error),
        })?
    };
    let internal_metadata =
        internal
            .metadata()
            .map_err(|source| StorageInstanceLockError::Open {
                path: internal_path.clone(),
                source,
            })?;
    let root_metadata = root
        .metadata()
        .map_err(|source| StorageInstanceLockError::Open {
            path: display_root.clone(),
            source,
        })?;
    if !internal_metadata.is_dir()
        || internal_metadata.dev() != root_metadata.dev()
        || internal_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(StorageInstanceLockError::Unsafe {
            path: internal_path.clone(),
            reason: "internal_directory must be a private directory on the storage-root filesystem"
                .into(),
        });
    }

    let lock_path = internal_path.join(STORAGE_INSTANCE_LOCK_NAME);
    // Open an independent probe description before locking. On CIFS, flock is
    // represented by SMB byte-range locks and can make later read/write opens
    // fail; opening both first keeps the semantic probe portable across the
    // audited Linux backends.
    let lock_file = open_storage_lock_file(&internal, &lock_path)?;
    let probe_file = open_storage_lock_file(&internal, &lock_path)?;
    validate_lock_file(&lock_file, &probe_file, &lock_path)?;

    match rustix::fs::flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(error) if lock_is_contended(error) => {
            return Err(StorageInstanceLockError::Contended { path: lock_path });
        }
        Err(error) => {
            return Err(StorageInstanceLockError::Open {
                path: lock_path,
                source: errno_error(error),
            });
        }
    }

    match rustix::fs::flock(&probe_file, FlockOperation::NonBlockingLockExclusive) {
        Err(error) if lock_is_contended(error) => {}
        Ok(()) => {
            let _ = rustix::fs::flock(&probe_file, FlockOperation::Unlock);
            return Err(StorageInstanceLockError::Unsupported { path: lock_path });
        }
        Err(error) => {
            return Err(StorageInstanceLockError::Verify {
                path: lock_path,
                source: errno_error(error),
            });
        }
    }

    // Re-open the directory entry without following links and verify that it
    // still names the locked inode. This catches replacement races during
    // acquisition; the private-directory ACL prevents replacement afterwards.
    let entry = rustix::fs::openat2(
        &internal,
        STORAGE_INSTANCE_LOCK_NAME,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|error| StorageInstanceLockError::Verify {
        path: lock_path.clone(),
        source: errno_error(error),
    })?;
    let locked_identity = file_identity(&lock_file, &lock_path)?;
    let entry_identity = file_identity(&entry, &lock_path)?;
    if locked_identity != entry_identity {
        return Err(StorageInstanceLockError::Unsafe {
            path: lock_path,
            reason: "lock-file directory entry changed during acquisition".into(),
        });
    }

    Ok(StorageInstanceLock {
        _file: lock_file,
        root,
        internal,
    })
}

fn open_storage_lock_file(
    internal: &File,
    lock_path: &Path,
) -> Result<File, StorageInstanceLockError> {
    rustix::fs::openat2(
        internal,
        STORAGE_INSTANCE_LOCK_NAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::ACCESS {
            StorageInstanceLockError::Contended {
                path: lock_path.to_path_buf(),
            }
        } else {
            StorageInstanceLockError::Open {
                path: lock_path.to_path_buf(),
                source: errno_error(error),
            }
        }
    })
}

fn validate_lock_file(
    lock_file: &File,
    probe_file: &File,
    lock_path: &Path,
) -> Result<(), StorageInstanceLockError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = lock_file
        .metadata()
        .map_err(|source| StorageInstanceLockError::Open {
            path: lock_path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(StorageInstanceLockError::Unsafe {
            path: lock_path.to_path_buf(),
            reason: "lock must be a private regular file with exactly one hard link".into(),
        });
    }
    if file_identity(lock_file, lock_path)? != file_identity(probe_file, lock_path)? {
        return Err(StorageInstanceLockError::Unsafe {
            path: lock_path.to_path_buf(),
            reason: "lock-file directory entry changed while it was opened".into(),
        });
    }
    Ok(())
}

fn file_identity(file: &File, lock_path: &Path) -> Result<(u64, u64), StorageInstanceLockError> {
    use std::os::unix::fs::MetadataExt;

    file.metadata()
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(|source| StorageInstanceLockError::Verify {
            path: lock_path.to_path_buf(),
            source,
        })
}

fn lock_is_contended(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::AGAIN
        || error == rustix::io::Errno::WOULDBLOCK
        || error == rustix::io::Errno::ACCESS
}

fn errno_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

fn runtime_settings_from_persisted(
    config: &Config,
    persisted: &[(String, String)],
) -> Result<RuntimeSettings, String> {
    let static_acme_domain = config.server.mode == ServerMode::StandaloneTls
        && config.tls.certificate_source == CertificateSource::LetsEncrypt;
    let mut runtime = RuntimeSettings::from_config(config);
    runtime.apply_many(persisted.iter().filter_map(|(key, value)| {
        // In built-in ACME mode the certificate domain is a file/restart setting.
        // Ignoring an older persisted URL lets an intentional config.toml domain
        // change take effect on restart while retaining every other runtime key.
        if static_acme_domain && key == "public_base_url" {
            None
        } else {
            Some((key.as_str(), value.as_str()))
        }
    }))?;
    runtime.validate_for_config(config)?;
    Ok(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Logging, ReverseProxy, Security, Server, Storage, Tls};

    const LOCK_CHILD_ROOT: &str = "VAULTLINK_TEST_STORAGE_LOCK_CHILD_ROOT";

    fn config(root: &std::path::Path, data: &std::path::Path) -> Config {
        Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: root.into(),
                data_directory: data.into(),
                internal_directory: None,
                require_mount: false,
                external_writers: false,
                expected_filesystem_type: None,
                expected_mount_source: None,
                max_upload_size: 1_000_000,
                max_zip_size: 1_000_000,
                max_zip_files: 100,
                max_search_entries: 1_000,
                max_search_results: 100,
                max_preview_size: 100_000,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1_000_000,
                blocked_extensions: vec!["exe".into()],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security::default(),
            logging: Logging::default(),
        }
    }

    fn acquire_test_storage_instance_lock(
        storage: &Storage,
    ) -> Result<StorageInstanceLock, StorageInstanceLockError> {
        let validated = storage_mount::validate_and_open(storage)
            .expect("test storage paths must produce validated capabilities");
        acquire_storage_instance_lock(storage, &validated)
    }

    #[test]
    fn startup_applies_valid_runtime_snapshot_without_key_order_failures() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let config = config(root.path(), data.path());
        let database = Database::open(data.path().join("data.sqlite")).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        let mut runtime = RuntimeSettings::from_config(&config);
        runtime.share_password_min_length = 8;
        runtime.share_password_max_length = 8;
        runtime.validate().unwrap();
        database
            .replace_runtime_settings(&runtime.pairs(), 1)
            .unwrap();
        drop(database);

        let state = AppState::new(config).unwrap();
        let runtime = state.runtime.read().unwrap();
        assert_eq!(runtime.share_password_min_length, 8);
        assert_eq!(runtime.share_password_max_length, 8);
    }

    #[test]
    fn letsencrypt_restart_uses_config_domain_over_stale_persisted_url() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), data.path());
        config.server.mode = ServerMode::StandaloneTls;
        config.server.production_mode = true;
        config.server.public_base_url = "https://new.example.test".into();
        config.tls.enabled = true;
        config.tls.certificate_source = CertificateSource::LetsEncrypt;

        let mut previous = RuntimeSettings::from_config(&config);
        previous.public_base_url = "https://old.example.test".into();
        previous.max_upload_size = 42_000_000;
        let persisted = previous
            .pairs()
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect::<Vec<_>>();
        let loaded = runtime_settings_from_persisted(&config, &persisted).unwrap();

        assert_eq!(loaded.public_base_url, "https://new.example.test");
        assert_eq!(loaded.max_upload_size, 42_000_000);
    }

    #[test]
    fn storage_instance_lock_is_shared_across_data_directories_and_clones() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_data = tempfile::tempdir().unwrap();
        let second_data = tempfile::tempdir().unwrap();
        let alias_parent = tempfile::tempdir().unwrap();
        let root_alias = alias_parent.path().join("same-storage-alias");
        symlink(root.path(), &root_alias).unwrap();
        let first = AppState::new(config(root.path(), first_data.path())).unwrap();
        let surviving_clone = first.clone();
        drop(first);

        let second_config = config(root.path(), second_data.path());
        let error = match AppState::new(second_config.clone()) {
            Ok(_) => panic!("a second process domain acquired the same storage lock"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("already held"),
            "unexpected startup error: {error}"
        );
        let alias_error = match AppState::new(config(&root_alias, second_data.path())) {
            Ok(_) => panic!("a symlink alias bypassed the canonical storage lock domain"),
            Err(error) => error,
        };
        assert!(
            alias_error.to_string().contains("already held"),
            "unexpected alias startup error: {alias_error}"
        );

        drop(surviving_clone);
        AppState::new(second_config).expect("dropping the final state must release the lock");
    }

    #[test]
    fn cleanup_cursor_retains_storage_instance_lock_after_state_drop() {
        let root = tempfile::tempdir().unwrap();
        let first_data = tempfile::tempdir().unwrap();
        let second_data = tempfile::tempdir().unwrap();
        let state = AppState::new(config(root.path(), first_data.path())).unwrap();
        let cleanup = state.secure_root.start_upload_fragment_cleanup().unwrap();
        let second_config = config(root.path(), second_data.path());

        // Model a cleanup batch already inside spawn_blocking after its router
        // and AppState were dropped during shutdown. The cursor itself must
        // keep the process-lifetime storage lock until that batch returns.
        drop(state);
        let error = match AppState::new(second_config.clone()) {
            Ok(_) => panic!("a cleanup cursor released the storage lock too early"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("already held"),
            "unexpected startup error: {error}"
        );

        drop(cleanup);
        AppState::new(second_config)
            .expect("dropping the completed cleanup cursor must release the lock");
    }

    #[test]
    fn pending_upload_retains_storage_instance_lock_after_state_drop() {
        let root = tempfile::tempdir().unwrap();
        let first_data = tempfile::tempdir().unwrap();
        let second_data = tempfile::tempdir().unwrap();
        let state = AppState::new(config(root.path(), first_data.path())).unwrap();
        let upload = state.secure_root.begin_upload("").unwrap();
        let second_config = config(root.path(), second_data.path());

        // A PendingUpload can be inside a non-cancellable publication task
        // after the request/router has gone away.
        drop(state);
        let error = match AppState::new(second_config.clone()) {
            Ok(_) => panic!("a pending upload released the storage lock too early"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("already held"),
            "unexpected startup error: {error}"
        );

        drop(upload);
        AppState::new(second_config)
            .expect("dropping the pending upload must release the storage lock");
    }

    #[test]
    fn storage_instance_lock_contends_across_processes() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let storage = config(root.path(), data.path()).storage;
        let _lock = acquire_test_storage_instance_lock(&storage).unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::storage_instance_lock_child_probe")
            .arg("--nocapture")
            .env(LOCK_CHILD_ROOT, root.path())
            .status()
            .unwrap();
        assert!(status.success(), "child-process contention probe failed");
    }

    #[test]
    fn storage_instance_lock_child_probe() {
        let Some(root) = std::env::var_os(LOCK_CHILD_ROOT) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let storage = config(&root, &root).storage;
        assert!(matches!(
            acquire_test_storage_instance_lock(&storage),
            Err(StorageInstanceLockError::Contended { .. })
        ));
    }

    #[test]
    fn storage_instance_lock_rejects_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let internal = root.path().join(DEFAULT_INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&internal).unwrap();
        std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o700)).unwrap();
        let outside = root.path().join("outside-lock-target");
        std::fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, internal.join(STORAGE_INSTANCE_LOCK_NAME)).unwrap();

        let storage = config(root.path(), data.path()).storage;
        let error = acquire_test_storage_instance_lock(&storage).unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot open storage instance lock"));
        assert_eq!(std::fs::read(outside).unwrap(), b"unchanged");
    }

    #[test]
    fn storage_instance_lock_rejects_internal_replacement_during_secure_root_handoff() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let storage = config(root.path(), data.path()).storage;
        let first_lock = Arc::new(acquire_test_storage_instance_lock(&storage).unwrap());
        let internal = root.path().join(DEFAULT_INTERNAL_DIRECTORY_NAME);
        let displaced = root.path().join(".vaultlink-internal-displaced");
        std::fs::rename(&internal, &displaced).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o700)).unwrap();

        // This demonstrates the handoff hazard: the replacement namespace has
        // a separate, otherwise valid lock while the first lock is still live.
        let _replacement_lock = acquire_test_storage_instance_lock(&storage).unwrap();
        let error = match secure_fs::SecureRoot::open_configured_with_locked_internal(
            &storage.root_mount_path,
            storage.internal_directory.as_deref(),
            storage.require_mount,
            storage.external_writers,
            first_lock,
        ) {
            Ok(_) => panic!("SecureRoot accepted a replacement internal-directory namespace"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("changed after the process-lifetime lock was acquired"));
        assert!(!internal.join("uploads").exists());
        assert!(!internal.join("tombstones").exists());
    }

    #[test]
    fn secure_root_handoff_rejects_a_replacement_root_before_mutation() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let displaced = parent.path().join("root-validated");
        let data = parent.path().join("data");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data).unwrap();
        let storage = config(&root, &data).storage;
        let validated = storage_mount::validate_and_open(&storage).unwrap();
        let lock = Arc::new(acquire_storage_instance_lock(&storage, &validated).unwrap());

        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = match secure_fs::SecureRoot::open_configured_with_locked_internal(
            &storage.root_mount_path,
            storage.internal_directory.as_deref(),
            storage.require_mount,
            storage.external_writers,
            lock,
        ) {
            Ok(_) => panic!("SecureRoot accepted a replacement root namespace"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("root_mount_path changed"));
        assert!(!root.join(DEFAULT_INTERNAL_DIRECTORY_NAME).exists());
    }
}
