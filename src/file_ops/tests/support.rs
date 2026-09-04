use std::path::{Path, PathBuf};

use crate::{
    config::{
        Admission, Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls,
    },
    db::{Permission, UploadConflictStrategy},
};

use super::*;

fn test_state(root: &Path, data: &Path) -> AppState {
    AppState::new(Config {
        server: Server {
            mode: ServerMode::Development,
            listen_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            production_mode: false,
        },
        storage: Storage {
            root_mount_path: root.into(),
            data_directory: data.into(),
            internal_directory: Some(root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)),
            require_mount: false,
            external_writers: false,
            allow_external_writer_replace: false,
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
        admission: Admission::default(),
        logging: Logging::default(),
    })
    .unwrap()
}

fn mfa_proof(state: &AppState) -> MfaSessionProof {
    let admin_id = match state.db().admin("admin").unwrap() {
        Some(admin) => admin.id,
        None => {
            state.db().create_admin("admin", "hash", "secret").unwrap();
            state.db().admin("admin").unwrap().unwrap().id
        }
    };
    const TOKEN: &str = "file-ops-test-session";
    state
        .db()
        .create_session(
            TOKEN,
            admin_id,
            "csrf",
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap();
    assert!(state.db().verify_mfa(TOKEN).unwrap());
    MfaSessionProof::for_test(TOKEN, admin_id)
}

fn authorized<T>(outcome: RequiredAuditFileOutcome<T>) -> T {
    let outcome = match outcome {
        RequiredAuditFileOutcome::Audited(audited) => crate::db::release_session_audited(audited),
        RequiredAuditFileOutcome::Uncertain(outcome) => outcome,
    };
    match outcome {
        SessionBound::Authorized(value) => value,
        SessionBound::SessionUnavailable => panic!("test MFA session unexpectedly unavailable"),
    }
}

#[tokio::test]
async fn database_executor_saturation_fails_storage_reads_closed() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.txt"), b"content").unwrap();
    let state = test_state(root.path(), data.path());
    recover_pending_file_operations(&state).await.unwrap();

    let mut permits = Vec::new();
    for _ in 0..state.db().runtime_available_permits() {
        permits.push(state.db().acquire_runtime_permit().await.unwrap());
    }
    let started = std::time::Instant::now();
    let error = inspect_delete(&state, "file.txt").await.unwrap_err();
    assert!(matches!(error, FileOperationError::DatabaseCapacity));
    assert!(started.elapsed() < std::time::Duration::from_millis(1_500));
    drop(permits);
}

fn tombstone_paths(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(
        root.join(crate::path_security::INTERNAL_STORAGE_DIRECTORY_NAME)
            .join("tombstones"),
    )
    .unwrap()
    .filter_map(Result::ok)
    .filter(|entry| crate::secure_fs::is_deletion_tombstone_name(&entry.file_name()))
    .map(|entry| entry.path())
    .collect()
}

fn install_audit_failure(data: &Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(data.join("data.sqlite")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_required_audit
             BEFORE INSERT ON audit
             BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    connection
}
fn install_share_update_failure(data: &Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(data.join("data.sqlite")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_share_update
             BEFORE UPDATE ON shares
             BEGIN SELECT RAISE(FAIL, 'injected share update failure'); END;",
        )
        .unwrap();
    connection
}
