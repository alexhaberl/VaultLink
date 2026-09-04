#[test]
fn persistent_secrets_survive_restart_and_key_rotation_without_plaintext_columns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("data.sqlite");
    let database = Database::open(&path).unwrap();
    database
        .create_admin("admin", "password-hash", "TOTP-SECRET")
        .unwrap();
    database
        .create_session(
            "rotation-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("rotation-session").unwrap());
    let service_token = format!("vlk_st_v1_{}", crate::auth::random_token(32));
    let SessionBound::Authorized(service_token_outcome) = database
        .create_service_token_for_mfa_session(
            &MfaSessionProof::for_test("rotation-session", 1),
            "password-hash",
            "Rotation invariant",
            &service_token,
            None,
            &AuditContext::new("admin", None),
        )
        .unwrap()
    else {
        panic!("service token was not created")
    };
    let ServiceTokenCreationOutcome::Created(service_token_metadata) =
        service_token_outcome.into_test_value()
    else {
        panic!("service token was not created")
    };
    database
        .create_share(
            "share-token",
            None,
            "file.txt",
            false,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let before: (u64, Vec<u8>, u64, Vec<u8>) = database
        .conn()
        .query_row(
            "SELECT shares.token_key_id,shares.token_ciphertext,
                    admins.totp_key_id,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let service_token_hash_before: String = database
        .conn()
        .query_row(
            "SELECT token_hash FROM service_tokens WHERE id=?1",
            [service_token_metadata.id],
            |row| row.get(0),
        )
        .unwrap();
    drop(database);

    Database::rotate_secrets(&path).unwrap();
    let reopened = Database::open(&path).unwrap();
    assert_eq!(
        reopened
            .share_by_token("share-token")
            .unwrap()
            .unwrap()
            .token,
        "share-token"
    );
    assert_eq!(
        reopened
            .admin("admin")
            .unwrap()
            .unwrap()
            .totp_secret
            .expose_secret(),
        "TOTP-SECRET"
    );
    assert_eq!(
        reopened
            .authorize_service_token(&service_token, SERVICE_TOKEN_SCOPE_MONITORING_READ)
            .unwrap(),
        ServiceTokenAuthorizationOutcome::Authorized {
            token_id: service_token_metadata.id
        }
    );
    let service_token_hash_after: String = reopened
        .conn()
        .query_row(
            "SELECT token_hash FROM service_tokens WHERE id=?1",
            [service_token_metadata.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(service_token_hash_after, service_token_hash_before);
    let after: (u64, Vec<u8>, u64, Vec<u8>) = reopened
        .conn()
        .query_row(
            "SELECT shares.token_key_id,shares.token_ciphertext,
                    admins.totp_key_id,admins.totp_ciphertext
             FROM shares JOIN admins ON admins.id=shares.created_by",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(after.0 > before.0);
    assert!(after.2 > before.2);
    assert_ne!(after.1, before.1);
    assert_ne!(after.3, before.3);
    assert_eq!(
        std::fs::metadata(directory.path().join("secrets.keyring"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn initialized_database_rejects_missing_or_unrelated_keyring_at_startup() {
    let missing_directory = tempfile::tempdir().unwrap();
    let missing_path = missing_directory.path().join("data.sqlite");
    let database = Database::open(&missing_path).unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    drop(database);
    std::fs::remove_file(missing_directory.path().join("secrets.keyring")).unwrap();
    assert!(matches!(
        Database::open(&missing_path),
        Err(DatabaseError::Cryptography(_))
    ));

    let first_directory = tempfile::tempdir().unwrap();
    let first_path = first_directory.path().join("data.sqlite");
    let first = Database::open(&first_path).unwrap();
    first.create_admin("admin", "hash", "secret").unwrap();
    drop(first);

    let second_directory = tempfile::tempdir().unwrap();
    let second_path = second_directory.path().join("data.sqlite");
    drop(Database::open(&second_path).unwrap());
    std::fs::copy(
        second_directory.path().join("secrets.keyring"),
        first_directory.path().join("secrets.keyring"),
    )
    .unwrap();
    assert!(matches!(
        Database::open(&first_path),
        Err(DatabaseError::Cryptography(_))
    ));
}

#[test]
fn startup_rejects_ciphertext_nonce_and_aad_manipulation() {
    for manipulation in ["ciphertext", "nonce", "aad"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.sqlite");
        let database = Database::open(&path).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database
            .create_share(
                "share-token",
                None,
                "file.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        if manipulation == "aad" {
            database
                .conn()
                .execute("UPDATE shares SET token_hash=?1", ["0".repeat(64)])
                .unwrap();
        } else {
            let mut ciphertext: Vec<u8> = database
                .conn()
                .query_row("SELECT token_ciphertext FROM shares", [], |row| row.get(0))
                .unwrap();
            let index = if manipulation == "nonce" {
                0
            } else {
                ciphertext.len() - 1
            };
            ciphertext[index] ^= 0x80;
            database
                .conn()
                .execute("UPDATE shares SET token_ciphertext=?1", [ciphertext])
                .unwrap();
        }
        drop(database);
        assert!(Database::open(&path).is_err(), "{manipulation}");
    }
}

#[test]
fn startup_validates_each_encrypted_secret_table() {
    for (table, corruption) in [
        (
            "admins",
            "UPDATE admins
             SET totp_ciphertext=zeroblob(length(totp_ciphertext))",
        ),
        (
            "admin_mfa_enrollments",
            "UPDATE admin_mfa_enrollments
             SET totp_ciphertext=zeroblob(length(totp_ciphertext))",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.sqlite");
        let database = Database::open(&path).unwrap();
        database.create_admin("admin", "hash", "secret").unwrap();
        database
            .start_admin_mfa_enrollment(1, "pending-token", "pending-secret")
            .unwrap();
        database.conn().execute(corruption, []).unwrap();
        drop(database);

        assert!(
            matches!(Database::open(&path), Err(DatabaseError::Cryptography(_))),
            "startup accepted corrupted {table} ciphertext"
        );
    }
}

#[test]
fn rejects_unversioned_legacy_and_wrong_schema_one_shape() {
    for (version, sql) in [
        (
            0,
            "CREATE TABLE shares(id INTEGER PRIMARY KEY, token TEXT NOT NULL);",
        ),
        (
            1,
            "CREATE TABLE shares(id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL);",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("legacy-{version}.sqlite"));
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        drop(connection);
        assert!(Database::open(path).is_err());
    }
}

#[test]
fn unlock_sessions_are_hashed_and_cascade_with_share() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let share_id = database
        .create_share(
            "share",
            None,
            "folder",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            Some("password-hash"),
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    let original_share = database.share_by_token("share").unwrap().unwrap();
    assert!(database
        .create_unlock_session_for_verified_password(
            "unlock-secret",
            share_id,
            original_share.password_hash.as_deref().unwrap(),
            original_share.upload_policy_epoch,
            "unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    assert!(database.unlock_session("unlock-secret", share_id).unwrap());
    assert_eq!(
        database
            .unlock_session_csrf("unlock-secret", share_id)
            .unwrap()
            .as_deref(),
        Some("unlock-csrf")
    );
    let stored: String = database
        .conn()
        .query_row("SELECT token_hash FROM public_unlock_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_ne!(stored, "unlock-secret");
    database
        .set_share_password(share_id, Some("new-password-hash"))
        .unwrap();
    assert!(!database.unlock_session("unlock-secret", share_id).unwrap());
    assert!(!database
        .create_unlock_session_for_verified_password(
            "stale-unlock-secret",
            share_id,
            original_share.password_hash.as_deref().unwrap(),
            original_share.upload_policy_epoch,
            "stale-unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    assert!(!database
        .unlock_session("stale-unlock-secret", share_id)
        .unwrap());
    let updated_share = database.share_by_token("share").unwrap().unwrap();
    assert!(updated_share.upload_policy_epoch > original_share.upload_policy_epoch);
    assert!(database
        .create_unlock_session_for_verified_password(
            "new-unlock-secret",
            share_id,
            updated_share.password_hash.as_deref().unwrap(),
            updated_share.upload_policy_epoch,
            "new-unlock-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    database
        .set_share_password(share_id, updated_share.password_hash.as_deref())
        .unwrap();
    assert!(!database
        .unlock_session("new-unlock-secret", share_id)
        .unwrap());
    assert!(!database
        .create_unlock_session_for_verified_password(
            "same-hash-stale-secret",
            share_id,
            updated_share.password_hash.as_deref().unwrap(),
            updated_share.upload_policy_epoch,
            "same-hash-stale-csrf",
            Utc::now() + chrono::Duration::minutes(60),
        )
        .unwrap());
    database.delete_share(share_id).unwrap();
    assert_eq!(
        database
            .conn()
            .query_row::<i64, _, _>("SELECT COUNT(*) FROM public_unlock_sessions", [], |row| {
                row.get(0)
            })
            .unwrap(),
        0
    );
}
