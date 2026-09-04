#[test]
fn webauthn_credentials_are_scoped_unique_and_mutable() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database.create_admin("other", "hash", "secret").unwrap();

    let id = database
        .add_admin_webauthn_credential(1, "Primary YubiKey", "credential-a", "{\"v\":1}")
        .unwrap();
    let rows = database.admin_webauthn_credentials(1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].label, "Primary YubiKey");
    assert!(rows[0].last_used_at.is_none());
    assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
    assert!(database
        .add_admin_webauthn_credential(1, "", "credential-empty-label", "{}")
        .is_err());
    assert!(database
        .add_admin_webauthn_credential(1, &"x".repeat(81), "credential-long-label", "{}")
        .is_err());

    assert!(database
        .add_admin_webauthn_credential(2, "Duplicate", "credential-a", "{}")
        .is_err());
    assert!(!database
        .update_admin_webauthn_credential(id, 2, "{\"v\":2}")
        .unwrap());
    assert!(database
        .update_admin_webauthn_credential(id, 1, "{\"v\":2}")
        .unwrap());
    let rows = database.admin_webauthn_credentials(1).unwrap();
    assert_eq!(rows[0].credential_blob, b"{\"v\":2}");
    assert!(rows[0].last_used_at.is_some());

    assert!(!database.delete_admin_webauthn_credential(id, 2).unwrap());
    assert!(database.delete_admin_webauthn_credential(id, 1).unwrap());
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

    let first = database
        .add_admin_webauthn_credential(1, "Primary", "credential-c", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Backup", "credential-d", "{}")
        .unwrap();
    assert!(!database.delete_admin_webauthn_credential(first, 1).unwrap());
    database
        .add_admin_webauthn_credential(1, "Replacement", "credential-e", "{}")
        .unwrap();
    assert!(database.delete_admin_webauthn_credential(first, 1).unwrap());
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 2);

    database
        .add_admin_webauthn_credential(2, "Backup", "credential-b", "{}")
        .unwrap();
    database
        .conn()
        .execute("DELETE FROM admins WHERE id=2", [])
        .unwrap();
    assert!(database.admin_webauthn_credentials(2).unwrap().is_empty());
}

#[test]
fn security_mutation_webauthn_deletion_consumes_totp_and_audits_atomically() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .create_session(
            "authorized-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());
    database
        .create_session("other-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("other-session").unwrap());
    let first = database
        .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
        .unwrap();
    let second = database
        .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
        .unwrap();
    let third = database
        .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
        .unwrap();
    let delete = |session_token, credential_id, step, client_ip| {
        database.delete_admin_webauthn_credential_with_totp(
            session_token,
            credential_id,
            1,
            "hash",
            1,
            step,
            client_ip,
        )
    };

    assert_eq!(
        delete("authorized-session", first, 42, Some("203.0.113.40")).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    assert!(database.session("authorized-session").unwrap().is_none());
    assert!(database.session("other-session").unwrap().is_none());
    let audit = database
        .list_audit(Some("webauthn_credential_deleted"), 10, 0)
        .unwrap();
    assert_eq!(audit.len(), 1);
    let first_object = first.to_string();
    assert_eq!(audit[0].object_id.as_deref(), Some(first_object.as_str()));
    assert_eq!(audit[0].client_ip.as_deref(), Some("203.0.113.40"));

    database
        .create_session("second-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("second-session").unwrap());

    assert_eq!(
        delete("second-session", second, 42, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::TotpRejected
    );
    assert_eq!(
        delete("second-session", second, 43, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::NotDeleted
    );
    database
        .add_admin_webauthn_credential(1, "Fourth", "credential-d", "{}")
        .unwrap();

    assert_eq!(
        delete("second-session", second, 43, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    database
        .add_admin_webauthn_credential(1, "Fifth", "credential-e", "{}")
        .unwrap();

    database
        .create_session("third-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("third-session").unwrap());

    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_webauthn_delete_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='webauthn_credential_deleted'
                 BEGIN
                     SELECT RAISE(ABORT, 'forced audit failure');
                 END;",
        )
        .unwrap();
    assert!(delete("third-session", third, 44, None).is_err());
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
    database
        .conn()
        .execute_batch("DROP TRIGGER fail_webauthn_delete_audit")
        .unwrap();

    assert_eq!(
        delete("third-session", third, 44, None).unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_deleted"))
            .unwrap(),
        3
    );
}

#[test]
fn security_mutation_webauthn_deletion_rejects_stale_credentials_and_session() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "original-hash", "original-secret")
        .unwrap();
    database
        .create_session("stale-session", 1, "csrf", Utc::now() + Duration::hours(1))
        .unwrap();
    assert!(database.verify_mfa("stale-session").unwrap());
    let first = database
        .add_admin_webauthn_credential(1, "First", "credential-a", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Second", "credential-b", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Third", "credential-c", "{}")
        .unwrap();

    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "wrong-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "original-hash",
                2,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );

    assert!(database
        .reset_admin_password(1, "replacement-hash")
        .unwrap());
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "stale-session",
                first,
                1,
                "original-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
    );
    assert_eq!(database.admin_webauthn_credentials(1).unwrap().len(), 3);
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_deleted"))
            .unwrap(),
        0
    );

    database
        .create_session(
            "replacement-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("replacement-session").unwrap());
    assert_eq!(
        database
            .delete_admin_webauthn_credential_with_totp(
                "replacement-session",
                first,
                1,
                "replacement-hash",
                1,
                42,
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );
}

#[test]
fn totp_setting_requires_two_keys_and_protects_key_only_accounts() {
    let database = Database::open(":memory:").unwrap();
    database
        .create_admin("admin", "password-hash", "totp-secret")
        .unwrap();
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);
    database
        .create_session(
            "authorized-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());

    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                Some(41),
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::InsufficientSecurityKeys
    );

    let first = database
        .add_admin_webauthn_credential(1, "Primary", "credential-a", "{}")
        .unwrap();
    database
        .add_admin_webauthn_credential(1, "Backup", "credential-b", "{}")
        .unwrap();
    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                None,
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::TotpRejected
    );
    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "authorized-session",
                1,
                "password-hash",
                1,
                false,
                Some(42),
                Some("203.0.113.60"),
            )
            .unwrap(),
        AdminTotpSettingOutcome::Updated
    );
    assert!(!database.admin("admin").unwrap().unwrap().totp_enabled);
    let disabled_audit = database
        .list_audit(Some("admin_totp_disabled"), 1, 0)
        .unwrap();
    assert_eq!(disabled_audit.len(), 1);
    assert_eq!(disabled_audit[0].client_ip.as_deref(), Some("203.0.113.60"));

    assert_eq!(
        database
            .delete_admin_webauthn_credential_without_totp(
                "authorized-session",
                first,
                1,
                "password-hash",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::NotDeleted
    );
    database
        .add_admin_webauthn_credential(1, "Spare", "credential-c", "{}")
        .unwrap();
    assert_eq!(
        database
            .delete_admin_webauthn_credential_without_totp(
                "authorized-session",
                first,
                1,
                "password-hash",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialDeletionOutcome::Deleted
    );

    database
        .create_session(
            "replacement-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    assert!(database.verify_mfa("replacement-session").unwrap());

    assert_eq!(
        database
            .set_admin_totp_enabled_with_reauthentication(
                "replacement-session",
                1,
                "password-hash",
                1,
                true,
                None,
                None,
            )
            .unwrap(),
        AdminTotpSettingOutcome::Updated
    );
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);

    assert_eq!(
        database.reset_admin_totp(1, "new-totp-secret").unwrap(),
        Some("admin".into())
    );
    assert!(database.admin("admin").unwrap().unwrap().totp_enabled);
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());
}

#[test]
fn webauthn_registration_cannot_restore_keys_after_mfa_reset() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    let expires = Utc::now() + chrono::Duration::hours(1);

    database
        .create_session("authorized-session", 1, "csrf", expires)
        .unwrap();
    assert!(database.verify_mfa("authorized-session").unwrap());
    assert!(matches!(
        database
            .add_admin_webauthn_credential_for_session(
                "authorized-session",
                1,
                "Primary",
                "credential-a",
                "{}",
                Some("203.0.113.24"),
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::Registered(_)
    ));
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .list_audit(Some("webauthn_credential_added"), 1, 0)
            .unwrap()[0]
            .client_ip
            .as_deref(),
        Some("203.0.113.24")
    );

    database
        .create_session("stale-session", 1, "csrf", expires)
        .unwrap();
    assert!(database.verify_mfa("stale-session").unwrap());
    assert_eq!(
        database.reset_admin_totp(1, "replacement-secret").unwrap(),
        Some("admin".to_string())
    );
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());

    assert_eq!(
        database
            .add_admin_webauthn_credential_for_session(
                "stale-session",
                1,
                "Stale",
                "credential-stale",
                "{}",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
    );
    assert!(database.admin_webauthn_credentials(1).unwrap().is_empty());
    assert_eq!(
        database
            .count_audit(Some("webauthn_credential_added"))
            .unwrap(),
        1
    );

    database
        .create_session("pre-mfa-session", 1, "csrf", expires)
        .unwrap();
    assert_eq!(
        database
            .add_admin_webauthn_credential_for_session(
                "pre-mfa-session",
                1,
                "Pre MFA",
                "credential-pre-mfa",
                "{}",
                None,
            )
            .unwrap(),
        AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
    );
}
