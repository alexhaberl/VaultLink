#[test]
fn audit_client_ips_are_optional_listed_and_purgeable_without_deleting_events() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit("admin", "settings_updated", None, None)
        .unwrap();
    database
        .audit_with_client_ip(
            "public",
            "share_unlock_failed",
            Some("7"),
            Some("rate limited"),
            Some("203.0.113.24"),
        )
        .unwrap();

    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    assert_eq!(database.count_audit(None).unwrap(), 2);
    assert_eq!(database.count_audit(Some("settings_updated")).unwrap(), 1);
    assert_eq!(database.count_audit(Some("missing_action")).unwrap(), 0);
    let events = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].client_ip.as_deref(), Some("203.0.113.24"));
    assert!(events[1].client_ip.is_none());

    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(1)
    );
    assert_eq!(database.count_audit_client_ips().unwrap(), 0);
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(0)
    );
    let events = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.client_ip.is_none()));
}

#[test]
fn audit_listing_sorts_only_by_the_selected_whitelisted_column() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit("zulu", "z_action", Some("2"), Some("later alphabetically"))
        .unwrap();
    database
        .audit(
            "Alpha",
            "a_action",
            Some("1"),
            Some("earlier alphabetically"),
        )
        .unwrap();

    let default = database.list_audit(None, 10, 0).unwrap();
    assert_eq!(default[0].actor, "Alpha");

    let ascending = database
        .list_audit_sorted(
            None,
            10,
            0,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
        )
        .unwrap();
    assert_eq!(
        ascending
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "zulu"]
    );

    let descending = database
        .list_audit_sorted(
            None,
            10,
            0,
            AuditSortColumn::Actor,
            AuditSortDirection::Descending,
        )
        .unwrap();
    assert_eq!(
        descending
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["zulu", "Alpha"]
    );
}

#[test]
fn audit_keyset_pages_are_gapless_in_both_directions() {
    let database = Database::open(":memory:").unwrap();
    for actor in ["delta", "Alpha", "charlie", "bravo"] {
        database.audit(actor, "keyset", Some(actor), None).unwrap();
    }
    let first = database
        .list_audit_keyset(
            Some("keyset"),
            2,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
            None,
            AuditKeysetPosition::After,
        )
        .unwrap();
    assert_eq!(
        first
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "bravo"]
    );
    let second = database
        .list_audit_keyset(
            Some("keyset"),
            2,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
            first
                .last()
                .map(|event| event.cursor(AuditSortColumn::Actor))
                .as_ref(),
            AuditKeysetPosition::After,
        )
        .unwrap();
    assert_eq!(
        second
            .iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["charlie", "delta"]
    );
    let back = database
        .list_audit_keyset(
            Some("keyset"),
            2,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
            second
                .first()
                .map(|event| event.cursor(AuditSortColumn::Actor))
                .as_ref(),
            AuditKeysetPosition::Before,
        )
        .unwrap();
    assert_eq!(
        back.iter()
            .map(|event| event.actor.as_str())
            .collect::<Vec<_>>(),
        ["Alpha", "bravo"]
    );
}

#[test]
fn standard_audit_order_uses_an_index_without_a_temporary_btree() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    let details = connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id,occurred_at,actor,action,object_id,detail,client_ip
             FROM audit ORDER BY occurred_at DESC,id DESC LIMIT 100",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        details
            .iter()
            .all(|detail| !detail.contains("USE TEMP B-TREE")),
        "{details:?}"
    );
    let filtered_details = connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT id,occurred_at,actor,action,object_id,detail,client_ip
             FROM audit WHERE action=?1
             ORDER BY occurred_at DESC,id DESC LIMIT 100",
        )
        .unwrap()
        .query_map(["upload"], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        filtered_details
            .iter()
            .all(|detail| !detail.contains("USE TEMP B-TREE")),
        "{filtered_details:?}"
    );
}

#[test]
fn audited_client_ip_purge_rolls_back_when_required_audit_fails() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit_with_client_ip("public", "existing_event", None, None, Some("203.0.113.24"))
        .unwrap();
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    database
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_audit_ip_purge_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='audit_client_ips_deleted'
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
        )
        .unwrap();
    let context = AuditContext::new("admin", None);

    let error = database
        .delete_audit_client_ips_if_disabled_and_audit(false, &context)
        .unwrap_err();
    assert!(is_audit_unavailable(&error));
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);
    assert_eq!(
        database
            .count_audit(Some("audit_client_ips_deleted"))
            .unwrap(),
        0
    );
}

#[test]
fn audit_ip_writes_and_purge_follow_the_persisted_privacy_setting() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
        .unwrap();
    database
        .audit_with_client_ip("public", "before_disable", None, None, Some("203.0.113.40"))
        .unwrap();

    // The committed setting wins over a stale in-memory fallback.
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::LoggingEnabled
    );

    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "false".to_string())], 1)
        .unwrap();
    // Model a delayed request that captured the IP while logging was still
    // enabled but reaches SQLite only after the disabling commit.
    database
        .audit_with_client_ip(
            "public",
            "delayed_after_disable",
            None,
            None,
            Some("203.0.113.41"),
        )
        .unwrap();
    let delayed = database
        .list_audit(Some("delayed_after_disable"), 1, 0)
        .unwrap();
    assert_eq!(delayed.len(), 1);
    assert!(delayed[0].client_ip.is_none());
    assert_eq!(database.count_audit_client_ips().unwrap(), 1);

    assert_eq!(
        database.delete_audit_client_ips_if_disabled(true).unwrap(),
        AuditClientIpDeletionOutcome::Deleted(1)
    );
    assert_eq!(database.count_audit_client_ips().unwrap(), 0);

    database
        .replace_runtime_settings(&[("audit_client_ip_enabled", "true".to_string())], 1)
        .unwrap();
    assert_eq!(
        database.delete_audit_client_ips_if_disabled(false).unwrap(),
        AuditClientIpDeletionOutcome::LoggingEnabled
    );
}

#[test]
fn audit_retention_keeps_only_the_newest_rows() {
    let database = Database::open(":memory:").unwrap();
    database.create_admin("admin", "hash", "secret").unwrap();
    {
        let mut connection = database.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        for index in 0..6 {
            transaction
                .execute(
                    "INSERT INTO audit(
                             occurred_at,actor,action,object_id,detail,client_ip
                         ) VALUES(?1,'test',?2,NULL,NULL,NULL)",
                    params![Utc::now().to_rfc3339(), format!("event-{index}")],
                )
                .unwrap();
            enforce_audit_retention(&transaction, 3).unwrap();
        }
        transaction.commit().unwrap();
    }

    let actions: Vec<String> = {
        let connection = database.conn();
        let mut statement = connection
            .prepare("SELECT action FROM audit ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(
        actions,
        vec![
            "event-3".to_string(),
            "event-4".to_string(),
            "event-5".to_string()
        ]
    );
}

#[test]
fn audit_action_policy_has_unique_names_and_explicit_priorities() {
    let mut names = std::collections::HashSet::new();
    assert_eq!(AuditAction::ALL.len(), 55);
    for action in AuditAction::ALL {
        assert!(
            names.insert(action.as_str()),
            "duplicate action {}",
            action.as_str()
        );
        let expected = match action {
            AuditAction::AdminDownload
            | AuditAction::AdminPreview
            | AuditAction::Download
            | AuditAction::Preview
            | AuditAction::UploadQuotaCommitted
            | AuditAction::ZipDownload => AuditPriority::Routine,
            _ => AuditPriority::Security,
        };
        assert_eq!(action.priority(), expected, "action {}", action.as_str());
    }
}

#[test]
fn typed_audit_writer_persists_policy_priority() {
    let database = Database::open(":memory:").unwrap();
    for action in AuditAction::ALL {
        database
            .audit_action_with_client_ip(*action, "policy-test", None, None, None)
            .unwrap();
    }
    for action in AuditAction::ALL {
        assert_eq!(
            database.audit_priorities(action.as_str()).unwrap(),
            [action.priority().as_i64()]
        );
    }
}

#[test]
fn audit_retention_preserves_security_events_during_routine_volume() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    connection
        .execute(
            "INSERT INTO audit(occurred_at,actor,action,priority)
             VALUES(?1,'local_recovery','admin_recovered',100)",
            [Utc::now().to_rfc3339()],
        )
        .unwrap();
    for index in 0..4 {
        connection
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,priority)
                 VALUES(?1,'public',?2,0)",
                params![Utc::now().to_rfc3339(), format!("download-{index}")],
            )
            .unwrap();
    }

    assert_eq!(enforce_audit_retention(&connection, 3).unwrap(), 2);
    let actions: Vec<String> = connection
        .prepare("SELECT action FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(actions, ["admin_recovered", "download-2", "download-3"]);
}

#[test]
fn audit_retention_falls_back_to_fifo_for_security_only_volume() {
    let database = Database::open(":memory:").unwrap();
    let connection = database.conn();
    for index in 0..5 {
        connection
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,priority)
                 VALUES(?1,'admin',?2,100)",
                params![Utc::now().to_rfc3339(), format!("security-{index}")],
            )
            .unwrap();
    }

    assert_eq!(enforce_audit_retention(&connection, 3).unwrap(), 2);
    let actions: Vec<String> = connection
        .prepare("SELECT action FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(actions, ["security-2", "security-3", "security-4"]);
}

#[test]
fn background_audit_retention_preserves_rows_below_the_cap() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit_action_with_client_ip(
            AuditAction::Upload,
            "public",
            Some("share-1"),
            Some("file=evidence.txt"),
            None,
        )
        .unwrap();

    assert_eq!(
        database.cleanup_audit_retention().unwrap(),
        AuditRetentionOutcome::default()
    );
    assert_eq!(database.count_audit(None).unwrap(), 1);
    assert_eq!(database.count_audit(Some("upload")).unwrap(), 1);
    assert_eq!(database.audit_priorities("upload").unwrap(), [100]);
}

#[test]
fn concurrent_audit_retention_calls_are_serialized_in_process() {
    let database = Database::open(":memory:").unwrap();
    let guard = database
        .0
        .audit_retention_admission
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
    let worker_database = database.clone();
    let worker = std::thread::spawn(move || {
        started_sender.send(()).unwrap();
        let result = worker_database.cleanup_audit_retention();
        finished_sender.send(()).unwrap();
        result
    });
    started_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        finished_receiver.recv_timeout(std::time::Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    drop(guard);
    finished_receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        AuditRetentionOutcome::default()
    );
}

#[test]
fn audit_retention_caps_recent_events() {
    let database = Database::open(":memory:").unwrap();
    database
        .audit_action_with_client_ip(
            AuditAction::Upload,
            "public",
            Some("share-1"),
            Some("file=evidence.txt"),
            None,
        )
        .unwrap();
    let mut connection = database.conn();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    for index in 0..MAX_AUDIT_ROWS + 1_234 {
        transaction
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip)
                 VALUES(?1,'test',?2,NULL,NULL,NULL)",
                params![Utc::now().to_rfc3339(), format!("event-{index}")],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    drop(connection);

    assert_eq!(
        database.cleanup_audit_retention().unwrap(),
        AuditRetentionOutcome {
            routine_deleted: 1_235,
            security_deleted: 0,
        }
    );
    assert_eq!(database.count_audit(None).unwrap(), MAX_AUDIT_ROWS as usize);
    assert_eq!(database.count_audit(Some("upload")).unwrap(), 1);
    assert_eq!(database.audit_priorities("upload").unwrap(), [100]);
}

#[test]
fn audit_retention_reports_security_eviction_when_only_security_rows_remain() {
    let database = Database::open(":memory:").unwrap();
    let mut connection = database.conn();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    for index in 0..=MAX_AUDIT_ROWS {
        transaction
            .execute(
                "INSERT INTO audit(occurred_at,actor,action,priority)
                 VALUES(?1,'test',?2,100)",
                params![Utc::now().to_rfc3339(), format!("security-{index}")],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    drop(connection);

    assert_eq!(
        database.cleanup_audit_retention().unwrap(),
        AuditRetentionOutcome {
            routine_deleted: 0,
            security_deleted: 1,
        }
    );
}
