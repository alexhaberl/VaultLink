#[test]
fn audit_bounds_reject_before_mutation_and_limit_historical_projection() {
    let db = Database::open(":memory:").unwrap();
    let oversized = "x".repeat(900_000);
    assert!(db
        .audit_action_with_client_ip(AuditAction::LoginFailed, &oversized, None, None, None)
        .is_err());
    let called = std::cell::Cell::new(false);
    let failure = db
        .required_transaction(&AuditContext::new(&oversized, None), |_| {
            called.set(true);
            Ok(((), Vec::new()))
        })
        .unwrap_err();
    assert!(is_audit_unavailable(&failure));
    assert!(!called.get());
    assert_eq!(db.count_audit(None).unwrap(), 0);
    // Simulate rows already stored by an older binary; never rewrite them.
    for actor in [&oversized, "a", "z"] {
        db.audit(actor, "login_failed", None, None).unwrap();
    }
    let rows = db
        .list_audit_keyset(
            None,
            2,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
            None,
            AuditKeysetPosition::After,
        )
        .unwrap();
    assert_eq!(rows[0].actor, "a");
    assert_eq!(rows[1].actor, "<oversized:900000 bytes>");
    let cursor = rows[1].cursor(AuditSortColumn::Actor);
    assert!(cursor.value.is_none());
    let next = db
        .list_audit_keyset(
            None,
            2,
            AuditSortColumn::Actor,
            AuditSortDirection::Ascending,
            Some(&cursor),
            AuditKeysetPosition::After,
        )
        .unwrap();
    assert_eq!(next[0].actor, "z");
    let original: i64 = db
        .conn()
        .query_row("SELECT length(actor) FROM audit WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(original, 900_000);
    for (actor, detail, allowed) in [
        ("a".repeat(64), "d".repeat(16384), true),
        ("a".repeat(65), String::new(), false),
        ("a".into(), "d".repeat(16385), false),
        ("é".repeat(33), String::new(), false),
    ] {
        assert_eq!(
            db.audit_action_with_client_ip(
                AuditAction::LoginFailed,
                &actor,
                None,
                Some(&detail),
                None
            )
            .is_ok(),
            allowed
        );
    }
}
