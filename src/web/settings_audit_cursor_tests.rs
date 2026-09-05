use super::*;

#[test]
fn cursor_v2_omits_historical_payload_and_v1_remains_readable() {
    let sort = AuditSortColumn::Actor;
    let direction = AuditSortDirection::Ascending;
    let cursor = AuditCursor {
        id: 42,
        value: Some("x".repeat(900_000)),
    };
    let encoded =
        encode_audit_cursor(&cursor, AuditKeysetPosition::After, "", sort, direction).unwrap();
    assert!(encoded.len() < 256);
    let decoded = decode_audit_cursor(&encoded, "", sort, direction)
        .unwrap()
        .0;
    assert_eq!(decoded.id, 42);
    assert!(decoded.value.is_none());
    let old = serde_json::json!({"value":"admin", "id":42, "position":"after",
        "action":"", "sort":audit_sort_column_value(sort), "direction":audit_sort_direction_value(direction)});
    let encode = |value: &serde_json::Value| {
        data_encoding::BASE64URL_NOPAD.encode(&serde_json::to_vec(value).unwrap())
    };
    assert_eq!(
        decode_audit_cursor(&encode(&old), "", sort, direction)
            .unwrap()
            .0
            .value
            .as_deref(),
        Some("admin")
    );
    assert!(decode_audit_cursor(&encoded, "login_failed", sort, direction).is_none());
    for (field, value) in [
        ("version", serde_json::json!(3)),
        ("id", serde_json::json!(0)),
        ("version", serde_json::json!(2)),
    ] {
        let mut invalid = old.clone();
        invalid[field] = value;
        assert!(decode_audit_cursor(&encode(&invalid), "", sort, direction).is_none());
    }
    assert!(decode_audit_cursor(&"x".repeat(8193), "", sort, direction).is_none());
}
