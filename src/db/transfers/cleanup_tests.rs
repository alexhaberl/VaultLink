use super::*;
use rusqlite::StatementStatus;

#[test]
fn cleanup_uses_indexes_at_one_hundred_and_three_hundred_thousand_grants() {
    let database = crate::db::tests::large_share_fixture(2);
    let mut connection = database.conn();
    for count in [100_000, 300_000] {
        connection
            .execute("DELETE FROM public_transfer_grants", [])
            .unwrap();
        connection
            .execute(
                "WITH RECURSIVE ids(id) AS (SELECT 1 UNION ALL SELECT id+1 FROM ids WHERE id<?1)
             INSERT INTO public_transfer_grants(id,session_token_hash,share_id,resource_key,
                 action,counted,created_at,expires_at)
             SELECT id,CAST(id AS TEXT),1,'file.bin','download',1,'2026','2099' FROM ids",
                [count],
            )
            .unwrap();
        for sql in [
            CLEANUP_EXPIRED_LEASES,
            CLEANUP_EXPIRED_GRANTS,
            CLEANUP_ORPHAN_GRANTS,
            CLEANUP_EXPIRED_LEASES_HEARTBEAT,
            CLEANUP_EXPIRED_GRANTS_HEARTBEAT,
            CLEANUP_ORPHAN_GRANTS_HEARTBEAT,
        ] {
            let mut statement = connection.prepare(sql).unwrap();
            let started = std::time::Instant::now();
            let deleted = if statement.parameter_count() == 2 {
                statement.execute(params!["2027", "current"])
            } else {
                statement.execute(["2027"])
            }
            .unwrap();
            assert_eq!(deleted, 0);
            assert_eq!(
                statement.get_status(StatementStatus::FullscanStep),
                0,
                "{sql}"
            );
            assert!(statement.get_status(StatementStatus::VmStep) < 100, "{sql}");
            eprintln!(
                "cleanup rows={count} elapsed_us={} vm_steps={}",
                started.elapsed().as_micros(),
                statement.get_status(StatementStatus::VmStep)
            );
        }
    }
    // Expired/current leases and live/orphan reservations coexist. The heartbeat
    // must retain its current grant until the heartbeat decision has been made.
    connection
        .execute("DELETE FROM public_transfer_grants", [])
        .unwrap();
    for (id, counted, expires) in [
        (1, 1, "2026"),
        (2, 0, "2099"),
        (3, 0, "2099"),
        (4, 0, "2026"),
        (5, 1, "2099"),
    ] {
        connection
            .execute(
                "INSERT INTO public_transfer_grants VALUES(?1,?1,1,'f','download',?2,'2025',?3)",
                params![id, counted, expires],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO public_transfer_leases VALUES('live',3,'2025','2025','2099'),
        ('current',4,'2025','2025','2026'),('expired',5,'2025','2025','2026')",
            [],
        )
        .unwrap();
    let transaction = connection.transaction().unwrap();
    cleanup_transfer_state_before_heartbeat(&transaction, "2027", "current").unwrap();
    let ids = |transaction: &Transaction<'_>| -> Vec<i64> {
        transaction
            .prepare("SELECT id FROM public_transfer_grants ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(ids(&transaction), vec![3, 4, 5]);
    cleanup_transfer_state(&transaction, "2027").unwrap();
    assert_eq!(ids(&transaction), vec![3, 5]);
}
