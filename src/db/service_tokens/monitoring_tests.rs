use super::*;
use rusqlite::StatementStatus;

#[test]
fn monitoring_deep_pages_use_bounded_keyset_work() {
    let database = crate::db::tests::large_share_fixture(300_000);
    let connection = database.conn();
    for cursor in [None, Some(200_000), Some(100_000)] {
        for status in [
            MonitoringShareListStatus::All,
            MonitoringShareListStatus::Available,
        ] {
            let mut statement = connection
                .prepare(monitoring_share_query_for(status, cursor.is_some()))
                .unwrap();
            let started = std::time::Instant::now();
            let ids = statement
                .query_map(params![Utc::now().to_rfc3339(), cursor, 101], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ids.len(), 101);
            assert_eq!(ids[0], cursor.map_or(300_000, |id| id - 1));
            assert!(statement.get_status(StatementStatus::VmStep) < 8_000);
            assert!(statement.get_status(StatementStatus::FullscanStep) <= 101);
            eprintln!(
                "monitoring cursor={cursor:?} elapsed_us={} vm_steps={}",
                started.elapsed().as_micros(),
                statement.get_status(StatementStatus::VmStep)
            );
        }
    }
}
