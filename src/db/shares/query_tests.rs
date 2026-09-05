use super::*;
use crate::db::ShareListStatus;
use rusqlite::StatementStatus;

#[test]
fn deep_share_pages_seek_in_both_directions_including_deleted_cursor_and_search() {
    let database = crate::db::tests::large_share_fixture(300_000);
    let connection = database.conn();
    connection
        .execute("DELETE FROM shares WHERE id IN (100000,200000)", [])
        .unwrap();
    for sort in [ShareListSort::Newest, ShareListSort::Oldest] {
        for cursor in [None, Some(100_000), Some(200_000)] {
            for needle in [None, Some("fi"), Some("file")] {
                let options = ShareListOptions {
                    status: ShareListStatus::All,
                    sort,
                    cursor,
                    query: needle.map(str::to_string),
                    limit: 100,
                    now: Utc::now(),
                };
                let sql = share_page_sql(&options, needle);
                let mut statement = connection.prepare(&sql).unwrap();
                let collect = |row: &rusqlite::Row<'_>| row.get::<_, i64>(0);
                let started = std::time::Instant::now();
                let ids = match needle {
                    Some(value) if value.len() >= 3 => statement.query_map(
                        params![
                            options.now.to_rfc3339(),
                            cursor,
                            101,
                            fts5_phrase(value),
                            value
                        ],
                        collect,
                    ),
                    Some(value) => statement.query_map(
                        params![options.now.to_rfc3339(), cursor, 101, value],
                        collect,
                    ),
                    None => {
                        statement.query_map(params![options.now.to_rfc3339(), cursor, 101], collect)
                    }
                }
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
                assert_eq!(ids.len(), 101);
                assert!(ids.windows(2).all(|pair| match sort {
                    ShareListSort::Newest => pair[0] > pair[1],
                    ShareListSort::Oldest => pair[0] < pair[1],
                }));
                if let Some(cursor) = cursor {
                    assert_eq!(
                        ids[0],
                        match sort {
                            ShareListSort::Newest => cursor - 1,
                            ShareListSort::Oldest => cursor + 1,
                        }
                    );
                }
                assert!(
                    statement.get_status(StatementStatus::VmStep) < 8_000,
                    "{sql}"
                );
                assert!(
                    statement.get_status(StatementStatus::FullscanStep) <= 101,
                    "{sql}"
                );
                assert_eq!(statement.get_status(StatementStatus::Sort), 0, "{sql}");
                eprintln!(
                    "share cursor={cursor:?} needle={needle:?} elapsed_us={} vm_steps={}",
                    started.elapsed().as_micros(),
                    statement.get_status(StatementStatus::VmStep)
                );
            }
        }
    }
}
