use super::*;
use crate::db::ShareListStatus;
use rusqlite::StatementStatus;

fn reference_ids(connection: &rusqlite::Connection, options: &ShareListOptions) -> Vec<i64> {
    // Deliberately simple full selection, independent of the optimized predicates.
    let status = match options.status {
        ShareListStatus::All => "all",
        ShareListStatus::Active => "active",
        ShareListStatus::Inactive => "inactive",
        ShareListStatus::Protected => "protected",
        ShareListStatus::Expired => "expired",
        ShareListStatus::LimitReached => "limit",
    };
    let sql = format!(
        "SELECT id FROM shares WHERE
        (?1='all' OR (?1='active' AND active AND (expires_at IS NULL OR expires_at>?2)
          AND (max_downloads IS NULL OR download_count<max_downloads))
        OR (?1='inactive' AND NOT active) OR (?1='protected' AND password_hash IS NOT NULL)
        OR (?1='expired' AND expires_at<=?2)
        OR (?1='limit' AND download_count>=max_downloads))
        AND (?3 IS NULL OR instr(alias_search_key,?3)>0 OR instr(path_search_key,?3)>0)
        AND (?4 IS NULL OR (?5 AND id<?4) OR (NOT ?5 AND id>?4))
        ORDER BY id {} LIMIT ?6",
        direction(options)
    );
    connection
        .prepare(&sql)
        .unwrap()
        .query_map(
            params![
                status,
                options.now.to_rfc3339(),
                options.query.as_deref(),
                options.cursor,
                options.sort == ShareListSort::Newest,
                options.limit + 1
            ],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn share_candidate_matrix_matches_reference_at_100k_and_300k() {
    for count in [100_000, 300_000] {
        let database = crate::db::tests::large_share_fixture(count);
        let connection = database.conn();
        connection
            .execute_batch(
                "UPDATE shares SET
            active=(id%7!=0), password_hash=CASE WHEN id%37=0 THEN 'protected' END,
            expires_at=CASE WHEN id%19=0 THEN '2020-01-01T00:00:00+00:00'
                WHEN id%3=0 THEN '2099-01-01T00:00:00+00:00' END,
            max_downloads=CASE WHEN id%41=0 THEN 1 END, download_count=(id%41=0),
            alias=CASE WHEN id%997=0 THEN 'rare-'||id END,
            alias_search_key=CASE WHEN id%997=0 THEN 'rare-'||id END;
            DELETE FROM shares WHERE id IN (50000,150000);",
            )
            .unwrap();
        for status in [
            ShareListStatus::All,
            ShareListStatus::Active,
            ShareListStatus::Protected,
            ShareListStatus::Expired,
            ShareListStatus::LimitReached,
            ShareListStatus::Inactive,
        ] {
            for sort in [ShareListSort::Newest, ShareListSort::Oldest] {
                for cursor in [None, Some(count / 2), Some(count - 501)] {
                    for query in [None, Some("file"), Some("rare"), Some("missing")] {
                        let options = ShareListOptions {
                            status,
                            sort,
                            cursor,
                            query: query.map(str::to_owned),
                            limit: 100,
                            now: Utc::now(),
                        };
                        let actual = candidate_ids(&connection, &options, query).unwrap();
                        assert_eq!(actual, reference_ids(&connection, &options),
                            "count={count} status={status:?} sort={sort:?} cursor={cursor:?} query={query:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn unsuccessful_status_filters_have_bounded_work_as_the_database_grows() {
    let mut baseline = Vec::new();
    for count in [100_000, 300_000] {
        let database = crate::db::tests::large_share_fixture(count);
        let connection = database.conn();
        for status in [
            ShareListStatus::Protected,
            ShareListStatus::Expired,
            ShareListStatus::LimitReached,
        ] {
            for query in [None, Some("missing"), Some("file")] {
                let options = ShareListOptions {
                    status,
                    sort: ShareListSort::Newest,
                    cursor: Some(count / 2),
                    query: query.map(str::to_owned),
                    limit: 100,
                    now: Utc::now(),
                };
                CANDIDATE_WORK.with(|work| work.set(CandidateWork::default()));
                assert!(candidate_ids(&connection, &options, query)
                    .unwrap()
                    .is_empty());
                let work = CANDIDATE_WORK.with(std::cell::Cell::get);
                assert!(work.scans <= 808, "bounded window: {work:?}");
                eprintln!("no-match count={count} status={status:?} query={query:?} work={work:?}");
                if count == 100_000 {
                    baseline.push(work.vm);
                } else {
                    assert!(work.vm <= baseline.remove(0) + 100, "work grew: {work:?}");
                }
            }
        }
        connection
            .execute(
                "UPDATE shares SET expires_at='2020-01-01T00:00:00+00:00'",
                [],
            )
            .unwrap();
        let options = ShareListOptions {
            status: ShareListStatus::Active,
            sort: ShareListSort::Oldest,
            cursor: None,
            query: None,
            limit: 100,
            now: Utc::now(),
        };
        CANDIDATE_WORK.with(|work| work.set(CandidateWork::default()));
        assert!(candidate_ids(&connection, &options, None)
            .unwrap()
            .is_empty());
        let work = CANDIDATE_WORK.with(std::cell::Cell::get);
        assert!(
            work.vm < 30_000 && work.scans <= 808,
            "expired-only active filter: {work:?}"
        );
    }
}

#[test]
fn deep_share_pages_seek_in_both_directions_including_deleted_cursor_and_search() {
    let database = crate::db::tests::large_share_fixture(300_000);
    let connection = database.conn();
    connection
        .execute("DELETE FROM shares WHERE id IN (100000,200000)", [])
        .unwrap();
    for sort in [ShareListSort::Newest, ShareListSort::Oldest] {
        for cursor in [None, Some(100_000), Some(200_000)] {
            for needle in [None, Some("file")] {
                let options = ShareListOptions {
                    status: ShareListStatus::All,
                    sort,
                    cursor,
                    query: needle.map(str::to_string),
                    limit: 100,
                    now: Utc::now(),
                };
                let sql = direct_candidate_sql(&options, needle.is_some());
                let mut statement = connection.prepare(&sql).unwrap();
                let collect = |row: &rusqlite::Row<'_>| row.get::<_, i64>(0);
                let started = std::time::Instant::now();
                let ids = statement
                    .query_map(
                        params![
                            options.now.to_rfc3339(),
                            cursor,
                            needle.map(fts5_phrase),
                            needle,
                            101
                        ],
                        collect,
                    )
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
