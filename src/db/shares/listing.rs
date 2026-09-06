use super::*;
use crate::db::{ShareListSort, ShareListStatus};
use crate::share_search::validate_share_search;

const AVAILABLE: &str = "shares.active=1 AND (shares.max_downloads IS NULL OR shares.download_count<shares.max_downloads)";
const LITERAL_MATCH: &str =
    "(instr(shares.alias_search_key,?4)>0 OR instr(shares.path_search_key,?4)>0)";
const SELECT_SHARE: &str = "SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id";

fn status_predicate(status: ShareListStatus) -> String {
    match status {
        ShareListStatus::All => "1".into(),
        ShareListStatus::Active => {
            format!("{AVAILABLE} AND (shares.expires_at IS NULL OR shares.expires_at>?1)")
        }
        ShareListStatus::Protected => "shares.password_hash IS NOT NULL".into(),
        ShareListStatus::Expired => {
            "shares.expires_at IS NOT NULL AND shares.expires_at<=?1".into()
        }
        ShareListStatus::LimitReached => {
            "shares.max_downloads IS NOT NULL AND shares.download_count>=shares.max_downloads"
                .into()
        }
        ShareListStatus::Inactive => "shares.active=0".into(),
    }
}

fn direction(options: &ShareListOptions) -> &'static str {
    match options.sort {
        ShareListSort::Newest => "DESC",
        ShareListSort::Oldest => "ASC",
    }
}

fn cursor_predicate(options: &ShareListOptions, column: &str) -> String {
    if options.cursor.is_none() {
        return "1=1".into();
    }
    let comparison = match options.sort {
        ShareListSort::Newest => "<",
        ShareListSort::Oldest => ">",
    };
    format!("{column}{comparison}?2")
}

fn index_hint(status: ShareListStatus) -> &'static str {
    match status {
        ShareListStatus::Protected => "INDEXED BY idx_shares_protected_id",
        ShareListStatus::LimitReached => "INDEXED BY idx_shares_limit_id",
        ShareListStatus::Expired => "INDEXED BY idx_shares_expires_id",
        ShareListStatus::Active => "INDEXED BY idx_shares_available_expires_id",
        ShareListStatus::Inactive => "INDEXED BY idx_shares_active_id",
        ShareListStatus::All => "",
    }
}

fn fts_membership(has_query: bool) -> String {
    if has_query {
        format!("AND EXISTS(SELECT 1 FROM share_search_fts WHERE share_search_fts.rowid=shares.id AND share_search_fts MATCH ?3) AND {LITERAL_MATCH}")
    } else {
        String::new()
    }
}

fn direct_candidate_sql(options: &ShareListOptions, has_query: bool) -> String {
    let order = direction(options);
    let predicate = status_predicate(options.status);
    if has_query && options.status == ShareListStatus::All {
        let cursor = cursor_predicate(options, "share_search_fts.rowid");
        return format!("SELECT shares.id,1 FROM share_search_fts JOIN shares ON shares.id=share_search_fts.rowid
            WHERE share_search_fts MATCH ?3 AND {cursor} AND {LITERAL_MATCH}
            ORDER BY share_search_fts.rowid {order} LIMIT ?5");
    }
    let cursor = cursor_predicate(options, "shares.id");
    let index = index_hint(options.status);
    let search = fts_membership(has_query);
    format!(
        "SELECT shares.id,1 FROM shares {index} WHERE {predicate} AND {cursor} {search}
        ORDER BY shares.id {order} LIMIT ?5"
    )
}

/// LIMIT applies to the input window, so a rejected predicate cannot turn this
/// fast path into an unbounded scan. The fallback supplies every remaining hit.
fn probe_candidate_sql(options: &ShareListOptions, has_query: bool) -> String {
    let order = direction(options);
    let (source, column, search) = if has_query {
        (
            "share_search_fts JOIN shares ON shares.id=share_search_fts.rowid",
            "share_search_fts.rowid",
            "AND share_search_fts MATCH ?3",
        )
    } else {
        ("shares", "shares.id", "")
    };
    let cursor = cursor_predicate(options, column);
    let predicate = status_predicate(options.status);
    let literal = if has_query {
        format!("AND {LITERAL_MATCH}")
    } else {
        String::new()
    };
    format!("WITH window AS MATERIALIZED (
        SELECT shares.id,active,expires_at,max_downloads,download_count,password_hash,shares.alias_search_key,shares.path_search_key
        FROM {source} WHERE {cursor} {search} ORDER BY {column} {order} LIMIT ?5)
        SELECT shares.id,COALESCE(({predicate} {literal}),0) FROM window shares ORDER BY shares.id {order}")
}

fn available_candidate_sql(options: &ShareListOptions, has_query: bool) -> String {
    let order = direction(options);
    let cursor = cursor_predicate(options, "shares.id");
    let search = fts_membership(has_query);
    // Separate NULL and future expiry ranges to guarantee index range seeks.
    let branch = |expiry: &str| {
        format!(
            "SELECT shares.id FROM shares INDEXED BY idx_shares_available_expires_id
        WHERE {AVAILABLE} AND {expiry} AND {cursor} {search} ORDER BY shares.id {order} LIMIT ?5"
        )
    };
    let permanent = branch("shares.expires_at IS NULL");
    let future = branch("shares.expires_at>?1");
    format!("SELECT id,1 FROM (SELECT id FROM ({permanent}) UNION ALL SELECT id FROM ({future})) ORDER BY id {order} LIMIT ?5")
}

fn run_candidates(
    connection: &rusqlite::Connection,
    options: &ShareListOptions,
    needle: Option<&str>,
    sql: &str,
    limit: usize,
) -> rusqlite::Result<Vec<(i64, bool)>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement
        .query_map(
            params![
                options.now.to_rfc3339(),
                options.cursor,
                needle.map(fts5_phrase),
                needle,
                limit as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
        .collect();
    #[cfg(test)]
    record_candidate_work(&statement);
    rows
}

fn candidate_ids(
    connection: &rusqlite::Connection,
    options: &ShareListOptions,
    needle: Option<&str>,
) -> rusqlite::Result<Vec<i64>> {
    let fetch = options.limit.clamp(1, 200) + 1;
    let has_query = needle.is_some();
    if options.status != ShareListStatus::All
        && (has_query
            || matches!(
                options.status,
                ShareListStatus::Active | ShareListStatus::Expired
            ))
    {
        let window = 4 * fetch;
        let batch = run_candidates(
            connection,
            options,
            needle,
            &probe_candidate_sql(options, has_query),
            window,
        )?;
        let examined = batch.len();
        let ids: Vec<_> = batch
            .into_iter()
            .filter_map(|(id, matched)| matched.then_some(id))
            .take(fetch)
            .collect();
        if ids.len() == fetch || examined < window {
            return Ok(ids);
        }
    }
    let sql = if options.status == ShareListStatus::Active {
        available_candidate_sql(options, has_query)
    } else {
        direct_candidate_sql(options, has_query)
    };
    Ok(run_candidates(connection, options, needle, &sql, fetch)?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

impl Database {
    pub fn list_share_page(&self, options: &ShareListOptions) -> rusqlite::Result<SharePage> {
        let needle = validate_share_search(options.query.as_deref())
            .map_err(|error| rusqlite::Error::InvalidParameterName(error.message().into()))?
            .map(unicode_search_key);
        let limit = options.limit.clamp(1, 200);
        let mut connection = self.try_conn()?;
        // Candidate selection and payload loading see the same read snapshot.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let ids = candidate_ids(&transaction, options, needle.as_deref())?;
        let mut shares = Vec::new();
        if !ids.is_empty() {
            let parameters = (1..=ids.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "{SELECT_SHARE} WHERE shares.id IN ({parameters}) ORDER BY shares.id {}",
                direction(options)
            );
            shares = transaction
                .prepare(&sql)?
                .query_map(rusqlite::params_from_iter(ids), |row| self.map_share(row))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        }
        transaction.commit()?;
        let has_more = shares.len() > limit;
        shares.truncate(limit);
        let next_cursor = has_more
            .then(|| shares.last().map(|share| share.id))
            .flatten();
        Ok(SharePage {
            shares,
            next_cursor,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct CandidateWork {
    vm: i64,
    scans: i64,
}

#[cfg(test)]
thread_local! {
    static CANDIDATE_WORK: std::cell::Cell<CandidateWork> = const { std::cell::Cell::new(CandidateWork { vm: 0, scans: 0 }) };
}

#[cfg(test)]
fn record_candidate_work(statement: &rusqlite::Statement<'_>) {
    use rusqlite::StatementStatus;
    CANDIDATE_WORK.with(|work| {
        let old = work.get();
        work.set(CandidateWork {
            vm: old.vm + i64::from(statement.get_status(StatementStatus::VmStep)),
            scans: old.scans + i64::from(statement.get_status(StatementStatus::FullscanStep)),
        });
    });
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
