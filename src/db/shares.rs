use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditAction, AuditContext, Database,
    MfaSessionProof, Permission, RequiredAuditEvent, SessionBound, Share,
    ShareControlsUpdateOutcome, ShareListOptions, ShareListSort, SharePage, ShareSummary,
    UploadConflictStrategy, MAX_SQLITE_UNSIGNED,
};
#[cfg(test)]
use super::{DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

#[cfg(any(test, feature = "fuzzing"))]
pub fn rewrite_share_path(
    candidate: &str,
    target: &str,
    replacement: &str,
    is_directory: bool,
) -> Option<String> {
    if candidate == target {
        return Some(replacement.to_string());
    }
    if !is_directory {
        return None;
    }
    candidate
        .strip_prefix(target)
        .filter(|suffix| suffix.starts_with('/'))
        .map(|suffix| format!("{replacement}{suffix}"))
}

fn glob_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '*' => escaped.push_str("[*]"),
            '?' => escaped.push_str("[?]"),
            '[' => escaped.push_str("[[]"),
            ']' => escaped.push_str("[]]"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn path_globs(path: &str) -> (String, String) {
    let exact = glob_literal(path);
    let subtree = format!("{exact}/*");
    (exact, subtree)
}

impl Database {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn create_share(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
    ) -> rusqlite::Result<i64> {
        let (upload_total, upload_files) = if is_dir && permission.can_upload() {
            (
                Some(DEFAULT_SHARE_UPLOAD_TOTAL_SIZE.max(upload_max.unwrap_or_default())),
                Some(DEFAULT_SHARE_UPLOAD_FILE_COUNT),
            )
        } else {
            (None, None)
        };
        self.create_share_with_upload_limits(
            token,
            alias,
            path,
            is_dir,
            permission,
            expires,
            max,
            upload_max,
            upload_total,
            upload_files,
            admin,
            password_hash,
            upload_conflict_strategy,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn create_share_with_upload_limits(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        upload_total: Option<u64>,
        upload_files: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
    ) -> rusqlite::Result<i64> {
        self.create_share_with_upload_limits_internal(
            token,
            alias,
            path,
            is_dir,
            permission,
            expires,
            max,
            upload_max,
            upload_total,
            upload_files,
            admin,
            password_hash,
            upload_conflict_strategy,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn create_share_with_upload_limits_and_audit(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        upload_total: Option<u64>,
        upload_files: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
        audit_context: &AuditContext,
        audit_detail: Option<String>,
    ) -> rusqlite::Result<i64> {
        self.create_share_with_upload_limits_internal(
            token,
            alias,
            path,
            is_dir,
            permission,
            expires,
            max,
            upload_max,
            upload_total,
            upload_files,
            admin,
            password_hash,
            upload_conflict_strategy,
            Some((audit_context, audit_detail)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_share_with_upload_limits_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        upload_total: Option<u64>,
        upload_files: Option<u64>,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
        audit_context: &AuditContext,
        audit_detail: Option<String>,
    ) -> rusqlite::Result<SessionBound<(i64, Share)>> {
        let expects_upload_limits = is_dir && permission.can_upload();
        if expects_upload_limits != (upload_total.is_some() && upload_files.is_some())
            || upload_total.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_files.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_total
                .zip(upload_max)
                .is_some_and(|(total, single)| total < single)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let token_digest = token_hash(token);
        let token_aad = format!("shares.token:{token_digest}");
        let (token_key_id, token_ciphertext) =
            self.encrypt_secret(token.as_bytes(), token_aad.as_bytes())?;
        self.required_transaction_for_mfa_session(proof, audit_context, |transaction| {
            transaction.execute(
                "INSERT INTO shares(
                     token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,
                     max_downloads,max_upload_size,created_by,created_at,password_hash,
                     upload_conflict_strategy,max_upload_total_size,max_upload_files
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    token_digest,
                    token_key_id,
                    token_ciphertext,
                    alias,
                    path,
                    is_dir as i64,
                    permission.as_str(),
                    expires.map(|value| value.to_rfc3339()),
                    max,
                    upload_max,
                    proof.admin_id(),
                    Utc::now().to_rfc3339(),
                    password_hash,
                    upload_conflict_strategy.as_str(),
                    upload_total,
                    upload_files,
                ],
            )?;
            let id = transaction.last_insert_rowid();
            let share = self
                .share_by_id_in_transaction(transaction, id)?
                .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            Ok((
                (id, share),
                vec![RequiredAuditEvent::new(
                    AuditAction::ShareCreated,
                    Some(id.to_string()),
                    audit_detail,
                )],
            ))
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn create_share_with_upload_limits_internal(
        &self,
        token: &str,
        alias: Option<&str>,
        path: &str,
        is_dir: bool,
        permission: &Permission,
        expires: Option<DateTime<Utc>>,
        max: Option<u64>,
        upload_max: Option<u64>,
        upload_total: Option<u64>,
        upload_files: Option<u64>,
        admin: i64,
        password_hash: Option<&str>,
        upload_conflict_strategy: &UploadConflictStrategy,
        required_audit: Option<(&AuditContext, Option<String>)>,
    ) -> rusqlite::Result<i64> {
        let expects_upload_limits = is_dir && permission.can_upload();
        if expects_upload_limits != (upload_total.is_some() && upload_files.is_some())
            || upload_total.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_files.is_some_and(|value| value == 0 || value > MAX_SQLITE_UNSIGNED)
            || upload_total
                .zip(upload_max)
                .is_some_and(|(total, single)| total < single)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let token_digest = token_hash(token);
        let token_aad = format!("shares.token:{token_digest}");
        let (token_key_id, token_ciphertext) =
            self.encrypt_secret(token.as_bytes(), token_aad.as_bytes())?;
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO shares(
                 token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,
                 max_downloads,max_upload_size,created_by,created_at,password_hash,
                 upload_conflict_strategy,max_upload_total_size,max_upload_files
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                token_digest,
                token_key_id,
                token_ciphertext,
                alias,
                path,
                is_dir as i64,
                permission.as_str(),
                expires.map(|value| value.to_rfc3339()),
                max,
                upload_max,
                admin,
                Utc::now().to_rfc3339(),
                password_hash,
                upload_conflict_strategy.as_str(),
                upload_total,
                upload_files,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        let (audit_context, audit_events) =
            required_audit.map_or((None, None), |(context, detail)| {
                (
                    Some(context),
                    Some([RequiredAuditEvent::new(
                        AuditAction::ShareCreated,
                        Some(id.to_string()),
                        detail,
                    )]),
                )
            });
        if let (Some(context), Some(events)) = (audit_context, audit_events.as_ref()) {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let (Some(context), Some(events)) = (audit_context, audit_events.as_ref()) {
            trace_required_audits(context, events);
        }
        Ok(id)
    }
    fn map_share(&self, r: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
        let token_digest: String = r.get(1)?;
        let token_key_id: u64 = r.get(2)?;
        let token_ciphertext: Vec<u8> = r.get(3)?;
        let token_plaintext = self.decrypt_secret(
            token_key_id,
            &token_ciphertext,
            format!("shares.token:{token_digest}").as_bytes(),
        )?;
        let token = String::from_utf8(token_plaintext).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
        let exp: Option<String> = r.get(8)?;
        let expires_at = exp
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
            })
            .transpose()?;
        Ok(Share {
            id: r.get(0)?,
            token,
            alias: r.get(4)?,
            relative_path: r.get(5)?,
            is_directory: r.get::<_, i64>(6)? != 0,
            permission: Permission::parse(&r.get::<_, String>(7)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            expires_at,
            max_downloads: r.get(9)?,
            max_upload_size: r.get(10)?,
            max_upload_total_size: r.get(11)?,
            max_upload_files: r.get(12)?,
            uploaded_bytes: r.get(13)?,
            uploaded_files: r.get(14)?,
            download_count: r.get(15)?,
            active: r.get::<_, i64>(16)? != 0,
            password_hash: r.get(17)?,
            upload_conflict_strategy: UploadConflictStrategy::parse(&r.get::<_, String>(18)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            created_at: r.get(19)?,
            upload_policy_epoch: r.get(20)?,
        })
    }

    fn share_by_id_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        id: i64,
    ) -> rusqlite::Result<Option<Share>> {
        transaction
            .query_row(
                "SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE shares.id=?1",
                [id],
                |row| self.map_share(row),
            )
            .optional()
    }

    pub fn share_by_token(&self, token: &str) -> rusqlite::Result<Option<Share>> {
        self.try_conn()?.query_row("SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE token_hash=?1",[token_hash(token)],|row| self.map_share(row)).optional()
    }
    pub fn share_by_alias(&self, alias: &str) -> rusqlite::Result<Option<Share>> {
        self.try_conn()?.query_row("SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE alias=?1",[alias],|row| self.map_share(row)).optional()
    }
    pub fn share_by_id(&self, id: i64) -> rusqlite::Result<Option<Share>> {
        self.try_conn()?.query_row("SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE shares.id=?1",[id],|row| self.map_share(row)).optional()
    }
    pub fn list_shares(&self) -> rusqlite::Result<Vec<Share>> {
        let c = self.try_conn()?;
        let mut s=c.prepare_cached("SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id ORDER BY shares.id DESC")?;
        let shares = s
            .query_map([], |row| self.map_share(row))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(shares)
    }
    pub fn list_share_page(&self, options: &ShareListOptions) -> rusqlite::Result<SharePage> {
        const BATCH_SIZE: usize = 256;
        const SELECT: &str = "SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id";
        let cursor_predicate = match options.sort {
            ShareListSort::Newest => "(?3 IS NULL OR shares.id<?3) ORDER BY shares.id DESC",
            ShareListSort::Oldest => "(?3 IS NULL OR shares.id>?3) ORDER BY shares.id ASC",
        };
        let sql = format!(
            "{SELECT} WHERE
             (CASE ?1
                WHEN 'all' THEN 1
                WHEN 'active' THEN active=1 AND (expires_at IS NULL OR expires_at>?2)
                     AND (max_downloads IS NULL OR download_count<max_downloads)
                WHEN 'protected' THEN password_hash IS NOT NULL
                WHEN 'expired' THEN expires_at IS NOT NULL AND expires_at<=?2
                WHEN 'limit' THEN max_downloads IS NOT NULL AND download_count>=max_downloads
                WHEN 'inactive' THEN active=0
                ELSE 0
              END)
             AND {cursor_predicate} LIMIT ?4"
        );
        let query = options
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(unicode_search_key);
        let limit = options.limit.clamp(1, 200);
        let mut scan_cursor = options.cursor;
        let mut shares = Vec::with_capacity(limit.saturating_add(1));
        let connection = self.try_conn()?;
        let mut statement = connection.prepare(&sql)?;
        loop {
            let mut rows = statement.query(params![
                options.status.as_str(),
                options.now.to_rfc3339(),
                scan_cursor,
                BATCH_SIZE as i64
            ])?;
            let mut scanned = 0usize;
            while let Some(row) = rows.next()? {
                scanned += 1;
                let share = self.map_share(row)?;
                scan_cursor = Some(share.id);
                let matches = query.as_ref().is_none_or(|needle| {
                    unicode_search_key(&share.relative_path).contains(needle)
                        || share
                            .alias
                            .as_deref()
                            .is_some_and(|alias| unicode_search_key(alias).contains(needle))
                });
                if matches {
                    shares.push(share);
                    if shares.len() > limit {
                        break;
                    }
                }
            }
            if shares.len() > limit || scanned < BATCH_SIZE {
                break;
            }
        }
        let next_cursor = if shares.len() > limit {
            shares.pop();
            shares.last().map(|share| share.id)
        } else {
            None
        };
        Ok(SharePage {
            shares,
            next_cursor,
        })
    }
    pub fn share_summary(&self, now: DateTime<Utc>) -> rusqlite::Result<ShareSummary> {
        self.try_conn()?.query_row(
            "SELECT
                 COALESCE(SUM(active=1 AND (expires_at IS NULL OR expires_at>?1)
                     AND (max_downloads IS NULL OR download_count<max_downloads)),0),
                 COALESCE(SUM(password_hash IS NOT NULL),0)
             FROM shares",
            [now.to_rfc3339()],
            |row| {
                Ok(ShareSummary {
                    available: row.get(0)?,
                    protected: row.get(1)?,
                })
            },
        )
    }
    pub fn count_available_shares(&self, now: DateTime<Utc>) -> rusqlite::Result<usize> {
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM shares
             WHERE active=1 AND (expires_at IS NULL OR expires_at>?1)
               AND (max_downloads IS NULL OR download_count<max_downloads)",
            [now.to_rfc3339()],
            |row| row.get(0),
        )
    }
    pub fn count_active_shares_for_path(
        &self,
        path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        let (exact, subtree) = path_globs(path);
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM shares
             WHERE active=1 AND (relative_path GLOB ?1 OR (?2 AND relative_path GLOB ?3))",
            params![exact, is_directory, subtree],
            |row| row.get(0),
        )
    }
    #[cfg(test)]
    pub fn rename_share_paths(
        &self,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        self.rename_share_paths_internal(old_path, new_path, is_directory, None)
    }

    pub fn rename_share_paths_and_audit(
        &self,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
        context: &AuditContext,
        recovery: bool,
    ) -> rusqlite::Result<usize> {
        self.rename_share_paths_internal(
            old_path,
            new_path,
            is_directory,
            Some((context, recovery)),
        )
    }

    pub(crate) fn rename_share_paths_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
        recovery: bool,
    ) -> rusqlite::Result<(usize, Vec<RequiredAuditEvent>)> {
        let (exact, subtree) = path_globs(old_path);
        let updated = transaction.execute(
            "UPDATE shares
             SET relative_path=?1 || substr(relative_path,length(?2)+1),
                 upload_policy_epoch=upload_policy_epoch+1
             WHERE relative_path GLOB ?3 OR (?4 AND relative_path GLOB ?5)",
            params![new_path, old_path, exact, is_directory, subtree],
        )?;
        Ok((
            updated,
            vec![RequiredAuditEvent::new(
                AuditAction::PathRenamed,
                Some(new_path.to_string()),
                Some(format!(
                    "old_path={old_path};updated_shares={updated};recovery={recovery}"
                )),
            )],
        ))
    }

    fn rename_share_paths_internal(
        &self,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
        required_audit: Option<(&AuditContext, bool)>,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (exact, subtree) = path_globs(old_path);
        let updated = transaction.execute(
            "UPDATE shares
             SET relative_path=?1 || substr(relative_path,length(?2)+1),
                 upload_policy_epoch=upload_policy_epoch+1
             WHERE relative_path GLOB ?3 OR (?4 AND relative_path GLOB ?5)",
            params![new_path, old_path, exact, is_directory, subtree],
        )?;
        let audit_events = required_audit.map(|(_, recovery)| {
            [RequiredAuditEvent::new(
                AuditAction::PathRenamed,
                Some(new_path.to_string()),
                Some(format!(
                    "old_path={old_path};updated_shares={};recovery={recovery}",
                    updated
                )),
            )]
        });
        if let (Some((context, _)), Some(events)) = (required_audit, audit_events.as_ref()) {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let (Some((context, _)), Some(events)) = (required_audit, audit_events.as_ref()) {
            trace_required_audits(context, events);
        }
        Ok(updated)
    }
    #[cfg(test)]
    pub fn deactivate_shares_for_path(
        &self,
        path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        self.deactivate_shares_for_path_internal(path, is_directory, None)
    }

    pub fn deactivate_shares_for_path_and_audit(
        &self,
        path: &str,
        is_directory: bool,
        context: &AuditContext,
        recovery: bool,
        cleanup_pending: bool,
    ) -> rusqlite::Result<usize> {
        self.deactivate_shares_for_path_internal(
            path,
            is_directory,
            Some((context, recovery, cleanup_pending)),
        )
    }

    pub(crate) fn deactivate_shares_for_path_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        path: &str,
        is_directory: bool,
        recovery: bool,
        cleanup_pending: bool,
    ) -> rusqlite::Result<(usize, Vec<RequiredAuditEvent>)> {
        let (exact, subtree) = path_globs(path);
        let deactivated = transaction.execute(
            "UPDATE shares
             SET active=0,upload_policy_epoch=upload_policy_epoch+1
             WHERE active=1 AND (relative_path GLOB ?1 OR (?2 AND relative_path GLOB ?3))",
            params![exact, is_directory, subtree],
        )?;
        Ok((
            deactivated,
            vec![RequiredAuditEvent::new(
                AuditAction::PathDeleted,
                Some(path.to_string()),
                Some(format!(
                    "kind={};deactivated_shares={};cleanup={};recovery={recovery}",
                    if is_directory { "directory" } else { "file" },
                    deactivated,
                    if cleanup_pending {
                        "pending"
                    } else {
                        "complete"
                    },
                )),
            )],
        ))
    }

    fn deactivate_shares_for_path_internal(
        &self,
        path: &str,
        is_directory: bool,
        required_audit: Option<(&AuditContext, bool, bool)>,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (exact, subtree) = path_globs(path);
        let deactivated = transaction.execute(
            "UPDATE shares
             SET active=0,upload_policy_epoch=upload_policy_epoch+1
             WHERE active=1 AND (relative_path GLOB ?1 OR (?2 AND relative_path GLOB ?3))",
            params![exact, is_directory, subtree],
        )?;
        let audit_events = required_audit.map(|(_, recovery, cleanup_pending)| {
            [RequiredAuditEvent::new(
                AuditAction::PathDeleted,
                Some(path.to_string()),
                Some(format!(
                    "kind={};deactivated_shares={};cleanup={};recovery={recovery}",
                    if is_directory { "directory" } else { "file" },
                    deactivated,
                    if cleanup_pending {
                        "pending"
                    } else {
                        "complete"
                    },
                )),
            )]
        });
        if let (Some((context, _, _)), Some(events)) = (required_audit, audit_events.as_ref()) {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let (Some((context, _, _)), Some(events)) = (required_audit, audit_events.as_ref()) {
            trace_required_audits(context, events);
        }
        Ok(deactivated)
    }
    #[cfg(test)]
    pub fn set_share_active(&self, id: i64, active: bool) -> rusqlite::Result<bool> {
        Ok(self.try_conn()?.execute(
            "UPDATE shares
             SET upload_policy_epoch=upload_policy_epoch+
                     CASE WHEN active<>?2 THEN 1 ELSE 0 END,
                 active=?2
             WHERE id=?1",
            params![id, active as i64],
        )? == 1)
    }

    #[cfg(test)]
    pub(crate) fn set_share_active_and_audit(
        &self,
        id: i64,
        active: bool,
        context: &AuditContext,
        action: AuditAction,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let changed = transaction.execute(
                "UPDATE shares
                 SET upload_policy_epoch=upload_policy_epoch+
                         CASE WHEN active<>?2 THEN 1 ELSE 0 END,
                     active=?2
                 WHERE id=?1",
                params![id, active as i64],
            )? == 1;
            let events = changed
                .then(|| RequiredAuditEvent::new(action, Some(id.to_string()), None))
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    pub(crate) fn set_share_active_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        active: bool,
        context: &AuditContext,
        action: AuditAction,
    ) -> rusqlite::Result<SessionBound<bool>> {
        self.required_transaction_for_mfa_session(proof, context, |transaction| {
            let changed = transaction.execute(
                "UPDATE shares
                 SET upload_policy_epoch=upload_policy_epoch+
                         CASE WHEN active<>?2 THEN 1 ELSE 0 END,
                     active=?2
                 WHERE id=?1",
                params![id, active as i64],
            )? == 1;
            let events = changed
                .then(|| RequiredAuditEvent::new(action, Some(id.to_string()), None))
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }
    #[cfg(test)]
    pub fn update_share_controls(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        self.update_share_controls_internal(id, active, strategy, upload_limits, None)
    }

    #[cfg(test)]
    pub fn update_share_controls_and_audit(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
        context: &AuditContext,
        events: &[RequiredAuditEvent],
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        self.update_share_controls_internal(
            id,
            active,
            strategy,
            upload_limits,
            Some((context, events)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_share_controls_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
        context: &AuditContext,
        events: &[RequiredAuditEvent],
    ) -> rusqlite::Result<SessionBound<(ShareControlsUpdateOutcome, Option<Share>)>> {
        self.required_transaction_for_mfa_session(proof, context, |transaction| {
            let now = Utc::now().to_rfc3339();
            transaction.execute(
                "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
                [&now],
            )?;
            let share = transaction
                .query_row(
                    "SELECT is_directory,permission,
                            COALESCE((SELECT uploaded_bytes FROM public_upload_usage WHERE share_id=?1),0),
                            COALESCE((SELECT uploaded_files FROM public_upload_usage WHERE share_id=?1),0),
                            COALESCE((
                                SELECT SUM(reservations.reserved_bytes)
                                FROM public_upload_reservations reservations
                                WHERE reservations.share_id=?1
                                  AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                            ),0),
                            (
                                SELECT COUNT(*) FROM public_upload_reservations reservations
                                WHERE reservations.share_id=?1
                                  AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                            )
                     FROM shares WHERE id=?1",
                    [id],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, u64>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, u64>(4)?,
                            row.get::<_, u64>(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                is_directory,
                permission,
                uploaded_bytes,
                uploaded_files,
                reserved_bytes,
                reserved_files,
            )) = share
            else {
                return Ok(((ShareControlsUpdateOutcome::NotFound, None), Vec::new()));
            };
            if let Some((total, files)) = upload_limits {
                let committed_and_reserved_bytes = uploaded_bytes.checked_add(reserved_bytes);
                let committed_and_reserved_files = uploaded_files.checked_add(reserved_files);
                if total == 0
                    || files == 0
                    || total > MAX_SQLITE_UNSIGNED
                    || files > MAX_SQLITE_UNSIGNED
                    || !is_directory
                    || !Permission::parse(&permission).is_some_and(|value| value.can_upload())
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                if committed_and_reserved_bytes.is_none_or(|used| total < used)
                    || committed_and_reserved_files.is_none_or(|used| files < used)
                {
                    return Ok(((ShareControlsUpdateOutcome::QuotaConflict, None), Vec::new()));
                }
            }
            transaction.execute(
                "UPDATE shares SET
                     upload_policy_epoch=upload_policy_epoch+CASE WHEN
                         (?2 IS NOT NULL AND active IS NOT ?2)
                         OR (?3 IS NOT NULL AND upload_conflict_strategy IS NOT ?3)
                         OR (?4 IS NOT NULL AND max_upload_total_size IS NOT ?4)
                         OR (?5 IS NOT NULL AND max_upload_files IS NOT ?5)
                     THEN 1 ELSE 0 END,
                     active=COALESCE(?2,active),
                     upload_conflict_strategy=COALESCE(?3,upload_conflict_strategy),
                     max_upload_total_size=COALESCE(?4,max_upload_total_size),
                     max_upload_files=COALESCE(?5,max_upload_files)
                 WHERE id=?1",
                params![
                    id,
                    active.map(i64::from),
                    strategy.map(UploadConflictStrategy::as_str),
                    upload_limits.map(|value| value.0),
                    upload_limits.map(|value| value.1),
                ],
            )?;
            let share = self
                .share_by_id_in_transaction(transaction, id)?
                .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            Ok(((ShareControlsUpdateOutcome::Updated, Some(share)), events.to_vec()))
        })
    }

    #[cfg(test)]
    fn update_share_controls_internal(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
        required_audit: Option<(&AuditContext, &[RequiredAuditEvent])>,
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now],
        )?;
        let share = transaction
            .query_row(
                "SELECT is_directory,permission,
                        COALESCE((SELECT uploaded_bytes FROM public_upload_usage WHERE share_id=?1),0),
                        COALESCE((SELECT uploaded_files FROM public_upload_usage WHERE share_id=?1),0),
                        COALESCE((
                            SELECT SUM(reservations.reserved_bytes)
                            FROM public_upload_reservations reservations
                            WHERE reservations.share_id=?1
                              AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                        ),0),
                        (
                            SELECT COUNT(*) FROM public_upload_reservations reservations
                            WHERE reservations.share_id=?1
                              AND reservations.upload_policy_epoch=shares.upload_policy_epoch
                        )
                 FROM shares WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            is_directory,
            permission,
            uploaded_bytes,
            uploaded_files,
            reserved_bytes,
            reserved_files,
        )) = share
        else {
            transaction.commit()?;
            return Ok(ShareControlsUpdateOutcome::NotFound);
        };
        if let Some((total, files)) = upload_limits {
            let committed_and_reserved_bytes = uploaded_bytes.checked_add(reserved_bytes);
            let committed_and_reserved_files = uploaded_files.checked_add(reserved_files);
            if total == 0
                || files == 0
                || total > MAX_SQLITE_UNSIGNED
                || files > MAX_SQLITE_UNSIGNED
                || !is_directory
                || !Permission::parse(&permission).is_some_and(|value| value.can_upload())
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if committed_and_reserved_bytes.is_none_or(|used| total < used)
                || committed_and_reserved_files.is_none_or(|used| files < used)
            {
                transaction.commit()?;
                return Ok(ShareControlsUpdateOutcome::QuotaConflict);
            }
        }
        transaction.execute(
            "UPDATE shares SET
                 upload_policy_epoch=upload_policy_epoch+CASE WHEN
                     (?2 IS NOT NULL AND active IS NOT ?2)
                     OR (?3 IS NOT NULL AND upload_conflict_strategy IS NOT ?3)
                     OR (?4 IS NOT NULL AND max_upload_total_size IS NOT ?4)
                     OR (?5 IS NOT NULL AND max_upload_files IS NOT ?5)
                 THEN 1 ELSE 0 END,
                 active=COALESCE(?2,active),
                 upload_conflict_strategy=COALESCE(?3,upload_conflict_strategy),
                 max_upload_total_size=COALESCE(?4,max_upload_total_size),
                 max_upload_files=COALESCE(?5,max_upload_files)
             WHERE id=?1",
            params![
                id,
                active.map(i64::from),
                strategy.map(UploadConflictStrategy::as_str),
                upload_limits.map(|value| value.0),
                upload_limits.map(|value| value.1),
            ],
        )?;
        if let Some((context, events)) = required_audit {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let Some((context, events)) = required_audit {
            trace_required_audits(context, events);
        }
        Ok(ShareControlsUpdateOutcome::Updated)
    }

    #[cfg(test)]
    pub fn delete_share(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .try_conn()?
            .execute("DELETE FROM shares WHERE id=?1", [id])?
            == 1)
    }

    #[cfg(test)]
    pub fn delete_share_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let deleted = transaction.execute("DELETE FROM shares WHERE id=?1", [id])? == 1;
            let events = deleted
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::ShareDeleted, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((deleted, events))
        })
    }

    pub(crate) fn delete_share_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<bool>> {
        self.required_transaction_for_mfa_session(proof, context, |transaction| {
            let deleted = transaction.execute("DELETE FROM shares WHERE id=?1", [id])? == 1;
            let events = deleted
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::ShareDeleted, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((deleted, events))
        })
    }

    #[cfg(test)]
    pub fn set_share_password(&self, id: i64, hash: Option<&str>) -> rusqlite::Result<bool> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE shares
             SET upload_policy_epoch=upload_policy_epoch+1,
                 password_hash=?2
             WHERE id=?1",
            params![id, hash],
        )? == 1;
        transaction.execute("DELETE FROM public_unlock_sessions WHERE share_id=?1", [id])?;
        transaction.commit()?;
        Ok(changed)
    }

    #[cfg(test)]
    pub(crate) fn set_share_password_and_audit(
        &self,
        id: i64,
        hash: Option<&str>,
        context: &AuditContext,
        action: AuditAction,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let changed = transaction.execute(
                "UPDATE shares
                 SET upload_policy_epoch=upload_policy_epoch+1,
                     password_hash=?2
                 WHERE id=?1",
                params![id, hash],
            )? == 1;
            transaction.execute("DELETE FROM public_unlock_sessions WHERE share_id=?1", [id])?;
            let events = changed
                .then(|| RequiredAuditEvent::new(action, Some(id.to_string()), None))
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    pub(crate) fn set_share_password_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        hash: Option<&str>,
        context: &AuditContext,
        action: AuditAction,
    ) -> rusqlite::Result<SessionBound<bool>> {
        self.required_transaction_for_mfa_session(proof, context, |transaction| {
            let changed = transaction.execute(
                "UPDATE shares
                 SET upload_policy_epoch=upload_policy_epoch+1,
                     password_hash=?2
                 WHERE id=?1",
                params![id, hash],
            )? == 1;
            transaction.execute("DELETE FROM public_unlock_sessions WHERE share_id=?1", [id])?;
            let events = changed
                .then(|| RequiredAuditEvent::new(action, Some(id.to_string()), None))
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }
}

fn unicode_search_key(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars().flat_map(char::to_lowercase) {
        // Rust's lowercase mapping is Unicode-aware but is not a full case
        // fold. Normalize sharp-s as well so common German searches such as
        // "GRÜS" match "Grüße" after the remaining Unicode lowercase pass.
        if character == 'ß' {
            normalized.push_str("ss");
        } else {
            normalized.push(character);
        }
    }
    normalized
}
