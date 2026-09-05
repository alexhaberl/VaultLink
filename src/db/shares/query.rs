fn share_page_sql(options: &ShareListOptions, needle: Option<&str>) -> String {
    const SELECT: &str = "SELECT shares.id,token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id";
    let status_predicate = match options.status {
        super::ShareListStatus::All => "1",
        super::ShareListStatus::Active => {
            "shares.active=1 AND (shares.expires_at IS NULL OR shares.expires_at>?1)
                 AND (shares.max_downloads IS NULL OR shares.download_count<shares.max_downloads)"
        }
        super::ShareListStatus::Protected => "shares.password_hash IS NOT NULL",
        super::ShareListStatus::Expired => {
            "shares.expires_at IS NOT NULL AND shares.expires_at<=?1"
        }
        super::ShareListStatus::LimitReached => {
            "shares.max_downloads IS NOT NULL
                 AND shares.download_count>=shares.max_downloads"
        }
        super::ShareListStatus::Inactive => "shares.active=0",
    };
    let (cursor_predicate, order_by) = match (options.sort, options.cursor.is_some()) {
        (ShareListSort::Newest, true) => ("shares.id<?2", "shares.id DESC"),
        (ShareListSort::Oldest, true) => ("shares.id>?2", "shares.id ASC"),
        (ShareListSort::Newest, false) => ("1=1", "shares.id DESC"),
        (ShareListSort::Oldest, false) => ("1=1", "shares.id ASC"),
    };
    match needle {
        Some(needle) if needle.chars().count() >= 3 => {
            // Give FTS5 its own rowid bound and order so it can seek and stop
            // after LIMIT instead of sorting the full matching posting list.
            let (cursor_predicate, order_by) = match (options.sort, options.cursor.is_some()) {
                (ShareListSort::Newest, true) => {
                    ("share_search_fts.rowid<?2", "share_search_fts.rowid DESC")
                }
                (ShareListSort::Oldest, true) => {
                    ("share_search_fts.rowid>?2", "share_search_fts.rowid ASC")
                }
                (ShareListSort::Newest, false) => ("1=1", "share_search_fts.rowid DESC"),
                (ShareListSort::Oldest, false) => ("1=1", "share_search_fts.rowid ASC"),
            };
            format!(
                "{SELECT}
                     JOIN share_search_fts ON share_search_fts.rowid=shares.id
                     WHERE {status_predicate}
                       AND {cursor_predicate}
                       AND share_search_fts MATCH ?4
                       AND (instr(shares.alias_search_key,?5)>0
                            OR instr(shares.path_search_key,?5)>0)
                     ORDER BY {order_by}
                     LIMIT ?3"
            )
        }
        Some(_) => {
            format!(
                "{SELECT} WHERE {status_predicate}
                       AND {cursor_predicate}
                       AND (instr(shares.alias_search_key,?4)>0
                            OR instr(shares.path_search_key,?4)>0)
                     ORDER BY {order_by}
                     LIMIT ?3"
            )
        }
        None => {
            format!(
                "{SELECT} WHERE {status_predicate} AND {cursor_predicate}
                 ORDER BY {order_by} LIMIT ?3"
            )
        }
    }
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
    ) -> rusqlite::Result<SessionBound<Audited<(i64, Share)>>> {
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
        let alias_search_key = alias.map(unicode_search_key);
        let path_search_key = unicode_search_key(path);
        self.required_transaction_for_mfa_session_audited(proof, audit_context, |transaction| {
            transaction.execute(
                "INSERT INTO shares(
                     token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,
                     max_downloads,max_upload_size,created_by,created_at,password_hash,
                     upload_conflict_strategy,max_upload_total_size,max_upload_files,
                     alias_search_key,path_search_key
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
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
                    alias_search_key,
                    path_search_key,
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
        let alias_search_key = alias.map(unicode_search_key);
        let path_search_key = unicode_search_key(path);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO shares(
                 token_hash,token_key_id,token_ciphertext,alias,relative_path,is_directory,permission,expires_at,
                 max_downloads,max_upload_size,created_by,created_at,password_hash,
                 upload_conflict_strategy,max_upload_total_size,max_upload_files,
                 alias_search_key,path_search_key
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
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
                alias_search_key,
                path_search_key,
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
        #[cfg(test)]
        SHARE_MAP_COUNT.with(|count| count.set(count.get().saturating_add(1)));
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
        let query = options
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(unicode_search_key);
        let limit = options.limit.clamp(1, 200);
        let fetch_limit = limit.saturating_add(1) as i64;
        let connection = self.try_conn()?;
        let now = options.now.to_rfc3339();
        let sql = share_page_sql(options, query.as_deref());
        let mut shares = if let Some(needle) = query.as_deref() {
            if needle.chars().count() >= 3 {
                let fts_query = fts5_phrase(needle);
                connection
                    .prepare(&sql)?
                    .query_map(
                        params![now, options.cursor, fetch_limit, fts_query, needle],
                        |row| self.map_share(row),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                // FTS5's trigram tokenizer intentionally emits no tokens for
                // one- and two-character terms. Keep those compatible using
                // the normalized content columns, while still applying LIMIT
                // before any encrypted token is loaded or decrypted.
                connection
                    .prepare(&sql)?
                    .query_map(params![now, options.cursor, fetch_limit, needle], |row| {
                        self.map_share(row)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            }
        } else {
            connection
                .prepare(&sql)?
                .query_map(params![now, options.cursor, fetch_limit], |row| {
                    self.map_share(row)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
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
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod query_tests;
