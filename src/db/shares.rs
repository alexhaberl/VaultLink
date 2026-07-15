use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditContext, Database, Permission,
    RequiredAuditEvent, Share, ShareControlsUpdateOutcome, UploadConflictStrategy,
    DEFAULT_SHARE_UPLOAD_FILE_COUNT, DEFAULT_SHARE_UPLOAD_TOTAL_SIZE, MAX_SQLITE_UNSIGNED,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

fn share_path_matches(candidate: &str, target: &str, is_directory: bool) -> bool {
    candidate == target
        || (is_directory
            && candidate
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

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

impl Database {
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
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO shares(
                 token_hash,token,alias,relative_path,is_directory,permission,expires_at,
                 max_downloads,max_upload_size,created_by,created_at,password_hash,
                 upload_conflict_strategy,max_upload_total_size,max_upload_files
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                token_hash(token),
                token,
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
        let audit_events = required_audit.as_ref().map(|(_, detail)| {
            vec![RequiredAuditEvent::new(
                "share_created",
                Some(id.to_string()),
                detail.clone(),
            )]
        });
        if let (Some((context, _)), Some(events)) =
            (required_audit.as_ref(), audit_events.as_deref())
        {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let (Some((context, _)), Some(events)) =
            (required_audit.as_ref(), audit_events.as_deref())
        {
            trace_required_audits(context, events);
        }
        Ok(id)
    }
    fn map_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
        let exp: Option<String> = r.get(6)?;
        let expires_at = exp
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
            })
            .transpose()?;
        Ok(Share {
            id: r.get(0)?,
            token: r.get(1)?,
            alias: r.get(2)?,
            relative_path: r.get(3)?,
            is_directory: r.get::<_, i64>(4)? != 0,
            permission: Permission::parse(&r.get::<_, String>(5)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            expires_at,
            max_downloads: r.get(7)?,
            max_upload_size: r.get(8)?,
            max_upload_total_size: r.get(9)?,
            max_upload_files: r.get(10)?,
            uploaded_bytes: r.get(11)?,
            uploaded_files: r.get(12)?,
            download_count: r.get(13)?,
            active: r.get::<_, i64>(14)? != 0,
            password_hash: r.get(15)?,
            upload_conflict_strategy: UploadConflictStrategy::parse(&r.get::<_, String>(16)?)
                .ok_or(rusqlite::Error::InvalidQuery)?,
            created_at: r.get(17)?,
            upload_policy_epoch: r.get(18)?,
        })
    }
    pub fn share_by_token(&self, token: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE token_hash=?1",[token_hash(token)],Self::map_share).optional()
    }
    pub fn share_by_alias(&self, alias: &str) -> rusqlite::Result<Option<Share>> {
        self.conn().query_row("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id WHERE alias=?1",[alias],Self::map_share).optional()
    }
    pub fn list_shares(&self) -> rusqlite::Result<Vec<Share>> {
        let c = self.conn();
        let mut s=c.prepare("SELECT id,token,alias,relative_path,is_directory,permission,expires_at,max_downloads,max_upload_size,max_upload_total_size,max_upload_files,COALESCE(usage.uploaded_bytes,0),COALESCE(usage.uploaded_files,0),download_count,active,password_hash,upload_conflict_strategy,created_at,upload_policy_epoch FROM shares LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id ORDER BY shares.id DESC")?;
        let shares = s
            .query_map([], Self::map_share)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(shares)
    }
    pub fn count_active_shares_for_path(
        &self,
        path: &str,
        is_directory: bool,
    ) -> rusqlite::Result<usize> {
        let connection = self.conn();
        let mut statement =
            connection.prepare("SELECT relative_path FROM shares WHERE active=1")?;
        let mut count = 0usize;
        for relative_path in statement.query_map([], |row| row.get::<_, String>(0))? {
            if share_path_matches(&relative_path?, path, is_directory) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
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

    fn rename_share_paths_internal(
        &self,
        old_path: &str,
        new_path: &str,
        is_directory: bool,
        required_audit: Option<(&AuditContext, bool)>,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updates = {
            let mut statement = transaction.prepare("SELECT id,relative_path FROM shares")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut updates = Vec::new();
            for row in rows {
                let (id, path) = row?;
                if let Some(rewritten) = rewrite_share_path(&path, old_path, new_path, is_directory)
                {
                    updates.push((id, rewritten));
                }
            }
            updates
        };
        for (id, path) in &updates {
            transaction.execute(
                "UPDATE shares
                 SET relative_path=?2,upload_policy_epoch=upload_policy_epoch+1
                 WHERE id=?1",
                params![id, path],
            )?;
        }
        let audit_events = required_audit.map(|(_, recovery)| {
            [RequiredAuditEvent::new(
                "path_renamed",
                Some(new_path.to_string()),
                Some(format!(
                    "old_path={old_path};updated_shares={};recovery={recovery}",
                    updates.len()
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
        Ok(updates.len())
    }
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

    fn deactivate_shares_for_path_internal(
        &self,
        path: &str,
        is_directory: bool,
        required_audit: Option<(&AuditContext, bool, bool)>,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = {
            let mut statement =
                transaction.prepare("SELECT id,relative_path FROM shares WHERE active=1")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut ids = Vec::new();
            for row in rows {
                let (id, relative_path) = row?;
                if share_path_matches(&relative_path, path, is_directory) {
                    ids.push(id);
                }
            }
            ids
        };
        for id in &ids {
            transaction.execute(
                "UPDATE shares
                 SET active=0,upload_policy_epoch=upload_policy_epoch+1
                 WHERE id=?1",
                [id],
            )?;
        }
        let audit_events = required_audit.map(|(_, recovery, cleanup_pending)| {
            [RequiredAuditEvent::new(
                "path_deleted",
                Some(path.to_string()),
                Some(format!(
                    "kind={};deactivated_shares={};cleanup={};recovery={recovery}",
                    if is_directory { "directory" } else { "file" },
                    ids.len(),
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
        Ok(ids.len())
    }
    pub fn set_share_active(&self, id: i64, active: bool) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE shares
             SET upload_policy_epoch=upload_policy_epoch+
                     CASE WHEN active<>?2 THEN 1 ELSE 0 END,
                 active=?2
             WHERE id=?1",
            params![id, active as i64],
        )? == 1)
    }

    pub fn set_share_active_and_audit(
        &self,
        id: i64,
        active: bool,
        context: &AuditContext,
        action: &'static str,
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
    pub fn update_share_controls(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        self.update_share_controls_internal(id, active, strategy, upload_limits, None)
    }

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

    fn update_share_controls_internal(
        &self,
        id: i64,
        active: Option<bool>,
        strategy: Option<&UploadConflictStrategy>,
        upload_limits: Option<(u64, u64)>,
        required_audit: Option<(&AuditContext, &[RequiredAuditEvent])>,
    ) -> rusqlite::Result<ShareControlsUpdateOutcome> {
        let mut connection = self.conn();
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

    pub fn delete_share(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM shares WHERE id=?1", [id])?
            == 1)
    }

    pub fn delete_share_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let deleted = transaction.execute("DELETE FROM shares WHERE id=?1", [id])? == 1;
            let events = deleted
                .then(|| RequiredAuditEvent::new("share_deleted", Some(id.to_string()), None))
                .into_iter()
                .collect();
            Ok((deleted, events))
        })
    }

    pub fn set_share_password(&self, id: i64, hash: Option<&str>) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
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

    pub fn set_share_password_and_audit(
        &self,
        id: i64,
        hash: Option<&str>,
        context: &AuditContext,
        action: &'static str,
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
}
