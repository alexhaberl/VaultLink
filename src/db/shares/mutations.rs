impl Database {
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
        let old_search_key = unicode_search_key(old_path);
        let new_search_key = unicode_search_key(new_path);
        let updated = transaction.execute(
            "UPDATE shares
             SET relative_path=?1 || substr(relative_path,length(?2)+1),
                 path_search_key=?6 || substr(path_search_key,length(?7)+1),
                 upload_policy_epoch=upload_policy_epoch+1
             WHERE relative_path GLOB ?3 OR (?4 AND relative_path GLOB ?5)",
            params![
                new_path,
                old_path,
                exact,
                is_directory,
                subtree,
                new_search_key,
                old_search_key
            ],
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
        let old_search_key = unicode_search_key(old_path);
        let new_search_key = unicode_search_key(new_path);
        let updated = transaction.execute(
            "UPDATE shares
             SET relative_path=?1 || substr(relative_path,length(?2)+1),
                 path_search_key=?6 || substr(path_search_key,length(?7)+1),
                 upload_policy_epoch=upload_policy_epoch+1
             WHERE relative_path GLOB ?3 OR (?4 AND relative_path GLOB ?5)",
            params![
                new_path,
                old_path,
                exact,
                is_directory,
                subtree,
                new_search_key,
                old_search_key
            ],
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
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
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
    ) -> rusqlite::Result<AuditedShareControlsUpdate> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
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
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
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
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
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
