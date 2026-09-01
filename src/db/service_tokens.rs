use super::{
    insert_required_audits, token_hash, trace_required_audits, valid_service_token_name,
    AuditAction, AuditContext, Database, MonitoringShare, MonitoringShareListOptions,
    MonitoringSharePage, MonitoringShareStatus, MonitoringSummary, Permission, RequiredAuditEvent,
    ServiceToken, ServiceTokenAuthorizationOutcome, ServiceTokenCreationOutcome,
    TransferMonthlyCounts, MAX_SERVICE_TOKENS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const SERVICE_TOKEN_PREFIX: &str = "vlk_st_v1_";
const SERVICE_TOKEN_RANDOM_BYTES: usize = 32;
const SERVICE_TOKEN_TOUCH_INTERVAL_SECONDS: i64 = 5 * 60;

fn valid_service_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix(SERVICE_TOKEN_PREFIX) else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|decoded| decoded.len() == SERVICE_TOKEN_RANDOM_BYTES)
}

fn map_service_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceToken> {
    Ok(ServiceToken {
        id: row.get(0)?,
        name: row.get(1)?,
        scope_mask: row.get(2)?,
        created_by: row.get(3)?,
        created_by_username: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}

fn parse_optional_timestamp(
    value: Option<String>,
    column: usize,
) -> rusqlite::Result<Option<DateTime<Utc>>> {
    value
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(&timestamp)
                .map(|parsed| parsed.with_timezone(&Utc))
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        column,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
        })
        .transpose()
}

fn parse_monitoring_status(value: &str) -> rusqlite::Result<MonitoringShareStatus> {
    match value {
        "available" => Ok(MonitoringShareStatus::Available),
        "inactive" => Ok(MonitoringShareStatus::Inactive),
        "expired" => Ok(MonitoringShareStatus::Expired),
        "download_limit_reached" => Ok(MonitoringShareStatus::DownloadLimitReached),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub fn create_service_token_for_verified_admin_and_audit(
        &self,
        session_token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        name: &str,
        plaintext_token: &str,
        expires_at: Option<DateTime<Utc>>,
        context: &AuditContext,
    ) -> rusqlite::Result<ServiceTokenCreationOutcome> {
        if !valid_service_token_name(name) || !valid_service_token(plaintext_token) {
            return Err(rusqlite::Error::InvalidQuery);
        }

        let now = Utc::now();
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let now_string = now.to_rfc3339();
        let idle_cutoff = (now - Duration::minutes(self.session_idle_minutes())).to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row(
                "SELECT admins.username
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND sessions.last_activity_at>?4
                   AND admins.active=1
                   AND admins.password_hash=?5",
                params![
                    token_hash(session_token),
                    admin_id,
                    now_string,
                    idle_cutoff,
                    expected_password_hash,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.rollback()?;
            return Ok(ServiceTokenCreationOutcome::ReauthenticationRejected);
        };

        let name_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM service_tokens WHERE name=?1 COLLATE NOCASE)",
            [name],
            |row| row.get(0),
        )?;
        if name_exists {
            transaction.rollback()?;
            return Ok(ServiceTokenCreationOutcome::NameConflict);
        }
        let token_count: usize =
            transaction.query_row("SELECT COUNT(*) FROM service_tokens", [], |row| row.get(0))?;
        if token_count >= MAX_SERVICE_TOKENS {
            transaction.rollback()?;
            return Ok(ServiceTokenCreationOutcome::CapacityReached);
        }

        let expires_at_string = expires_at.map(|value| value.to_rfc3339());
        transaction.execute(
            "INSERT INTO service_tokens(
                 name,token_hash,scope_mask,created_by,created_at,expires_at,last_used_at
             ) VALUES(?1,?2,1,?3,?4,?5,NULL)",
            params![
                name,
                token_hash(plaintext_token),
                admin_id,
                now_string,
                expires_at_string,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        let service_token = ServiceToken {
            id,
            name: name.to_owned(),
            scope_mask: super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
            created_by: admin_id,
            created_by_username: username.clone(),
            created_at: now_string,
            expires_at: expires_at_string,
            last_used_at: None,
        };
        let audit_context = AuditContext::new(username, context.client_ip.clone());
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::ServiceTokenCreated,
            Some(id.to_string()),
            Some("scope=monitoring:read".to_string()),
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(ServiceTokenCreationOutcome::Created(service_token))
    }

    pub fn list_service_tokens(&self) -> rusqlite::Result<Vec<ServiceToken>> {
        let connection = self.try_conn()?;
        let mut statement = connection.prepare_cached(
            "SELECT tokens.id,tokens.name,tokens.scope_mask,tokens.created_by,
                    admins.username,tokens.created_at,tokens.expires_at,tokens.last_used_at
             FROM service_tokens tokens
             JOIN admins ON admins.id=tokens.created_by
             ORDER BY tokens.id DESC",
        )?;
        let tokens = statement
            .query_map([], map_service_token)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(tokens)
    }

    #[cfg(test)]
    pub(crate) fn expire_service_token_for_test(&self, id: i64) -> rusqlite::Result<()> {
        let connection = self.try_conn()?;
        let changed = connection.execute(
            "UPDATE service_tokens SET expires_at=?2 WHERE id=?1",
            params![id, (Utc::now() - Duration::seconds(1)).to_rfc3339()],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn authorize_service_token(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome> {
        self.authorize_service_token_at(plaintext_token, required_scope_mask, Utc::now())
    }

    fn authorize_service_token_at(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome> {
        self.authorize_service_token_at_after_lookup(
            plaintext_token,
            required_scope_mask,
            now,
            || {},
        )
    }

    fn authorize_service_token_at_after_lookup<F>(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
        now: DateTime<Utc>,
        after_authorized_lookup: F,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome>
    where
        F: FnOnce(),
    {
        if required_scope_mask <= 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if !valid_service_token(plaintext_token) {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        }
        let connection = self.try_conn()?;
        let token = connection
            .query_row(
                "SELECT id,scope_mask,expires_at,last_used_at
                 FROM service_tokens WHERE token_hash=?1",
                [token_hash(plaintext_token)],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, scope_mask, expires_at, last_used_at)) = token else {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        };
        let expires_at = parse_optional_timestamp(expires_at, 2)?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        }
        if scope_mask & required_scope_mask != required_scope_mask {
            return Ok(ServiceTokenAuthorizationOutcome::InsufficientScope);
        }

        let last_used_at = parse_optional_timestamp(last_used_at, 3)?;
        after_authorized_lookup();
        let cutoff = now - Duration::seconds(SERVICE_TOKEN_TOUCH_INTERVAL_SECONDS);
        if last_used_at.is_none_or(|last_used_at| last_used_at <= cutoff) {
            // Revocation may linearize between the read and this throttled
            // metadata write. That request was already authorized; the guarded
            // update cannot resurrect it and every subsequent lookup fails.
            connection.execute(
                "UPDATE service_tokens SET last_used_at=?2
                 WHERE id=?1
                   AND (expires_at IS NULL OR expires_at>?2)
                   AND (last_used_at IS NULL OR last_used_at<=?3)",
                params![id, now.to_rfc3339(), cutoff.to_rfc3339()],
            )?;
        }
        Ok(ServiceTokenAuthorizationOutcome::Authorized { token_id: id })
    }

    pub fn revoke_service_token_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists = transaction
            .query_row("SELECT 1 FROM service_tokens WHERE id=?1", [id], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .is_some();
        if !exists {
            transaction.rollback()?;
            return Ok(false);
        }
        let deleted = transaction.execute("DELETE FROM service_tokens WHERE id=?1", [id])?;
        if deleted != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::ServiceTokenRevoked,
            Some(id.to_string()),
            None,
        )];
        insert_required_audits(&transaction, context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(context, &audit_events);
        Ok(true)
    }

    pub fn revoke_all_service_tokens_and_audit(
        &self,
        context: &AuditContext,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = transaction.execute("DELETE FROM service_tokens", [])?;
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::ServiceTokensRevokedAll,
            None,
            Some(format!("count={deleted}")),
        )];
        insert_required_audits(&transaction, context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(context, &audit_events);
        Ok(deleted)
    }

    pub fn monitoring_summary(&self, now: DateTime<Utc>) -> rusqlite::Result<MonitoringSummary> {
        let month = now.format("%Y-%m").to_string();
        let now_string = now.to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction()?;
        let (total, inactive, expired, download_limit_reached, available, protected) = transaction
            .query_row(
                "SELECT
                     COUNT(*),
                     COALESCE(SUM(CASE WHEN active=0 THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1 AND expires_at IS NOT NULL
                         AND expires_at<=?1 THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1
                         AND (expires_at IS NULL OR expires_at>?1)
                         AND max_downloads IS NOT NULL
                         AND download_count>=max_downloads THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN active=1
                         AND (expires_at IS NULL OR expires_at>?1)
                         AND (max_downloads IS NULL OR download_count<max_downloads)
                         THEN 1 ELSE 0 END),0),
                     COALESCE(SUM(CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END),0)
                 FROM shares",
                [&now_string],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )?;
        let statistics_started_at = transaction.query_row(
            "SELECT started_at FROM transfer_statistics WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let (download, zip_download, preview) = transaction.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN action='download' THEN count ELSE 0 END),0),
                 COALESCE(SUM(CASE WHEN action='zip_download' THEN count ELSE 0 END),0),
                 COALESCE(SUM(CASE WHEN action='preview' THEN count ELSE 0 END),0)
             FROM transfer_monthly_counts WHERE month=?1",
            [&month],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )?;
        transaction.commit()?;
        Ok(MonitoringSummary {
            total,
            available,
            inactive,
            expired,
            download_limit_reached,
            protected,
            transfers: TransferMonthlyCounts {
                month,
                download,
                zip_download,
                preview,
            },
            statistics_started_at,
        })
    }

    pub fn list_monitoring_share_page(
        &self,
        options: &MonitoringShareListOptions,
    ) -> rusqlite::Result<MonitoringSharePage> {
        let limit = options.limit.clamp(1, 200);
        let connection = self.try_conn()?;
        let mut statement = connection.prepare_cached(
            "WITH redacted AS (
                 SELECT shares.id,
                        CASE
                            WHEN shares.active=0 THEN 'inactive'
                            WHEN shares.expires_at IS NOT NULL AND shares.expires_at<=?2
                                THEN 'expired'
                            WHEN shares.max_downloads IS NOT NULL
                                 AND shares.download_count>=shares.max_downloads
                                THEN 'download_limit_reached'
                            ELSE 'available'
                        END AS status,
                        shares.permission,
                        shares.is_directory,
                        shares.password_hash IS NOT NULL AS password_protected,
                        shares.created_at,
                        shares.expires_at,
                        shares.download_count,
                        shares.max_downloads,
                        shares.max_upload_size,
                        COALESCE(usage.uploaded_bytes,0) AS uploaded_bytes,
                        shares.max_upload_total_size,
                        COALESCE(usage.uploaded_files,0) AS uploaded_files,
                        shares.max_upload_files
                 FROM shares
                 LEFT JOIN public_upload_usage usage ON usage.share_id=shares.id
             )
             SELECT id,status,permission,is_directory,password_protected,created_at,expires_at,
                    download_count,max_downloads,max_upload_size,uploaded_bytes,
                    max_upload_total_size,uploaded_files,max_upload_files
             FROM redacted
             WHERE (?1='all' OR status=?1)
               AND (?3 IS NULL OR id<?3)
             ORDER BY id DESC
             LIMIT ?4",
        )?;
        let mut shares = statement
            .query_map(
                params![
                    options.status.as_str(),
                    options.now.to_rfc3339(),
                    options.cursor,
                    limit.saturating_add(1) as i64,
                ],
                |row| {
                    let status = parse_monitoring_status(&row.get::<_, String>(1)?)?;
                    let permission = Permission::parse(&row.get::<_, String>(2)?)
                        .ok_or(rusqlite::Error::InvalidQuery)?;
                    let expires_at = parse_optional_timestamp(row.get::<_, Option<String>>(6)?, 6)?;
                    Ok(MonitoringShare {
                        id: row.get(0)?,
                        status,
                        permission,
                        is_directory: row.get::<_, i64>(3)? != 0,
                        password_protected: row.get::<_, i64>(4)? != 0,
                        created_at: row.get(5)?,
                        expires_at,
                        download_count: row.get(7)?,
                        max_downloads: row.get(8)?,
                        max_upload_size_bytes: row.get(9)?,
                        uploaded_bytes: row.get(10)?,
                        max_upload_total_size_bytes: row.get(11)?,
                        uploaded_files: row.get(12)?,
                        max_upload_files: row.get(13)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next_cursor = if shares.len() > limit {
            shares.pop();
            shares.last().map(|share| share.id)
        } else {
            None
        };
        Ok(MonitoringSharePage {
            shares,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service_token(seed: u8) -> String {
        format!(
            "{SERVICE_TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode([seed; SERVICE_TOKEN_RANDOM_BYTES])
        )
    }

    fn authenticated_database() -> Database {
        let database = Database::open(":memory:").unwrap();
        database
            .create_admin("admin", "password-hash", "secret")
            .unwrap();
        database
            .create_session("admin-session", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        assert!(database.verify_mfa("admin-session").unwrap());
        database
    }

    fn create_token(database: &Database, name: &str, seed: u8) -> (String, ServiceToken) {
        let plaintext = test_service_token(seed);
        let context = AuditContext::new("admin", None);
        let outcome = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                name,
                &plaintext,
                Some(Utc::now() + Duration::days(1)),
                &context,
            )
            .unwrap();
        let ServiceTokenCreationOutcome::Created(token) = outcome else {
            panic!("service token was not created")
        };
        (plaintext, token)
    }

    #[test]
    fn service_tokens_store_only_hash_and_touch_at_most_every_five_minutes() {
        let database = authenticated_database();
        let (plaintext, token) = create_token(&database, "Home Assistant", 7);
        let stored: (String, Option<String>) = database
            .conn()
            .query_row(
                "SELECT token_hash,last_used_at FROM service_tokens WHERE id=?1",
                [token.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored.0, token_hash(&plaintext));
        assert!(!stored.0.contains(&plaintext));
        assert!(stored.1.is_none());

        let first = Utc::now();
        assert_eq!(
            database
                .authorize_service_token_at(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                    first,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );
        let first_touch: String = database
            .conn()
            .query_row(
                "SELECT last_used_at FROM service_tokens WHERE id=?1",
                [token.id],
                |row| row.get(0),
            )
            .unwrap();
        database
            .authorize_service_token_at(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                first + Duration::minutes(4),
            )
            .unwrap();
        let throttled_touch: String = database
            .conn()
            .query_row(
                "SELECT last_used_at FROM service_tokens WHERE id=?1",
                [token.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(throttled_touch, first_touch);
        database
            .authorize_service_token_at(
                &plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                first + Duration::minutes(5),
            )
            .unwrap();
        let refreshed_touch: String = database
            .conn()
            .query_row(
                "SELECT last_used_at FROM service_tokens WHERE id=?1",
                [token.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(refreshed_touch, first_touch);
    }

    #[test]
    fn service_token_create_rechecks_live_mfa_session_password_and_capacity() {
        let database = authenticated_database();
        let context = AuditContext::new("admin", None);
        let rejected = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "stale-hash",
                "Rejected",
                &test_service_token(1),
                None,
                &context,
            )
            .unwrap();
        assert_eq!(
            rejected,
            ServiceTokenCreationOutcome::ReauthenticationRejected
        );

        for index in 0..MAX_SERVICE_TOKENS {
            create_token(&database, &format!("token-{index}"), index as u8);
        }
        let capacity = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                "one-too-many",
                &test_service_token(255),
                None,
                &context,
            )
            .unwrap();
        assert_eq!(capacity, ServiceTokenCreationOutcome::CapacityReached);
        let direct_insert = database.conn().execute(
            "INSERT INTO service_tokens(
                 name,token_hash,scope_mask,created_by,created_at
             ) VALUES('direct-overflow',?1,1,1,?2)",
            params![
                token_hash(&test_service_token(255)),
                Utc::now().to_rfc3339()
            ],
        );
        assert!(direct_insert.is_err());
    }

    #[test]
    fn service_token_expiration_must_be_strictly_in_the_future() {
        let database = authenticated_database();
        let context = AuditContext::new("admin", None);
        for (index, expires_at) in [Utc::now() - Duration::seconds(1), Utc::now()]
            .into_iter()
            .enumerate()
        {
            let result = database.create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                &format!("invalid-expiry-{index}"),
                &test_service_token(index as u8 + 40),
                Some(expires_at),
                &context,
            );
            assert!(matches!(result, Err(rusqlite::Error::InvalidQuery)));
        }
        assert!(database.list_service_tokens().unwrap().is_empty());
        assert_eq!(
            database.count_audit(Some("service_token_created")).unwrap(),
            0
        );

        let future = Utc::now() + Duration::days(1);
        let future_string = future.to_rfc3339();
        let outcome = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                "future-expiry",
                &test_service_token(42),
                Some(future),
                &context,
            )
            .unwrap();
        let ServiceTokenCreationOutcome::Created(created) = outcome else {
            panic!("future service-token expiration was rejected")
        };
        assert_eq!(created.expires_at.as_deref(), Some(future_string.as_str()));
    }

    #[test]
    fn service_token_names_are_canonical_and_case_insensitively_unique() {
        assert!(super::super::valid_service_token_name("Home Assistant"));
        for invalid in ["", " padded", "padded ", "line\nbreak"] {
            assert!(!super::super::valid_service_token_name(invalid));
        }
        assert!(!super::super::valid_service_token_name(
            &"x".repeat(super::super::SERVICE_TOKEN_NAME_MAX_CHARACTERS + 1)
        ));

        let database = authenticated_database();
        create_token(&database, "Home Assistant", 20);
        let outcome = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                "home assistant",
                &test_service_token(21),
                None,
                &AuditContext::new("admin", None),
            )
            .unwrap();
        assert_eq!(outcome, ServiceTokenCreationOutcome::NameConflict);
        assert_eq!(database.list_service_tokens().unwrap().len(), 1);
    }

    #[test]
    fn unknown_expired_and_insufficient_scope_tokens_are_indistinguishable_or_scoped() {
        let database = authenticated_database();
        let (plaintext, token) = create_token(&database, "Authorization", 30);
        assert_eq!(
            database
                .authorize_service_token(
                    &test_service_token(31),
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Unauthorized
        );
        assert_eq!(
            database.authorize_service_token(&plaintext, 2).unwrap(),
            ServiceTokenAuthorizationOutcome::InsufficientScope
        );
        database
            .conn()
            .execute(
                "UPDATE service_tokens SET expires_at=?2 WHERE id=?1",
                params![token.id, (Utc::now() - Duration::minutes(1)).to_rfc3339()],
            )
            .unwrap();
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Unauthorized
        );
    }

    #[test]
    fn create_and_revoke_all_roll_back_when_required_audit_is_unavailable() {
        let database = authenticated_database();
        database
            .conn()
            .execute_batch(
                "CREATE TRIGGER fail_service_token_required_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action IN ('service_token_created','service_tokens_revoked_all')
                 BEGIN
                     SELECT RAISE(FAIL, 'injected audit failure');
                 END;",
            )
            .unwrap();
        let context = AuditContext::new("admin", None);
        let create_error = database
            .create_service_token_for_verified_admin_and_audit(
                "admin-session",
                1,
                "password-hash",
                "Rolled Back",
                &test_service_token(40),
                None,
                &context,
            )
            .unwrap_err();
        assert!(super::super::is_audit_unavailable(&create_error));
        assert!(database.list_service_tokens().unwrap().is_empty());

        database
            .conn()
            .execute_batch("DROP TRIGGER fail_service_token_required_audit")
            .unwrap();
        create_token(&database, "Preserved", 41);
        database
            .conn()
            .execute_batch(
                "CREATE TRIGGER fail_service_token_required_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action='service_tokens_revoked_all'
                 BEGIN
                     SELECT RAISE(FAIL, 'injected audit failure');
                 END;",
            )
            .unwrap();
        let revoke_error = database
            .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
            .unwrap_err();
        assert!(super::super::is_audit_unavailable(&revoke_error));
        assert_eq!(database.list_service_tokens().unwrap().len(), 1);
    }

    #[test]
    fn revoked_ids_are_not_reused_and_revoke_all_is_audited_even_when_empty() {
        let database = authenticated_database();
        let (_, first) = create_token(&database, "First", 50);
        let context = AuditContext::new("admin", None);
        assert!(database
            .revoke_service_token_and_audit(first.id, &context)
            .unwrap());
        assert!(!database
            .revoke_service_token_and_audit(first.id, &context)
            .unwrap());
        let (_, second) = create_token(&database, "Second", 51);
        assert!(second.id > first.id);
        assert_eq!(
            database
                .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .count_audit(Some("service_tokens_revoked_all"))
                .unwrap(),
            2
        );
    }

    #[test]
    fn revocation_and_required_audit_are_atomic() {
        let database = authenticated_database();
        let (plaintext, token) = create_token(&database, "Revocable", 11);
        database
            .conn()
            .execute_batch(
                "CREATE TRIGGER fail_service_token_audit
                 BEFORE INSERT ON audit
                 WHEN NEW.action IN ('service_token_revoked','service_tokens_revoked_all')
                 BEGIN
                     SELECT RAISE(FAIL, 'injected audit failure');
                 END;",
            )
            .unwrap();
        let context = AuditContext::new("admin", None);
        let error = database
            .revoke_service_token_and_audit(token.id, &context)
            .unwrap_err();
        assert!(super::super::is_audit_unavailable(&error));
        assert_eq!(database.list_service_tokens().unwrap().len(), 1);
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );
    }

    #[test]
    fn monitoring_queries_apply_status_priority_and_return_only_redacted_fields() {
        let database = authenticated_database();
        let now = Utc::now();
        let available = database
            .create_share_with_upload_limits(
                "available-share-secret",
                Some("private-alias"),
                "private/path",
                true,
                &Permission::DownloadUpload,
                None,
                Some(10),
                Some(100),
                Some(1_000),
                Some(10),
                1,
                Some("private-password-hash"),
                &super::super::UploadConflictStrategy::Reject,
            )
            .unwrap();
        let inactive = database
            .create_share(
                "inactive-share-secret",
                None,
                "inactive/path",
                false,
                &Permission::DownloadOnly,
                Some(now - Duration::days(1)),
                Some(1),
                None,
                1,
                None,
                &super::super::UploadConflictStrategy::Reject,
            )
            .unwrap();
        let expired = database
            .create_share(
                "expired-share-secret",
                None,
                "expired/path",
                false,
                &Permission::DownloadOnly,
                Some(now - Duration::days(1)),
                None,
                None,
                1,
                None,
                &super::super::UploadConflictStrategy::Reject,
            )
            .unwrap();
        let limited = database
            .create_share(
                "limited-share-secret",
                None,
                "limited/path",
                false,
                &Permission::DownloadOnly,
                None,
                Some(2),
                None,
                1,
                None,
                &super::super::UploadConflictStrategy::Reject,
            )
            .unwrap();
        database
            .conn()
            .execute("UPDATE shares SET active=0 WHERE id=?1", [inactive])
            .unwrap();
        database
            .conn()
            .execute("UPDATE shares SET download_count=2 WHERE id=?1", [limited])
            .unwrap();
        database
            .conn()
            .execute(
                "INSERT INTO public_upload_usage(share_id,uploaded_bytes,uploaded_files)
                 VALUES(?1,250,3)",
                [available],
            )
            .unwrap();
        database
            .conn()
            .execute(
                "INSERT INTO transfer_monthly_counts(month,action,count)
                 VALUES(?1,'download',42),
                       (?1,'zip_download',3),
                       (?1,'preview',11)",
                [now.format("%Y-%m").to_string()],
            )
            .unwrap();

        let summary = database.monitoring_summary(now).unwrap();
        assert_eq!(summary.total, 4);
        assert_eq!(summary.available, 1);
        assert_eq!(summary.inactive, 1);
        assert_eq!(summary.expired, 1);
        assert_eq!(summary.download_limit_reached, 1);
        assert_eq!(summary.protected, 1);
        assert_eq!(summary.transfers.download, 42);
        assert_eq!(summary.transfers.zip_download, 3);
        assert_eq!(summary.transfers.preview, 11);

        let all = database
            .list_monitoring_share_page(&MonitoringShareListOptions {
                status: super::super::MonitoringShareListStatus::All,
                cursor: None,
                limit: 3,
                now,
            })
            .unwrap();
        assert_eq!(all.shares.len(), 3);
        assert_eq!(all.next_cursor, all.shares.last().map(|share| share.id));
        assert_eq!(all.shares[0].id, limited);
        assert_eq!(
            all.shares[0].status,
            MonitoringShareStatus::DownloadLimitReached
        );
        let second = database
            .list_monitoring_share_page(&MonitoringShareListOptions {
                status: super::super::MonitoringShareListStatus::All,
                cursor: all.next_cursor,
                limit: 3,
                now,
            })
            .unwrap();
        assert_eq!(second.shares.len(), 1);
        assert_eq!(second.shares[0].id, available);
        assert!(second.shares[0].password_protected);
        assert_eq!(second.shares[0].uploaded_bytes, 250);
        assert_eq!(second.shares[0].uploaded_files, 3);

        let inactive_page = database
            .list_monitoring_share_page(&MonitoringShareListOptions {
                status: super::super::MonitoringShareListStatus::Inactive,
                cursor: None,
                limit: 50,
                now,
            })
            .unwrap();
        assert_eq!(inactive_page.shares.len(), 1);
        assert_eq!(inactive_page.shares[0].id, inactive);
        assert_eq!(
            inactive_page.shares[0].status,
            MonitoringShareStatus::Inactive
        );
        assert_ne!(inactive_page.shares[0].id, expired);
    }

    #[test]
    fn service_tokens_are_instance_wide_across_creator_account_changes() {
        let database = authenticated_database();
        database
            .create_admin("second-admin", "second-password-hash", "second-secret")
            .unwrap();
        let (plaintext, token) = create_token(&database, "Instance-wide", 60);

        assert_eq!(
            database.deactivate_admin(1).unwrap(),
            super::super::AdminDeactivationOutcome::Deactivated
        );
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );

        assert!(database
            .reset_admin_password(1, "replacement-password-hash")
            .unwrap());
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );

        assert_eq!(
            database.reset_admin_totp(1, "replacement-secret").unwrap(),
            Some("admin".to_string())
        );
        assert_eq!(
            database
                .authorize_service_token(
                    &plaintext,
                    super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                )
                .unwrap(),
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );
        let listed = database.list_service_tokens().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, token.id);
        assert_eq!(listed[0].name, token.name);
    }

    #[test]
    fn authorized_monitoring_read_may_finish_across_revoke_without_resurrecting_token() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("data.sqlite")).unwrap();
        database
            .create_admin("admin", "password-hash", "secret")
            .unwrap();
        database
            .create_session("admin-session", 1, "csrf", Utc::now() + Duration::hours(1))
            .unwrap();
        assert!(database.verify_mfa("admin-session").unwrap());
        let (plaintext, token) = create_token(&database, "Race", 70);

        let (lookup_sender, lookup_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let authorizing_database = database.clone();
        let authorizing_plaintext = plaintext.clone();
        let request = std::thread::spawn(move || -> rusqlite::Result<_> {
            let authorization = authorizing_database.authorize_service_token_at_after_lookup(
                &authorizing_plaintext,
                super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                Utc::now(),
                || {
                    lookup_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                },
            )?;
            // This models the rest of the already-authorized monitoring
            // handler. Revocation removes future authority, not an in-flight
            // read that has already crossed the authorization boundary.
            let summary = authorizing_database.monitoring_summary(Utc::now())?;
            Ok((authorization, summary))
        });
        lookup_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        assert!(database
            .revoke_service_token_and_audit(
                token.id,
                &AuditContext::new("admin", Some("192.0.2.1".into())),
            )
            .unwrap());
        release_sender.send(()).unwrap();
        let (authorization, summary) = request.join().unwrap().unwrap();
        assert_eq!(
            authorization,
            ServiceTokenAuthorizationOutcome::Authorized { token_id: token.id }
        );
        assert_eq!(summary.total, 0);
        assert_eq!(
            database
                .conn()
                .query_row::<i64, _, _>(
                    "SELECT COUNT(*) FROM service_tokens WHERE id=?1",
                    [token.id],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        for _ in 0..3 {
            assert_eq!(
                database
                    .authorize_service_token(
                        &plaintext,
                        super::super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                    )
                    .unwrap(),
                ServiceTokenAuthorizationOutcome::Unauthorized
            );
        }
    }

    #[test]
    fn service_token_audit_fields_never_contain_plaintext_or_hash() {
        let database = authenticated_database();
        let (first_plaintext, first) = create_token(&database, "Audit first", 80);
        let first_hash = token_hash(&first_plaintext);
        // A token-shaped value is a valid 1-80 character name. Audit details
        // must therefore never mirror administrator-supplied token names.
        let (second_plaintext, second) = create_token(&database, &first_plaintext, 81);
        let second_hash = token_hash(&second_plaintext);
        assert!(database
            .revoke_service_token_and_audit(second.id, &AuditContext::new("admin", None))
            .unwrap());
        assert_eq!(
            database
                .revoke_all_service_tokens_and_audit(&AuditContext::new("local_recovery", None))
                .unwrap(),
            1
        );

        let events = database.list_audit(None, 100, 0).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action.starts_with("service_token"))
                .count(),
            4
        );
        for event in events
            .into_iter()
            .filter(|event| event.action.starts_with("service_token"))
        {
            match event.action.as_str() {
                "service_token_created" => {
                    assert_eq!(event.detail.as_deref(), Some("scope=monitoring:read"));
                }
                "service_token_revoked" => assert!(event.detail.is_none()),
                "service_tokens_revoked_all" => {
                    assert_eq!(event.detail.as_deref(), Some("count=1"));
                }
                action => panic!("unexpected service-token audit action: {action}"),
            }
            let persisted = [
                Some(event.occurred_at.as_str()),
                Some(event.actor.as_str()),
                Some(event.action.as_str()),
                event.object_id.as_deref(),
                event.detail.as_deref(),
                event.client_ip.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
            for forbidden in [
                first_plaintext.as_str(),
                first_hash.as_str(),
                second_plaintext.as_str(),
                second_hash.as_str(),
            ] {
                assert!(!persisted.contains(forbidden));
            }
            assert!(!persisted.contains("token_hash"));
        }
        assert_ne!(first.id, second.id);
    }
}
