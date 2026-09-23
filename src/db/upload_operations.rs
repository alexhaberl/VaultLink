use chrono::{Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

use super::{token_hash, Database};
use crate::auth;

const RETENTION_HOURS: i64 = 24;
const MAX_UNUSED_PER_SCOPE: i64 = 64;
const MAX_UNUSED_GLOBAL: i64 = 4096;
const MAX_ALL_PER_SCOPE: i64 = 4096;
const MAX_ALL_GLOBAL: i64 = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UploadOperationScope {
    Admin(i64),
    Share(i64),
}

impl UploadOperationScope {
    fn parts(self) -> (&'static str, i64) {
        match self {
            Self::Admin(id) => ("admin", id),
            Self::Share(id) => ("share", id),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UploadOperationView {
    pub(crate) state: String,
    pub(crate) expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<serde_json::Value>,
    #[serde(skip_serializing)]
    pub(crate) fingerprint: Option<String>,
}

#[derive(Debug)]
pub(crate) enum UploadOperationClaim {
    Started,
    Existing(UploadOperationView),
    Unavailable,
}

impl Database {
    pub(crate) fn register_active_upload_operation(&self, id_hash: &str) {
        self.0
            .active_upload_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id_hash.to_owned());
    }

    pub(crate) fn unregister_active_upload_operation(&self, id_hash: &str) {
        self.0
            .active_upload_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id_hash);
    }

    pub(crate) fn create_upload_operation(
        &self,
        scope: UploadOperationScope,
    ) -> rusqlite::Result<Option<(String, String)>> {
        let (kind, id) = scope.parts();
        if id <= 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires = (now + Duration::hours(RETENTION_HOURS)).to_rfc3339();
        let _write_guard = self.transfer_write_guard()?;
        let mut conn = self.try_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM upload_operations WHERE expires_at<=?1
             AND state IN ('ready','retryable','completed','rejected','outcome_unknown')",
            [&now_text],
        )?;
        let counts: (i64, i64, i64, i64) = tx.query_row(
            "SELECT
               COUNT(*) FILTER (WHERE scope_kind=?1 AND scope_id=?2 AND state IN ('ready','retryable')),
               COUNT(*) FILTER (WHERE state IN ('ready','retryable')),
               COUNT(*) FILTER (WHERE scope_kind=?1 AND scope_id=?2),
               COUNT(*)
             FROM upload_operations",
            params![kind, id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if counts.0 >= MAX_UNUSED_PER_SCOPE
            || counts.1 >= MAX_UNUSED_GLOBAL
            || counts.2 >= MAX_ALL_PER_SCOPE
            || counts.3 >= MAX_ALL_GLOBAL
        {
            return Ok(None);
        }
        let id_token = auth::random_token(32);
        tx.execute(
            "INSERT INTO upload_operations(id_hash,scope_kind,scope_id,state,created_at,expires_at)
             VALUES(?1,?2,?3,'ready',?4,?5)",
            params![token_hash(&id_token), kind, id, now_text, expires],
        )?;
        tx.commit()?;
        Ok(Some((id_token, expires)))
    }

    pub(crate) fn upload_operation(
        &self,
        scope: UploadOperationScope,
        id_token: &str,
    ) -> rusqlite::Result<Option<UploadOperationView>> {
        let (kind, id) = scope.parts();
        let conn = self.try_conn()?;
        let row = conn
            .query_row(
                "SELECT state,expires_at,result_json,fingerprint FROM upload_operations
                 WHERE id_hash=?1 AND scope_kind=?2 AND scope_id=?3",
                params![token_hash(id_token), kind, id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((state, expires_at, result_json, fingerprint)) = row else {
            return Ok(None);
        };
        if expires_at <= Utc::now().to_rfc3339()
            && !matches!(state.as_str(), "processing" | "committing")
        {
            return Ok(None);
        }
        let result = result_json
            .map(|json| serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?;
        Ok(Some(UploadOperationView {
            state: if state == "committing" {
                "processing".to_owned()
            } else {
                state
            },
            expires_at,
            result,
            fingerprint,
        }))
    }

    pub(crate) fn claim_upload_operation(
        &self,
        scope: UploadOperationScope,
        id_token: &str,
    ) -> rusqlite::Result<UploadOperationClaim> {
        let _write_guard = self.transfer_write_guard()?;
        let mut conn = self.try_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (kind, id) = scope.parts();
        let changed = tx.execute(
            "UPDATE upload_operations SET state='processing'
             WHERE id_hash=?1 AND scope_kind=?2 AND scope_id=?3
               AND state IN ('ready','retryable') AND expires_at>?4",
            params![token_hash(id_token), kind, id, Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
        drop(conn);
        if changed == 1 {
            Ok(UploadOperationClaim::Started)
        } else {
            Ok(self.upload_operation(scope, id_token)?.map_or(
                UploadOperationClaim::Unavailable,
                UploadOperationClaim::Existing,
            ))
        }
    }

    pub(crate) fn bind_upload_fingerprint(
        &self,
        id_hash: &str,
        fingerprint: &str,
        fragment_name: &str,
    ) -> rusqlite::Result<bool> {
        let _write_guard = self.transfer_write_guard()?;
        let conn = self.try_conn()?;
        Ok(conn.execute(
            "UPDATE upload_operations SET fingerprint=?2,fragment_name=?3
             WHERE id_hash=?1 AND state IN ('processing','committing')
               AND (fingerprint IS NULL OR fingerprint=?2)",
            params![id_hash, fingerprint, fragment_name],
        )? == 1)
    }

    pub(crate) fn release_upload_operation(&self, id_hash: &str) -> rusqlite::Result<()> {
        let _write_guard = self.transfer_write_guard()?;
        let conn = self.try_conn()?;
        conn.execute(
            "UPDATE upload_operations SET state='retryable',fragment_name=NULL,fingerprint=NULL
             WHERE id_hash=?1 AND state='processing'",
            [id_hash],
        )?;
        Ok(())
    }

    pub(crate) fn mark_upload_committing(&self, id_hash: &str) -> rusqlite::Result<bool> {
        let _write_guard = self.transfer_write_guard()?;
        let conn = self.try_conn()?;
        Ok(conn.execute(
            "UPDATE upload_operations SET state='committing'
             WHERE id_hash=?1 AND state='processing'",
            [id_hash],
        )? == 1)
    }

    pub(crate) fn finish_upload_operation(
        &self,
        id_hash: &str,
        state: &str,
        result: Option<&serde_json::Value>,
    ) -> rusqlite::Result<bool> {
        if !matches!(
            state,
            "retryable" | "completed" | "rejected" | "outcome_unknown"
        ) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let _write_guard = self.transfer_write_guard()?;
        let conn = self.try_conn()?;
        let expires = (Utc::now() + Duration::hours(RETENTION_HOURS)).to_rfc3339();
        let result = result
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(conn.execute(
            "UPDATE upload_operations SET state=?2,result_json=?3,
               expires_at=CASE WHEN ?2='retryable' THEN expires_at ELSE ?4 END,
               fingerprint=CASE WHEN ?2='retryable' THEN NULL ELSE fingerprint END,
               fragment_name=CASE WHEN ?2='outcome_unknown' THEN fragment_name ELSE NULL END
             WHERE id_hash=?1 AND state IN ('processing','committing')",
            params![id_hash, state, result, expires],
        )? == 1)
    }

    /// Recover once before admitting new storage mutations. An entered commit
    /// may have published or booked quota; it can never be retried blindly.
    pub(crate) fn recover_upload_operations(&self) -> rusqlite::Result<()> {
        let active = self
            .0
            .active_upload_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let _write_guard = self.transfer_write_guard()?;
        let mut conn = self.try_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending = {
            let mut query = tx.prepare("SELECT id_hash,state FROM upload_operations WHERE state IN ('processing','committing')")?;
            let rows = query
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let expires = (Utc::now() + Duration::hours(RETENTION_HOURS)).to_rfc3339();
        for (id_hash, state) in pending {
            if active.contains(&id_hash) {
                continue;
            }
            if state == "processing" {
                tx.execute("UPDATE upload_operations SET state='retryable',fragment_name=NULL,fingerprint=NULL WHERE id_hash=?1 AND state='processing'", [&id_hash])?;
            } else {
                tx.execute("UPDATE upload_operations SET state='outcome_unknown',expires_at=?2 WHERE id_hash=?1 AND state='committing'", params![id_hash, expires])?;
            }
        }
        tx.commit()
    }

    pub(crate) fn protected_upload_fragments(
        &self,
    ) -> rusqlite::Result<std::collections::HashSet<String>> {
        let conn = self.try_conn()?;
        let mut query = conn.prepare(
            "SELECT fragment_name FROM upload_operations
             WHERE fragment_name IS NOT NULL AND state IN ('committing','outcome_unknown')
               AND (state='committing' OR expires_at>?1)",
        )?;
        let fragments = query
            .query_map([Utc::now().to_rfc3339()], |row| row.get::<_, String>(0))?
            .collect();
        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_operation_is_bound_to_owner_and_cannot_be_claimed_twice() {
        let database = Database::open(":memory:").unwrap();
        let scope = UploadOperationScope::Admin(1);
        let (id, _) = database.create_upload_operation(scope).unwrap().unwrap();
        assert_eq!(id.len(), 43);
        assert!(database
            .upload_operation(UploadOperationScope::Admin(2), &id)
            .unwrap()
            .is_none());
        assert!(matches!(
            database.claim_upload_operation(scope, &id).unwrap(),
            UploadOperationClaim::Started
        ));
        assert!(
            matches!(database.claim_upload_operation(scope, &id).unwrap(), UploadOperationClaim::Existing(view) if view.state == "processing")
        );
        let hash = token_hash(&id);
        assert!(database
            .bind_upload_fingerprint(&hash, "same-request", ".vaultlink-upload-fragment-test")
            .unwrap());
        assert!(!database
            .bind_upload_fingerprint(
                &hash,
                "different-request",
                ".vaultlink-upload-fragment-test"
            )
            .unwrap());
        assert!(database.mark_upload_committing(&hash).unwrap());
        let receipt = serde_json::json!({"file":"one.txt","outcome":"created","warnings":[]});
        assert!(database
            .finish_upload_operation(&hash, "completed", Some(&receipt))
            .unwrap());
        assert!(
            matches!(database.claim_upload_operation(scope, &id).unwrap(), UploadOperationClaim::Existing(view) if view.state == "completed" && view.result == Some(receipt))
        );
    }

    #[test]
    fn unused_capacity_and_expired_ids_fail_closed() {
        let database = Database::open(":memory:").unwrap();
        let scope = UploadOperationScope::Share(7);
        let ids = (0..MAX_UNUSED_PER_SCOPE)
            .map(|_| database.create_upload_operation(scope).unwrap().unwrap().0)
            .collect::<Vec<_>>();
        assert!(database.create_upload_operation(scope).unwrap().is_none());
        assert!(database
            .create_upload_operation(UploadOperationScope::Share(8))
            .unwrap()
            .is_some());
        database
            .conn()
            .execute(
                "UPDATE upload_operations SET expires_at='2000-01-01T00:00:00Z' WHERE id_hash=?1",
                [token_hash(&ids[0])],
            )
            .unwrap();
        assert!(database.upload_operation(scope, &ids[0]).unwrap().is_none());
        assert!(matches!(
            database.claim_upload_operation(scope, &ids[0]).unwrap(),
            UploadOperationClaim::Unavailable
        ));
        assert!(database.create_upload_operation(scope).unwrap().is_some());
    }

    #[test]
    fn retryable_upload_does_not_extend_the_registration_deadline() {
        let database = Database::open(":memory:").unwrap();
        let scope = UploadOperationScope::Admin(1);
        let (id, original_expiry) = database.create_upload_operation(scope).unwrap().unwrap();
        assert!(matches!(
            database.claim_upload_operation(scope, &id).unwrap(),
            UploadOperationClaim::Started
        ));
        assert!(database
            .finish_upload_operation(&token_hash(&id), "retryable", None)
            .unwrap());
        let view = database.upload_operation(scope, &id).unwrap().unwrap();
        assert_eq!(view.state, "retryable");
        assert_eq!(view.expires_at, original_expiry);
    }

    #[test]
    fn recovery_retries_only_uncommitted_receivers() {
        let database = Database::open(":memory:").unwrap();
        let scope = UploadOperationScope::Share(1);
        let (retry_id, _) = database.create_upload_operation(scope).unwrap().unwrap();
        let (unknown_id, _) = database.create_upload_operation(scope).unwrap().unwrap();
        assert!(matches!(
            database.claim_upload_operation(scope, &retry_id).unwrap(),
            UploadOperationClaim::Started
        ));
        assert!(matches!(
            database.claim_upload_operation(scope, &unknown_id).unwrap(),
            UploadOperationClaim::Started
        ));
        assert!(database
            .mark_upload_committing(&token_hash(&unknown_id))
            .unwrap());
        database.recover_upload_operations().unwrap();
        assert_eq!(
            database
                .upload_operation(scope, &retry_id)
                .unwrap()
                .unwrap()
                .state,
            "retryable"
        );
        assert_eq!(
            database
                .upload_operation(scope, &unknown_id)
                .unwrap()
                .unwrap()
                .state,
            "outcome_unknown"
        );
        assert!(matches!(
            database.claim_upload_operation(scope, &unknown_id).unwrap(),
            UploadOperationClaim::Existing(_)
        ));
    }

    #[test]
    fn in_process_recovery_preserves_active_upload_finalizer() {
        let database = Database::open(":memory:").unwrap();
        let scope = UploadOperationScope::Admin(1);
        let (active_id, _) = database.create_upload_operation(scope).unwrap().unwrap();
        let (abandoned_id, _) = database.create_upload_operation(scope).unwrap().unwrap();
        for id in [&active_id, &abandoned_id] {
            assert!(matches!(
                database.claim_upload_operation(scope, id).unwrap(),
                UploadOperationClaim::Started
            ));
            assert!(database.mark_upload_committing(&token_hash(id)).unwrap());
        }
        database.register_active_upload_operation(&token_hash(&active_id));
        database.recover_upload_operations().unwrap();
        assert_eq!(
            database
                .upload_operation(scope, &active_id)
                .unwrap()
                .unwrap()
                .state,
            "processing"
        );
        assert_eq!(
            database
                .upload_operation(scope, &abandoned_id)
                .unwrap()
                .unwrap()
                .state,
            "outcome_unknown"
        );
        database.unregister_active_upload_operation(&token_hash(&active_id));
        database.recover_upload_operations().unwrap();
        assert_eq!(
            database
                .upload_operation(scope, &active_id)
                .unwrap()
                .unwrap()
                .state,
            "outcome_unknown"
        );
    }

    #[test]
    fn unfinished_operation_survives_database_reopen_without_republication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upload-recovery.sqlite");
        let scope = UploadOperationScope::Share(1);
        let id = {
            let database = Database::open(&path).unwrap();
            let (id, _) = database.create_upload_operation(scope).unwrap().unwrap();
            assert!(matches!(
                database.claim_upload_operation(scope, &id).unwrap(),
                UploadOperationClaim::Started
            ));
            assert!(database
                .bind_upload_fingerprint(
                    &token_hash(&id),
                    "fingerprint",
                    ".vaultlink-upload-fragment-restart"
                )
                .unwrap());
            assert!(database.mark_upload_committing(&token_hash(&id)).unwrap());
            id
        };
        let reopened = Database::open(&path).unwrap();
        reopened.recover_upload_operations().unwrap();
        let result = reopened.upload_operation(scope, &id).unwrap().unwrap();
        assert_eq!(result.state, "outcome_unknown");
        assert_eq!(result.fingerprint.as_deref(), Some("fingerprint"));
        assert!(reopened
            .protected_upload_fragments()
            .unwrap()
            .contains(".vaultlink-upload-fragment-restart"));
        assert!(matches!(
            reopened.claim_upload_operation(scope, &id).unwrap(),
            UploadOperationClaim::Existing(_)
        ));
    }
}
