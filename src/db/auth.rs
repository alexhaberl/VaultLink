use super::{
    insert_required_audits, token_hash, trace_required_audits, Admin, AdminDeactivationOutcome,
    AdminMfaEnrollmentActivationOutcome, AdminPasswordChangeOutcome, AdminRecoveryOutcome,
    AdminSummary, AdminTotpSettingOutcome, AdminWebauthnCredential,
    AdminWebauthnCredentialDeletionOutcome, AuditAction, AuditContext, Audited,
    AuditedAdminMfaEnrollmentStartOutcome, Database, InitialAdminOutcome, MfaMutationContext,
    MfaSessionAuthentication, MfaSessionProof, PasswordSessionCreationOutcome,
    PendingAdminMfaEnrollment, RequiredAuditDecision, RequiredAuditEvent, Session, SessionBound,
    ADMIN_MFA_ENROLLMENT_TTL_SECONDS,
};
#[cfg(test)]
use super::{AdminMfaEnrollmentStartOutcome, AdminWebauthnCredentialRegistrationOutcome};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, DropBehavior, OptionalExtension, Transaction, TransactionBehavior};

use crate::sensitive::SecretString;

const SESSION_TOUCH_INTERVAL_SECONDS: i64 = 60;

struct SessionTimes {
    now: String,
    idle_cutoff: String,
    touch_cutoff: String,
}

impl Database {
    fn session_times(&self, now: DateTime<Utc>) -> SessionTimes {
        SessionTimes {
            now: now.to_rfc3339(),
            idle_cutoff: (now - Duration::minutes(self.session_idle_minutes())).to_rfc3339(),
            touch_cutoff: (now - Duration::seconds(SESSION_TOUCH_INTERVAL_SECONDS)).to_rfc3339(),
        }
    }
}

fn consume_admin_totp_step(
    transaction: &Transaction<'_>,
    admin_id: i64,
    step: u64,
) -> rusqlite::Result<bool> {
    if !admin_totp_step_is_fresh(transaction, admin_id, step)? {
        return Ok(false);
    }
    Ok(transaction.execute(
        "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
         ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step
         WHERE excluded.last_step>admin_totp_replay.last_step",
        params![admin_id, step as i64],
    )? == 1)
}

fn admin_totp_step_is_fresh(
    transaction: &Transaction<'_>,
    admin_id: i64,
    step: u64,
) -> rusqlite::Result<bool> {
    if step > i64::MAX as u64 {
        return Ok(false);
    }
    transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM admins
             WHERE id=?1 AND active=1
               AND NOT EXISTS(
                   SELECT 1 FROM admin_totp_replay
                   WHERE admin_id=?1 AND last_step>=?2
               )
         )",
        params![admin_id, step as i64],
        |row| row.get::<_, bool>(0),
    )
}

fn cleanup_admin_mfa_enrollments(
    transaction: &Transaction<'_>,
    now: &str,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
        [now],
    )
}

fn revoke_admin_auth_state(transaction: &Transaction<'_>, admin_id: i64) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [admin_id])?;
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE admin_id=?1",
        [admin_id],
    )?;
    Ok(())
}

fn live_mfa_session(
    transaction: &Transaction<'_>,
    proof: &MfaSessionProof,
    times: &SessionTimes,
) -> rusqlite::Result<bool> {
    transaction.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM sessions
             JOIN admins ON admins.id=sessions.admin_id
             WHERE sessions.token_hash=?1
               AND sessions.admin_id=?2
               AND sessions.mfa_verified=1
               AND sessions.expires_at>?3
               AND sessions.last_activity_at>?4
               AND admins.active=1
         )",
        params![
            proof.token_hash.as_str(),
            proof.admin_id,
            times.now.as_str(),
            times.idle_cutoff.as_str(),
        ],
        |row| row.get::<_, bool>(0),
    )
}

fn active_admin_usernames_on_connection(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<Vec<String>> {
    let mut statement =
        connection.prepare("SELECT username FROM admins WHERE active=1 ORDER BY id ASC")?;
    let usernames = statement
        .query_map([], |row| {
            row.get::<_, String>(0)
                .map(|username| username.to_ascii_lowercase())
        })?
        .collect();
    usernames
}

include!("auth/common.rs");
include!("auth/admins.rs");
include!("auth/mfa.rs");
include!("auth/webauthn.rs");
include!("auth/sessions.rs");
