use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::{rngs::SysRng, TryRng};
use sha1::Sha1;
use std::{
    collections::{hash_map::RandomState, HashMap},
    hash::BuildHasher,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

use crate::sensitive::SecretString;

const MAX_LIMITER_KEYS: usize = 10_000;
const OVERFLOW_BUCKETS: usize = 256;
const GLOBAL_CLEANUP_INTERVAL: u64 = 64;

pub const ADMIN_PASSWORD_MIN_CHARACTERS: usize = 14;
pub const ADMIN_PASSWORD_MAX_CHARACTERS: usize = 256;
pub const MAX_PASSWORD_BYTES: usize = 1_024;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

fn password_argon2() -> Argon2<'static> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("VaultLink Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Compares authentication tokens without leaking the first differing byte.
///
/// Token length is not secret, so differently sized values can be rejected
/// before invoking the constant-time primitive.
pub fn constant_time_eq(expected: &str, supplied: &str) -> bool {
    expected.len() == supplied.len() && bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn fill_random(bytes: &mut [u8]) {
    SysRng
        .try_fill_bytes(bytes)
        .expect("operating system CSPRNG unavailable");
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes);
    password_argon2()
        .hash_password_with_salt(password.as_bytes(), &salt_bytes)
        .map(|h| h.to_string())
}

/// Hashes an owned password on a worker thread without requiring the caller to
/// retain a second application-owned plaintext allocation.
pub(crate) fn hash_secret_password(
    password: &SecretString,
) -> Result<String, argon2::password_hash::Error> {
    hash_password(password.expose_secret())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    PasswordHash::new(hash)
        .ok()
        .and_then(|h| {
            password_argon2()
                .verify_password(password.as_bytes(), &h)
                .ok()
        })
        .is_some()
}

/// Verifies owned task inputs and zeroes the plaintext password when the task
/// finishes. Password hashes are not treated as secrets.
pub(crate) fn verify_secret_password(hash: &str, password: &SecretString) -> bool {
    verify_password(hash, password.expose_secret())
}

pub fn valid_admin_username(username: &str) -> bool {
    (3..=64).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn failed_login_identity(username: &str) -> (String, Option<String>) {
    if valid_admin_username(username) {
        (username.to_owned(), None)
    } else {
        use sha2::{Digest, Sha256};
        (
            "<invalid-username>".into(),
            Some(format!(
                "reason=invalid_username;username_bytes={};username_sha256={}",
                username.len(),
                data_encoding::HEXLOWER.encode(&Sha256::digest(username.as_bytes()))
            )),
        )
    }
}

pub fn valid_admin_password(password: &str) -> bool {
    (ADMIN_PASSWORD_MIN_CHARACTERS..=ADMIN_PASSWORD_MAX_CHARACTERS)
        .contains(&password.chars().count())
        && password.len() <= MAX_PASSWORD_BYTES
}

pub fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    fill_random(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}
pub fn new_totp_secret() -> String {
    let mut b = [0u8; 20];
    fill_random(&mut b);
    BASE32_NOPAD.encode(&b)
}

pub(crate) fn new_totp_secret_value() -> SecretString {
    SecretString::from(new_totp_secret())
}
pub fn matching_totp_step(secret: &str, code: &str, now: u64) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted = code.as_bytes();
    let current_step = now / 30;
    [
        current_step.checked_add(1),
        Some(current_step),
        current_step.checked_sub(1),
    ]
    .into_iter()
    .flatten()
    .find(|step| {
        totp_code(secret, *step)
            .map(SecretString::from)
            .is_some_and(|candidate| candidate.expose_secret().as_bytes().ct_eq(wanted).into())
    })
}

pub fn verify_totp(secret: &str, code: &str, now: u64) -> bool {
    matching_totp_step(secret, code, now).is_some()
}

pub(crate) fn totp_code(secret: &str, step: u64) -> Option<String> {
    let key = BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())
        .ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = (out[19] & 15) as usize;
    let number = ((u32::from(out[offset]) & 0x7f) << 24)
        | u32::from(out[offset + 1]) << 16
        | u32::from(out[offset + 2]) << 8
        | u32::from(out[offset + 3]);
    Some(format!("{:06}", number % 1_000_000))
}
pub fn matching_totp_step_now(secret: &str, code: &str) -> Option<u64> {
    matching_totp_step(
        secret,
        code,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

#[derive(Clone)]
pub struct LoginLimiter {
    inner: Arc<Mutex<LimiterState>>,
    max: usize,
    window: Duration,
    capacity: usize,
    overflow_buckets: usize,
}

struct LimiterState {
    entries: HashMap<String, AttemptHistory>,
    overflow: Vec<Option<AttemptHistory>>,
    hash_builder: RandomState,
    operations: u64,
}

#[derive(Clone)]
struct AttemptHistory {
    attempts: Vec<Instant>,
}

/// Password-login budgets depend only on request history, never account existence.
#[derive(Clone)]
pub struct AdminLoginLimiter {
    origins: LoginLimiter,
    accounts: LoginLimiter,
}

impl AdminLoginLimiter {
    pub fn new(origin_max: usize, account_max: usize, window: Duration) -> Self {
        Self {
            origins: LoginLimiter::new(origin_max, window),
            accounts: LoginLimiter::new(account_max, window),
        }
    }

    /// Always charge the origin first, even when the account budget is exhausted.
    /// Password success and account activation never erase either history.
    pub fn check_and_record_attempt(&self, username: &str, origin: IpAddr) -> bool {
        self.origins.check_and_record_attempt(&origin.to_string())
            && (!valid_admin_username(username)
                || self
                    .accounts
                    .check_and_record_attempt(&username.to_ascii_lowercase()))
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> Vec<(String, Vec<Instant>)> {
        let mut snapshot = Vec::new();
        for (prefix, limiter) in [("ip", &self.origins), ("account", &self.accounts)] {
            let state = limiter.state();
            snapshot.extend(
                state
                    .entries
                    .iter()
                    .map(|(key, history)| (format!("{prefix}:{key}"), history.attempts.clone())),
            );
            snapshot.extend(
                state
                    .overflow
                    .iter()
                    .enumerate()
                    .filter_map(|(index, history)| {
                        history.as_ref().map(|history| {
                            (
                                format!("{prefix}:overflow:{index}"),
                                history.attempts.clone(),
                            )
                        })
                    }),
            );
        }
        snapshot.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }
}

impl LimiterState {
    fn new(overflow_buckets: usize) -> Self {
        Self {
            entries: HashMap::new(),
            overflow: std::iter::repeat_with(|| None)
                .take(overflow_buckets.max(1))
                .collect(),
            hash_builder: RandomState::new(),
            operations: 0,
        }
    }
}

impl LoginLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self::with_capacity_and_overflow(max, window, MAX_LIMITER_KEYS, OVERFLOW_BUCKETS)
    }

    fn with_capacity_and_overflow(
        max: usize,
        window: Duration,
        capacity: usize,
        overflow_buckets: usize,
    ) -> Self {
        let overflow_buckets = overflow_buckets.max(1);
        Self {
            inner: Arc::new(Mutex::new(LimiterState::new(overflow_buckets))),
            max,
            window,
            capacity: capacity.max(1),
            overflow_buckets,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LimiterState> {
        match self.inner.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                tracing::error!("recovering poisoned login limiter state");
                let mut state = poisoned.into_inner();
                let now = Instant::now();

                if state.overflow.len() != self.overflow_buckets
                    || state.entries.len() > self.capacity
                {
                    // A structurally damaged limiter must remain bounded and
                    // fail closed until the current window expires. Saturating
                    // every overflow bucket avoids accidentally granting a new
                    // key after discarding an untrustworthy primary map.
                    state.entries.clear();
                    state.overflow = (0..self.overflow_buckets)
                        .map(|_| {
                            Some(AttemptHistory {
                                attempts: vec![now; self.max],
                            })
                        })
                        .collect();
                } else {
                    self.cleanup_expired(&mut state, now);
                    for history in state.entries.values_mut() {
                        if history.attempts.len() > self.max {
                            let excess = history.attempts.len() - self.max;
                            history.attempts.drain(..excess);
                        }
                    }
                    for history in state.overflow.iter_mut().filter_map(Option::as_mut) {
                        if history.attempts.len() > self.max {
                            let excess = history.attempts.len() - self.max;
                            history.attempts.drain(..excess);
                        }
                    }
                }
                self.inner.clear_poison();
                state
            }
        }
    }

    /// Atomically checks the limit and records the admitted attempt.
    ///
    /// Attempts remain recorded until the configured window expires. Callers may
    /// invoke [`Self::success`] only for cheap, replay-protected follow-up factors;
    /// successful password checks deliberately stay in the budget so valid
    /// credentials cannot be abused for unbounded Argon2 work or session creation.
    /// This check-and-record operation must happen before expensive credential
    /// verification so concurrent requests cannot all pass an unconsumed check.
    pub fn check_and_record_attempt(&self, key: &str) -> bool {
        self.check_and_record_attempts(&[key])
    }

    /// Atomically admits and records an attempt against every supplied key.
    ///
    /// This is intended for checks that combine identities such as a username
    /// and client IP. Either every key is consumed or none is, preventing both
    /// partial reservations and races between the individual limits.
    pub fn check_and_record_attempts(&self, keys: &[&str]) -> bool {
        if self.max == 0 || self.window.is_zero() {
            return false;
        }
        if keys.is_empty() {
            return true;
        }

        let unique_keys = keys
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, key)| (!keys[..index].contains(&key)).then_some(key))
            .collect::<Vec<_>>();

        let mut state = self.state();
        let now = Instant::now();
        self.periodic_cleanup(&mut state, now);

        for key in &unique_keys {
            if let Some(history) = state.entries.get_mut(*key) {
                Self::prune_history(history, now, self.window);
            }
        }
        for key in &unique_keys {
            if state
                .entries
                .get(*key)
                .is_some_and(|history| history.attempts.is_empty())
            {
                state.entries.remove(*key);
            }
        }

        let mut primary_targets = Vec::with_capacity(unique_keys.len());
        let mut overflow_targets = Vec::new();
        let mut primary_slots = self.capacity.saturating_sub(state.entries.len());
        for key in unique_keys {
            if state.entries.contains_key(key) {
                primary_targets.push(key);
                continue;
            }

            let bucket = Self::overflow_bucket(&state, key);
            let expired = state.overflow[bucket].as_mut().is_some_and(|history| {
                Self::prune_history(history, now, self.window);
                history.attempts.is_empty()
            });
            if expired {
                state.overflow[bucket] = None;
            }

            if state.overflow[bucket].is_some() || primary_slots == 0 {
                if !overflow_targets.contains(&bucket) {
                    overflow_targets.push(bucket);
                }
            } else {
                primary_targets.push(key);
                primary_slots -= 1;
            }
        }

        if primary_targets.iter().any(|key| {
            state
                .entries
                .get(*key)
                .is_some_and(|history| history.attempts.len() >= self.max)
        }) {
            return false;
        }
        if overflow_targets.iter().any(|bucket| {
            state.overflow[*bucket]
                .as_ref()
                .is_some_and(|history| history.attempts.len() >= self.max)
        }) {
            return false;
        }

        for key in primary_targets {
            let history = state
                .entries
                .entry(key.to_owned())
                .or_insert_with(|| AttemptHistory {
                    attempts: Vec::new(),
                });
            history.attempts.push(now);
        }
        for bucket in overflow_targets {
            state.overflow[bucket]
                .get_or_insert_with(|| AttemptHistory {
                    attempts: Vec::new(),
                })
                .attempts
                .push(now);
        }
        true
    }

    /// Clears an exact primary history after successful authentication.
    ///
    /// Overflow buckets aggregate multiple unknown keys and deliberately are
    /// not cleared here: a success for one key must not erase other keys'
    /// protection. Their attempts expire only with the configured window.
    pub fn success(&self, key: &str) {
        self.state().entries.remove(key);
    }

    fn periodic_cleanup(&self, state: &mut LimiterState, now: Instant) {
        state.operations = state.operations.wrapping_add(1);
        if state.operations.is_multiple_of(GLOBAL_CLEANUP_INTERVAL) {
            self.cleanup_expired(state, now);
        }
    }

    fn cleanup_expired(&self, state: &mut LimiterState, now: Instant) {
        state.entries.retain(|_, history| {
            Self::prune_history(history, now, self.window);
            !history.attempts.is_empty()
        });
        for bucket in &mut state.overflow {
            let expired = bucket.as_mut().is_some_and(|history| {
                Self::prune_history(history, now, self.window);
                history.attempts.is_empty()
            });
            if expired {
                *bucket = None;
            }
        }
    }

    fn prune_history(history: &mut AttemptHistory, now: Instant, window: Duration) {
        history
            .attempts
            .retain(|attempt| now.duration_since(*attempt) < window);
    }

    fn overflow_bucket(state: &LimiterState, key: &str) -> usize {
        (state.hash_builder.hash_one(key) as usize) % state.overflow.len()
    }
}

#[cfg(test)]
include!("auth/tests.rs");
