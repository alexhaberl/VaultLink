use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
}
pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .and_then(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .ok()
        })
        .is_some()
}
pub fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}
pub fn new_totp_secret() -> String {
    let mut b = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut b);
    BASE32_NOPAD.encode(&b)
}
pub fn verify_totp(secret: &str, code: &str, now: u64) -> bool {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let wanted = code.as_bytes();
    (-1i64..=1).any(|offset| {
        let step = (now / 30) as i64 + offset;
        if step < 0 {
            return false;
        }
        totp_code(secret, step as u64)
            .is_some_and(|candidate| candidate.as_bytes().ct_eq(wanted).into())
    })
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
pub fn verify_totp_now(secret: &str, code: &str) -> bool {
    verify_totp(
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
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max: usize,
    window: Duration,
}
impl LoginLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            inner: Default::default(),
            max,
            window,
        }
    }
    pub fn allowed(&self, key: &str) -> bool {
        let mut m = self.inner.lock().unwrap();
        let now = Instant::now();
        if !m.contains_key(key) && m.len() >= 10_000 {
            return false;
        }
        let e = m.entry(key.to_string()).or_default();
        e.retain(|t| now.duration_since(*t) < self.window);
        e.len() < self.max
    }
    pub fn failure(&self, key: &str) {
        let mut m = self.inner.lock().unwrap();
        if !m.contains_key(key) && m.len() >= 10_000 {
            return;
        }
        m.entry(key.to_string()).or_default().push(Instant::now());
    }
    pub fn success(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password(&h, "correct horse battery staple"));
        assert!(!verify_password(&h, "wrong"));
    }
    #[test]
    fn rfc_totp() {
        assert!(verify_totp(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "287082",
            59
        ));
    }
    #[test]
    fn limiter_blocks() {
        let l = LoginLimiter::new(2, Duration::from_secs(60));
        l.failure("x");
        l.failure("x");
        assert!(!l.allowed("x"));
        l.success("x");
        assert!(l.allowed("x"));
    }
}
