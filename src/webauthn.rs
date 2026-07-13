use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use webauthn_rs::{
    prelude::{
        CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse, SecurityKey, SecurityKeyAuthentication, SecurityKeyRegistration,
        Uuid,
    },
    Webauthn, WebauthnBuilder,
};

const CEREMONY_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PENDING_CEREMONIES: usize = 1024;

fn session_key(session_token: &str) -> String {
    let digest = Sha256::digest(session_token.as_bytes());
    data_encoding::HEXLOWER.encode(digest.as_ref())
}

fn make_room<T>(pending: &mut HashMap<String, T>) {
    if pending.len() >= MAX_PENDING_CEREMONIES {
        if let Some(key) = pending.keys().next().cloned() {
            pending.remove(&key);
        }
    }
}

struct PendingRegistration {
    admin_id: i64,
    created: Instant,
    state: SecurityKeyRegistration,
}

struct PendingAuthentication {
    admin_id: i64,
    created: Instant,
    state: SecurityKeyAuthentication,
}

#[derive(Clone)]
pub struct WebAuthnService {
    inner: Arc<WebAuthnInner>,
}

struct WebAuthnInner {
    engine: Webauthn,
    registrations: Mutex<HashMap<String, PendingRegistration>>,
    authentications: Mutex<HashMap<String, PendingAuthentication>>,
}

impl WebAuthnService {
    pub fn from_public_base_url(public_base_url: &str) -> Result<Self, String> {
        let origin = url::Url::parse(public_base_url).map_err(|error| error.to_string())?;
        let rp_id = origin
            .host_str()
            .ok_or_else(|| "WebAuthn origin must contain a host".to_string())?;
        let engine = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|error| error.to_string())?
            .rp_name("VaultLink")
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            inner: Arc::new(WebAuthnInner {
                engine,
                registrations: Mutex::new(HashMap::new()),
                authentications: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[cfg(test)]
    pub fn instance_id(&self) -> usize {
        Arc::as_ptr(&self.inner) as usize
    }

    pub fn start_registration(
        &self,
        session_token: &str,
        admin_id: i64,
        username: &str,
        existing: &[SecurityKey],
    ) -> Result<CreationChallengeResponse, String> {
        let excluded = existing.iter().map(|key| key.cred_id().clone()).collect();
        let (challenge, state) = self
            .inner
            .engine
            .start_securitykey_registration(
                Uuid::new_v4(),
                username,
                username,
                Some(excluded),
                None,
                None,
            )
            .map_err(|error| error.to_string())?;
        let mut pending = self
            .inner
            .registrations
            .lock()
            .map_err(|_| "lock poisoned")?;
        pending.retain(|_, value| value.created.elapsed() < CEREMONY_TTL);
        make_room(&mut pending);
        pending.insert(
            session_key(session_token),
            PendingRegistration {
                admin_id,
                created: Instant::now(),
                state,
            },
        );
        Ok(challenge)
    }

    pub fn finish_registration(
        &self,
        session_token: &str,
        admin_id: i64,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<SecurityKey, String> {
        let pending = self
            .inner
            .registrations
            .lock()
            .map_err(|_| "lock poisoned")?
            .remove(&session_key(session_token))
            .ok_or_else(|| "registration challenge missing or already used".to_string())?;
        if pending.admin_id != admin_id || pending.created.elapsed() >= CEREMONY_TTL {
            return Err("registration challenge expired or belongs to another account".into());
        }
        self.inner
            .engine
            .finish_securitykey_registration(credential, &pending.state)
            .map_err(|error| error.to_string())
    }

    pub fn start_authentication(
        &self,
        session_token: &str,
        admin_id: i64,
        credentials: &[SecurityKey],
    ) -> Result<RequestChallengeResponse, String> {
        let (challenge, state) = self
            .inner
            .engine
            .start_securitykey_authentication(credentials)
            .map_err(|error| error.to_string())?;
        let mut pending = self
            .inner
            .authentications
            .lock()
            .map_err(|_| "lock poisoned")?;
        pending.retain(|_, value| value.created.elapsed() < CEREMONY_TTL);
        make_room(&mut pending);
        pending.insert(
            session_key(session_token),
            PendingAuthentication {
                admin_id,
                created: Instant::now(),
                state,
            },
        );
        Ok(challenge)
    }

    pub fn finish_authentication(
        &self,
        session_token: &str,
        admin_id: i64,
        credential: &PublicKeyCredential,
        credentials: &mut [SecurityKey],
    ) -> Result<usize, String> {
        let pending = self
            .inner
            .authentications
            .lock()
            .map_err(|_| "lock poisoned")?
            .remove(&session_key(session_token))
            .ok_or_else(|| "authentication challenge missing or already used".to_string())?;
        if pending.admin_id != admin_id || pending.created.elapsed() >= CEREMONY_TTL {
            return Err("authentication challenge expired or belongs to another account".into());
        }
        let result = self
            .inner
            .engine
            .finish_securitykey_authentication(credential, &pending.state)
            .map_err(|error| error.to_string())?;
        credentials
            .iter_mut()
            .position(|key| key.update_credential(&result).is_some())
            .ok_or_else(|| "authenticated credential is not registered".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_keeps_lowercase_sha256_encoding() {
        assert_eq!(
            session_key("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }
}
