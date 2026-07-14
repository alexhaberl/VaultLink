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

    fn service() -> WebAuthnService {
        WebAuthnService::from_public_base_url("https://vaultlink.example.test").unwrap()
    }

    fn invalid_registration_response() -> RegisterPublicKeyCredential {
        serde_json::from_str(
            r#"{
                "id":"invalid",
                "rawId":"",
                "response":{"attestationObject":"","clientDataJSON":""},
                "type":"public-key",
                "clientExtensionResults":{}
            }"#,
        )
        .unwrap()
    }

    fn test_security_key() -> SecurityKey {
        // A structurally valid public credential is enough to make the production
        // engine create an authentication ceremony. The matching private key is
        // deliberately not present in this server-side state test.
        serde_json::from_str(
            r#"{
                "cred": {
                    "cred_id":"AQ",
                    "cred": {
                        "type_":"ES256",
                        "key":{"EC_EC2":{
                            "curve":"SECP256R1",
                            "x":[194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],
                            "y":[143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]
                        }}
                    },
                    "counter":0,
                    "transports":null,
                    "user_verified":false,
                    "backup_eligible":false,
                    "backup_state":false,
                    "registration_policy":"preferred",
                    "extensions":{"cred_protect":"NotRequested","hmac_create_secret":"NotRequested"},
                    "attestation":{"data":"None","metadata":"None"},
                    "attestation_format":"none"
                }
            }"#,
        )
        .unwrap()
    }

    fn invalid_authentication_response() -> PublicKeyCredential {
        serde_json::from_str(
            r#"{
                "id":"AQ",
                "rawId":"AQ",
                "response":{
                    "authenticatorData":"",
                    "clientDataJSON":"",
                    "signature":"",
                    "userHandle":null
                },
                "type":"public-key",
                "clientExtensionResults":{}
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn session_key_keeps_lowercase_sha256_encoding() {
        assert_eq!(
            session_key("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn registration_start_replaces_a_challenge_for_the_same_session() {
        let service = service();
        let first = service
            .start_registration("session", 7, "admin", &[])
            .unwrap();
        let second = service
            .start_registration("session", 7, "admin", &[])
            .unwrap();

        assert_ne!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
        assert_eq!(service.inner.registrations.lock().unwrap().len(), 1);
    }

    #[test]
    fn registration_state_is_bound_to_session_and_admin_and_single_use() {
        let service = service();
        let invalid = invalid_registration_response();
        service
            .start_registration("correct-session", 7, "admin", &[])
            .unwrap();

        let wrong_session = service
            .finish_registration("other-session", 7, &invalid)
            .unwrap_err();
        assert!(wrong_session.contains("missing or already used"));
        assert_eq!(service.inner.registrations.lock().unwrap().len(), 1);

        let wrong_admin = service
            .finish_registration("correct-session", 8, &invalid)
            .unwrap_err();
        assert!(wrong_admin.contains("belongs to another account"));
        let replay = service
            .finish_registration("correct-session", 7, &invalid)
            .unwrap_err();
        assert!(replay.contains("missing or already used"));
    }

    #[test]
    fn expired_registration_and_invalid_finish_both_consume_state() {
        let service = service();
        let invalid = invalid_registration_response();

        service
            .start_registration("expired", 7, "admin", &[])
            .unwrap();
        service
            .inner
            .registrations
            .lock()
            .unwrap()
            .get_mut(&session_key("expired"))
            .unwrap()
            .created = Instant::now() - CEREMONY_TTL - Duration::from_secs(1);
        assert!(service
            .finish_registration("expired", 7, &invalid)
            .unwrap_err()
            .contains("expired"));
        assert!(service
            .finish_registration("expired", 7, &invalid)
            .unwrap_err()
            .contains("missing or already used"));

        service
            .start_registration("invalid-finish", 7, "admin", &[])
            .unwrap();
        assert!(service
            .finish_registration("invalid-finish", 7, &invalid)
            .is_err());
        assert!(service
            .finish_registration("invalid-finish", 7, &invalid)
            .unwrap_err()
            .contains("missing or already used"));
    }

    #[test]
    fn authentication_state_is_replaced_bound_and_consumed_on_invalid_finish() {
        let service = service();
        let key = test_security_key();
        let invalid = invalid_authentication_response();
        let first = service
            .start_authentication("session", 7, std::slice::from_ref(&key))
            .unwrap();
        let second = service
            .start_authentication("session", 7, std::slice::from_ref(&key))
            .unwrap();
        assert_ne!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
        assert_eq!(service.inner.authentications.lock().unwrap().len(), 1);

        let mut credentials = vec![key];
        assert!(service
            .finish_authentication("wrong-session", 7, &invalid, &mut credentials)
            .unwrap_err()
            .contains("missing or already used"));
        assert_eq!(service.inner.authentications.lock().unwrap().len(), 1);

        assert!(service
            .finish_authentication("session", 8, &invalid, &mut credentials)
            .unwrap_err()
            .contains("belongs to another account"));
        assert!(service
            .finish_authentication("session", 7, &invalid, &mut credentials)
            .unwrap_err()
            .contains("missing or already used"));

        service
            .start_authentication("invalid-finish", 7, &credentials)
            .unwrap();
        assert!(service
            .finish_authentication("invalid-finish", 7, &invalid, &mut credentials)
            .is_err());
        assert!(service
            .finish_authentication("invalid-finish", 7, &invalid, &mut credentials)
            .unwrap_err()
            .contains("missing or already used"));
    }

    #[test]
    fn expired_authentication_is_single_use() {
        let service = service();
        let key = test_security_key();
        let invalid = invalid_authentication_response();
        service
            .start_authentication("expired", 7, std::slice::from_ref(&key))
            .unwrap();
        service
            .inner
            .authentications
            .lock()
            .unwrap()
            .get_mut(&session_key("expired"))
            .unwrap()
            .created = Instant::now() - CEREMONY_TTL - Duration::from_secs(1);
        let mut credentials = vec![key];
        assert!(service
            .finish_authentication("expired", 7, &invalid, &mut credentials)
            .unwrap_err()
            .contains("expired"));
        assert!(service
            .finish_authentication("expired", 7, &invalid, &mut credentials)
            .unwrap_err()
            .contains("missing or already used"));
    }
}
