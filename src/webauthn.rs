use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use webauthn_rp::{
    bin::{Decode, Encode},
    request::{
        auth::{
            AllowedCredentials, AuthenticationVerificationOptions,
            NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
        },
        register::{
            CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers, PublicKeyCredentialCreationOptions,
            PublicKeyCredentialUserEntity, RegistrationServerState,
            RegistrationVerificationOptions, UserHandle64, USER_HANDLE_MAX_LEN,
        },
        AsciiDomain, Credentials, PublicKeyCredentialDescriptor, RpId,
    },
    response::{
        register::{bin::MetadataOwned, CompressedPubKey, DynamicState, StaticState},
        AuthTransports, CredentialId,
    },
    AuthenticatedCredential, NonDiscoverableAuthentication64, RegisteredCredential, Registration,
};

const CEREMONY_TTL: Duration = Duration::from_secs(10 * 60);
const CEREMONY_TIMEOUT_MS: u32 = 10 * 60 * 1_000;
const MAX_PENDING_CEREMONIES: usize = 1024;
const CREDENTIAL_BLOB_VERSION: u8 = 1;

type OwnedPublicKey = CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>;
type OwnedStaticState = StaticState<OwnedPublicKey>;

fn ensure_supported_static_state(state: &OwnedStaticState) -> Result<(), WebAuthnServiceError> {
    if matches!(state.credential_public_key, CompressedPubKey::Rsa(_)) {
        return Err(WebAuthnServiceError::Ceremony(
            "RS256 WebAuthn credentials are not supported".into(),
        ));
    }
    Ok(())
}

fn decode_supported_static_state(data: &[u8]) -> Result<OwnedStaticState, WebAuthnServiceError> {
    let state = OwnedStaticState::decode(data).map_err(WebAuthnServiceError::ceremony)?;
    ensure_supported_static_state(&state)?;
    Ok(state)
}

fn session_key(session_token: &str) -> String {
    let digest = Sha256::digest(session_token.as_bytes());
    data_encoding::HEXLOWER.encode(digest.as_ref())
}

fn user_handle(admin_id: i64) -> Result<UserHandle64, WebAuthnServiceError> {
    let digest = Sha512::digest(format!("vaultlink-webauthn-user:{admin_id}").as_bytes());
    let mut bytes = [0u8; USER_HANDLE_MAX_LEN];
    bytes.copy_from_slice(&digest);
    UserHandle64::decode(bytes).map_err(WebAuthnServiceError::ceremony)
}

fn ensure_pending_capacity<T>(
    pending: &HashMap<String, T>,
    key: &str,
) -> Result<(), WebAuthnServiceError> {
    if !pending.contains_key(key) && pending.len() >= MAX_PENDING_CEREMONIES {
        return Err(WebAuthnServiceError::CapacityExceeded);
    }
    Ok(())
}

fn ceremony_map<'a, T>(
    lock: &'a Mutex<HashMap<String, T>>,
    name: &'static str,
) -> std::sync::MutexGuard<'a, HashMap<String, T>> {
    match lock.lock() {
        Ok(pending) => pending,
        Err(poisoned) => {
            tracing::error!(lock = name, "discarding poisoned WebAuthn ceremonies");
            let mut pending = poisoned.into_inner();
            pending.clear();
            lock.clear_poison();
            pending
        }
    }
}

#[derive(Debug, Error)]
pub enum WebAuthnServiceError {
    #[error("pending WebAuthn ceremony capacity exhausted")]
    CapacityExceeded,
    #[error("{0}")]
    Ceremony(String),
}

impl WebAuthnServiceError {
    fn ceremony(error: impl ToString) -> Self {
        let message = error.to_string();
        drop(error);
        Self::Ceremony(message)
    }
}

#[derive(Clone, Debug)]
pub struct StoredCredential {
    id: Vec<u8>,
    transports: u8,
    user_id: [u8; USER_HANDLE_MAX_LEN],
    static_state: Vec<u8>,
    dynamic_state: [u8; 7],
    metadata: Vec<u8>,
}

impl StoredCredential {
    pub fn from_blob(blob: &[u8]) -> Result<Self, WebAuthnServiceError> {
        let mut input = blob;
        if take_u8(&mut input)? != CREDENTIAL_BLOB_VERSION {
            return Err(WebAuthnServiceError::Ceremony(
                "unsupported WebAuthn credential blob version".into(),
            ));
        }
        let id = take_vec(&mut input)?;
        CredentialId::<&[u8]>::decode(id.as_slice()).map_err(WebAuthnServiceError::ceremony)?;
        let transports = take_u8(&mut input)?;
        AuthTransports::decode(transports).map_err(WebAuthnServiceError::ceremony)?;
        let user_id = take_array::<USER_HANDLE_MAX_LEN>(&mut input)?;
        UserHandle64::decode(user_id).map_err(WebAuthnServiceError::ceremony)?;
        let static_state = take_vec(&mut input)?;
        decode_supported_static_state(static_state.as_slice())?;
        let dynamic_state = take_array::<7>(&mut input)?;
        DynamicState::decode(dynamic_state).map_err(WebAuthnServiceError::ceremony)?;
        let metadata = take_vec(&mut input)?;
        MetadataOwned::decode(metadata.as_slice()).map_err(WebAuthnServiceError::ceremony)?;
        if !input.is_empty() {
            return Err(WebAuthnServiceError::Ceremony(
                "trailing data in WebAuthn credential blob".into(),
            ));
        }
        Ok(Self {
            id,
            transports,
            user_id,
            static_state,
            dynamic_state,
            metadata,
        })
    }

    fn from_registered(
        credential: RegisteredCredential<'_, USER_HANDLE_MAX_LEN>,
    ) -> Result<Self, WebAuthnServiceError> {
        let (id, transports, user_id, static_state, dynamic_state, metadata) =
            credential.into_parts();
        let static_state = static_state
            .encode()
            .map_err(WebAuthnServiceError::ceremony)?;
        decode_supported_static_state(&static_state)?;
        Ok(Self {
            id: id.as_ref().to_vec(),
            transports: transports
                .encode()
                .map_err(WebAuthnServiceError::ceremony)?,
            user_id: user_id.encode().map_err(WebAuthnServiceError::ceremony)?,
            static_state,
            dynamic_state: dynamic_state
                .encode()
                .map_err(WebAuthnServiceError::ceremony)?,
            metadata: metadata.encode().map_err(WebAuthnServiceError::ceremony)?,
        })
    }

    pub fn to_blob(&self) -> Result<Vec<u8>, WebAuthnServiceError> {
        let mut output = Vec::with_capacity(
            1 + 4
                + self.id.len()
                + 1
                + USER_HANDLE_MAX_LEN
                + 4
                + self.static_state.len()
                + 7
                + 4
                + self.metadata.len(),
        );
        output.push(CREDENTIAL_BLOB_VERSION);
        push_vec(&mut output, &self.id)?;
        output.push(self.transports);
        output.extend_from_slice(&self.user_id);
        push_vec(&mut output, &self.static_state)?;
        output.extend_from_slice(&self.dynamic_state);
        push_vec(&mut output, &self.metadata)?;
        Ok(output)
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.id
    }

    fn descriptor(&self) -> Result<PublicKeyCredentialDescriptor<Vec<u8>>, WebAuthnServiceError> {
        Ok(PublicKeyCredentialDescriptor {
            id: CredentialId::<Vec<u8>>::decode(self.id.clone())
                .map_err(WebAuthnServiceError::ceremony)?,
            transports: AuthTransports::decode(self.transports)
                .map_err(WebAuthnServiceError::ceremony)?,
        })
    }

    fn ensure_supported(&self) -> Result<(), WebAuthnServiceError> {
        decode_supported_static_state(&self.static_state).map(drop)
    }
}

fn push_vec(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WebAuthnServiceError> {
    let length = u32::try_from(value.len())
        .map_err(|_| WebAuthnServiceError::Ceremony("credential component too large".into()))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_u8(input: &mut &[u8]) -> Result<u8, WebAuthnServiceError> {
    let Some((value, rest)) = input.split_first() else {
        return Err(WebAuthnServiceError::Ceremony(
            "truncated WebAuthn credential blob".into(),
        ));
    };
    *input = rest;
    Ok(*value)
}

fn take_vec(input: &mut &[u8]) -> Result<Vec<u8>, WebAuthnServiceError> {
    let length = u32::from_le_bytes(take_array::<4>(input)?) as usize;
    let Some((value, rest)) = input.split_at_checked(length) else {
        return Err(WebAuthnServiceError::Ceremony(
            "truncated WebAuthn credential component".into(),
        ));
    };
    *input = rest;
    Ok(value.to_vec())
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], WebAuthnServiceError> {
    let Some((value, rest)) = input.split_at_checked(N) else {
        return Err(WebAuthnServiceError::Ceremony(
            "truncated WebAuthn credential component".into(),
        ));
    };
    *input = rest;
    value.try_into().map_err(WebAuthnServiceError::ceremony)
}

struct PendingRegistration {
    admin_id: i64,
    created: Instant,
    state: RegistrationServerState<USER_HANDLE_MAX_LEN>,
}

struct PendingAuthentication {
    admin_id: i64,
    created: Instant,
    state: NonDiscoverableAuthenticationServerState,
}

#[derive(Clone)]
pub struct WebAuthnService {
    inner: Arc<WebAuthnInner>,
}

struct WebAuthnInner {
    rp_id: RpId,
    origin: String,
    registrations: Mutex<HashMap<String, PendingRegistration>>,
    authentications: Mutex<HashMap<String, PendingAuthentication>>,
}

impl WebAuthnService {
    pub fn from_public_base_url(public_base_url: &str) -> Result<Self, WebAuthnServiceError> {
        let origin = url::Url::parse(public_base_url).map_err(WebAuthnServiceError::ceremony)?;
        let host = origin.host_str().ok_or_else(|| {
            WebAuthnServiceError::Ceremony("WebAuthn origin must contain a host".into())
        })?;
        let rp_id = RpId::Domain(
            AsciiDomain::try_from(host.to_owned()).map_err(WebAuthnServiceError::ceremony)?,
        );
        Ok(Self {
            inner: Arc::new(WebAuthnInner {
                rp_id,
                origin: origin.origin().ascii_serialization(),
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
        existing: &[StoredCredential],
    ) -> Result<serde_json::Value, WebAuthnServiceError> {
        let user_id = user_handle(admin_id)?;
        let user = PublicKeyCredentialUserEntity {
            name: username
                .try_into()
                .map_err(WebAuthnServiceError::ceremony)?,
            id: &user_id,
            display_name: Some(
                username
                    .try_into()
                    .map_err(WebAuthnServiceError::ceremony)?,
            ),
        };
        let excluded = existing
            .iter()
            .map(StoredCredential::descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        let mut options =
            PublicKeyCredentialCreationOptions::second_factor(&self.inner.rp_id, user, excluded);
        // rsa 0.9 has no fixed release for RUSTSEC-2023-0071. webauthn_rp
        // depends on it unconditionally, so make its verification path
        // unreachable: fresh-schema installations never accept or advertise
        // RS256 credentials.
        options.pub_key_cred_params =
            CoseAlgorithmIdentifiers::default().remove(CoseAlgorithmIdentifier::Rs256);
        options.timeout = NonZeroU32::new(CEREMONY_TIMEOUT_MS)
            .ok_or_else(|| WebAuthnServiceError::Ceremony("invalid WebAuthn timeout".into()))?;
        let (state, client) = options
            .start_ceremony()
            .map_err(WebAuthnServiceError::ceremony)?;
        let challenge = serde_json::json!({ "publicKey": client });
        let mut pending = ceremony_map(&self.inner.registrations, "WebAuthn registrations");
        pending.retain(|_, value| value.created.elapsed() < CEREMONY_TTL);
        let key = session_key(session_token);
        ensure_pending_capacity(&pending, &key)?;
        pending.insert(
            key,
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
        credential: &serde_json::Value,
    ) -> Result<StoredCredential, WebAuthnServiceError> {
        let pending = ceremony_map(&self.inner.registrations, "WebAuthn registrations")
            .remove(&session_key(session_token))
            .ok_or_else(|| {
                WebAuthnServiceError::Ceremony(
                    "registration challenge missing or already used".into(),
                )
            })?;
        if pending.admin_id != admin_id || pending.created.elapsed() >= CEREMONY_TTL {
            return Err(WebAuthnServiceError::Ceremony(
                "registration challenge expired or belongs to another account".into(),
            ));
        }
        let json = serde_json::to_vec(credential).map_err(WebAuthnServiceError::ceremony)?;
        let registration =
            Registration::from_json_custom(&json).map_err(WebAuthnServiceError::ceremony)?;
        let options = RegistrationVerificationOptions::<String, String> {
            allowed_origins: std::slice::from_ref(&self.inner.origin),
            ..Default::default()
        };
        let registered = pending
            .state
            .verify(&self.inner.rp_id, &registration, &options)
            .map_err(WebAuthnServiceError::ceremony)?;
        StoredCredential::from_registered(registered)
    }

    pub fn start_authentication(
        &self,
        session_token: &str,
        admin_id: i64,
        credentials: &[StoredCredential],
    ) -> Result<serde_json::Value, WebAuthnServiceError> {
        let mut allowed = AllowedCredentials::with_capacity(credentials.len());
        for credential in credentials {
            credential.ensure_supported()?;
            if !allowed.push(credential.descriptor()?.into()) {
                return Err(WebAuthnServiceError::Ceremony(
                    "duplicate WebAuthn credential ID".into(),
                ));
            }
        }
        let mut options =
            NonDiscoverableCredentialRequestOptions::second_factor(&self.inner.rp_id, allowed)
                .map_err(WebAuthnServiceError::ceremony)?;
        options.options().timeout = NonZeroU32::new(CEREMONY_TIMEOUT_MS)
            .ok_or_else(|| WebAuthnServiceError::Ceremony("invalid WebAuthn timeout".into()))?;
        let (state, client) = options
            .start_ceremony()
            .map_err(WebAuthnServiceError::ceremony)?;
        let challenge = serde_json::json!({ "publicKey": client });
        let mut pending = ceremony_map(&self.inner.authentications, "WebAuthn authentications");
        pending.retain(|_, value| value.created.elapsed() < CEREMONY_TTL);
        let key = session_key(session_token);
        ensure_pending_capacity(&pending, &key)?;
        pending.insert(
            key,
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
        credential: &serde_json::Value,
        credentials: &mut [StoredCredential],
    ) -> Result<usize, WebAuthnServiceError> {
        for stored in credentials.iter() {
            stored.ensure_supported()?;
        }
        let pending = ceremony_map(&self.inner.authentications, "WebAuthn authentications")
            .remove(&session_key(session_token))
            .ok_or_else(|| {
                WebAuthnServiceError::Ceremony(
                    "authentication challenge missing or already used".into(),
                )
            })?;
        if pending.admin_id != admin_id || pending.created.elapsed() >= CEREMONY_TTL {
            return Err(WebAuthnServiceError::Ceremony(
                "authentication challenge expired or belongs to another account".into(),
            ));
        }
        let json = serde_json::to_vec(credential).map_err(WebAuthnServiceError::ceremony)?;
        let authentication = NonDiscoverableAuthentication64::from_json_custom(&json)
            .map_err(WebAuthnServiceError::ceremony)?;
        let index = credentials
            .iter()
            .position(|stored| stored.id.as_slice() == authentication.raw_id().as_ref())
            .ok_or_else(|| {
                WebAuthnServiceError::Ceremony("authenticated credential is not registered".into())
            })?;
        let stored = &mut credentials[index];
        let credential_id = CredentialId::<&[u8]>::decode(stored.id.as_slice())
            .map_err(WebAuthnServiceError::ceremony)?;
        let user_id =
            UserHandle64::decode(stored.user_id).map_err(WebAuthnServiceError::ceremony)?;
        let static_state = decode_supported_static_state(stored.static_state.as_slice())?;
        let dynamic_state =
            DynamicState::decode(stored.dynamic_state).map_err(WebAuthnServiceError::ceremony)?;
        let mut authenticated =
            AuthenticatedCredential::new(credential_id, &user_id, static_state, dynamic_state)
                .map_err(WebAuthnServiceError::ceremony)?;
        let options = AuthenticationVerificationOptions::<String, String> {
            allowed_origins: std::slice::from_ref(&self.inner.origin),
            ..Default::default()
        };
        let changed = pending
            .state
            .verify(
                &self.inner.rp_id,
                &authentication,
                &mut authenticated,
                &options,
            )
            .map_err(WebAuthnServiceError::ceremony)?;
        if changed {
            stored.dynamic_state = authenticated
                .dynamic_state()
                .encode()
                .map_err(WebAuthnServiceError::ceremony)?;
        }
        Ok(index)
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

    #[test]
    fn capacity_rejects_only_new_sessions() {
        let pending = (0..MAX_PENDING_CEREMONIES)
            .map(|index| (format!("session-{index}"), ()))
            .collect::<HashMap<_, _>>();
        assert!(matches!(
            ensure_pending_capacity(&pending, "new-session"),
            Err(WebAuthnServiceError::CapacityExceeded)
        ));
        assert!(ensure_pending_capacity(&pending, "session-0").is_ok());
    }

    #[test]
    fn generated_user_handle_is_stable_and_account_bound() {
        assert_eq!(
            user_handle(7).unwrap().encode().unwrap(),
            user_handle(7).unwrap().encode().unwrap()
        );
        assert_ne!(
            user_handle(7).unwrap().encode().unwrap(),
            user_handle(8).unwrap().encode().unwrap()
        );
    }

    #[test]
    fn registration_never_advertises_the_unpatched_rs256_path() {
        let service = WebAuthnService::from_public_base_url("https://vault.example").unwrap();
        let options = service
            .start_registration("session", 1, "admin", &[])
            .unwrap();
        let algorithms = options["publicKey"]["pubKeyCredParams"]
            .as_array()
            .expect("registration options contain credential parameters");
        assert!(algorithms.iter().any(|parameter| parameter["alg"] == -7));
        assert!(algorithms.iter().all(|parameter| parameter["alg"] != -257));
    }

    #[test]
    fn authentication_rejects_persisted_rs256_credentials() {
        let mut encoded_static_state = vec![3, 0, 1];
        encoded_static_state.extend(std::iter::repeat_n(1, 256));
        encoded_static_state.extend_from_slice(&65_537u32.to_le_bytes());
        encoded_static_state.extend_from_slice(&[0, 0]);
        assert!(matches!(
            decode_supported_static_state(&encoded_static_state),
            Err(WebAuthnServiceError::Ceremony(message))
                if message == "RS256 WebAuthn credentials are not supported"
        ));

        let credential = StoredCredential {
            id: vec![],
            transports: 0,
            user_id: [0; USER_HANDLE_MAX_LEN],
            static_state: encoded_static_state.clone(),
            dynamic_state: [0; 7],
            metadata: vec![],
        };
        assert!(matches!(
            credential.ensure_supported(),
            Err(WebAuthnServiceError::Ceremony(message))
                if message == "RS256 WebAuthn credentials are not supported"
        ));
        let service = WebAuthnService::from_public_base_url("https://vault.example").unwrap();
        assert!(matches!(
            service.start_authentication("rsa-start", 1, std::slice::from_ref(&credential)),
            Err(WebAuthnServiceError::Ceremony(message))
                if message == "RS256 WebAuthn credentials are not supported"
        ));
        let mut credentials = [credential];
        assert!(matches!(
            service.finish_authentication(
                "rsa-finish",
                1,
                &serde_json::json!({}),
                &mut credentials,
            ),
            Err(WebAuthnServiceError::Ceremony(message))
                if message == "RS256 WebAuthn credentials are not supported"
        ));

        let mut blob = vec![CREDENTIAL_BLOB_VERSION];
        push_vec(&mut blob, &[1; 16]).unwrap();
        blob.push(0);
        blob.extend_from_slice(&user_handle(1).unwrap().encode().unwrap());
        push_vec(&mut blob, &encoded_static_state).unwrap();
        assert!(matches!(
            StoredCredential::from_blob(&blob),
            Err(WebAuthnServiceError::Ceremony(message))
                if message == "RS256 WebAuthn credentials are not supported"
        ));
    }
}
