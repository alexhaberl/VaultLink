use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::RngExt as _;
use rustix::fs::FlockOperation;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const KEYRING_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;

#[derive(Clone)]
pub(super) struct Keyring(Arc<KeyringInner>);

struct KeyringInner {
    active_key_id: u64,
    keys: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    _lock: Option<File>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKeyring {
    version: u32,
    active_key_id: u64,
    keys: BTreeMap<u64, String>,
}

impl Keyring {
    pub(super) fn open(
        database_path: &Path,
        persistent: bool,
        initialize: bool,
    ) -> rusqlite::Result<Self> {
        if !persistent {
            return Ok(Self::ephemeral());
        }
        let directory = database_path.parent().ok_or_else(|| {
            keyring_error("database path has no parent directory for secrets.keyring")
        })?;
        let lock_path = directory.join("secrets.keyring.lock");
        let lock = open_private_file(&lock_path, true)?;
        // Initialization is serialized as well: two first-start processes must
        // never create different keys and then race to create the database.
        rustix::fs::flock(&lock, FlockOperation::LockExclusive).map_err(|error| {
            keyring_error(format!(
                "cannot acquire keyring initialization lock: {error}"
            ))
        })?;

        let path = directory.join("secrets.keyring");
        let stored = match OpenOptions::new().read(true).open(&path) {
            Ok(mut file) => {
                validate_private_regular_file(&path, &file)?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).map_err(io_error)?;
                serde_json::from_slice::<StoredKeyring>(&bytes)
                    .map_err(|error| keyring_error(format!("invalid secrets.keyring: {error}")))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && initialize => {
                let stored = new_stored_keyring();
                write_keyring_atomic(&path, directory, &stored)?;
                stored
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(keyring_error(
                    "secrets.keyring is required for an initialized database",
                ));
            }
            Err(error) => return Err(io_error(error)),
        };
        rustix::fs::flock(&lock, FlockOperation::LockShared).map_err(|error| {
            keyring_error(format!("cannot acquire shared keyring lock: {error}"))
        })?;
        Self::from_stored(stored, Some(lock))
    }

    fn ephemeral() -> Self {
        let stored = new_stored_keyring();
        Self::from_stored(stored, None).expect("generated ephemeral keyring is valid")
    }

    fn from_stored(stored: StoredKeyring, lock: Option<File>) -> rusqlite::Result<Self> {
        if stored.version != KEYRING_VERSION || !stored.keys.contains_key(&stored.active_key_id) {
            return Err(keyring_error("unsupported or inconsistent secrets.keyring"));
        }
        let mut keys = BTreeMap::new();
        for (id, encoded) in stored.keys {
            let decoded = STANDARD_NO_PAD.decode(encoded).map_err(|error| {
                keyring_error(format!("invalid key encoding for key {id}: {error}"))
            })?;
            if decoded.len() != KEY_BYTES {
                return Err(keyring_error(format!("key {id} has invalid length")));
            }
            keys.insert(id, Zeroizing::new(decoded));
        }
        Ok(Self(Arc::new(KeyringInner {
            active_key_id: stored.active_key_id,
            keys,
            _lock: lock,
        })))
    }

    pub(super) fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> rusqlite::Result<(u64, Vec<u8>)> {
        let key_id = self.0.active_key_id;
        let key = self
            .0
            .keys
            .get(&key_id)
            .ok_or_else(|| keyring_error("active key is unavailable"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| keyring_error("active key has invalid length"))?;
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rng().fill(&mut nonce);
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| keyring_error("secret encryption failed"))?;
        let mut output = Vec::with_capacity(NONCE_BYTES + encrypted.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&encrypted);
        Ok((key_id, output))
    }

    pub(super) fn decrypt(
        &self,
        key_id: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> rusqlite::Result<Vec<u8>> {
        if ciphertext.len() <= NONCE_BYTES {
            return Err(keyring_error("encrypted secret is truncated"));
        }
        let key = self
            .0
            .keys
            .get(&key_id)
            .ok_or_else(|| keyring_error(format!("secret references missing key {key_id}")))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| keyring_error("stored key has invalid length"))?;
        cipher
            .decrypt(
                XNonce::from_slice(&ciphertext[..NONCE_BYTES]),
                Payload {
                    msg: &ciphertext[NONCE_BYTES..],
                    aad,
                },
            )
            .map_err(|_| keyring_error("secret authentication failed"))
    }
}

pub(super) fn rotate_database(database_path: &Path) -> rusqlite::Result<()> {
    let directory = database_path.parent().ok_or_else(|| {
        keyring_error("database path has no parent directory for secrets.keyring")
    })?;
    let lock = open_private_file(&directory.join("secrets.keyring.lock"), true)?;
    rustix::fs::flock(&lock, FlockOperation::LockExclusive).map_err(|error| {
        keyring_error(format!("cannot acquire exclusive keyring lock: {error}"))
    })?;

    let keyring_path = directory.join("secrets.keyring");
    let mut stored = read_stored_keyring(&keyring_path)?;
    // Validate every existing key before publishing a new active key.
    let _validated = Keyring::from_stored(stored.clone(), None)?;
    let new_key_id = match stored.keys.last_key_value() {
        Some((id, _)) => id
            .checked_add(1)
            .ok_or_else(|| keyring_error("key id exhausted"))?,
        None => 1,
    };
    let mut new_key = [0u8; KEY_BYTES];
    rand::rng().fill(&mut new_key);
    stored
        .keys
        .insert(new_key_id, STANDARD_NO_PAD.encode(new_key));
    new_key.fill(0);
    stored.active_key_id = new_key_id;

    // Phase one is durable before any ciphertext references the new key.
    write_keyring_atomic(&keyring_path, directory, &stored)?;
    let rotating = Keyring::from_stored(stored.clone(), None)?;

    let mut connection = rusqlite::Connection::open_with_flags(
        database_path,
        rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    super::schema::migrate(&mut connection)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    rotate_rows(
        &transaction,
        &rotating,
        "SELECT token_hash,token_key_id,token_ciphertext FROM shares",
        "UPDATE shares SET token_key_id=?2,token_ciphertext=?3 WHERE token_hash=?1",
        |stable_id| format!("shares.token:{stable_id}"),
    )?;
    rotate_rows(
        &transaction,
        &rotating,
        "SELECT username,totp_key_id,totp_ciphertext FROM admins",
        "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3 WHERE username=?1",
        |stable_id| format!("admins.totp:{}", stable_id.to_lowercase()),
    )?;
    rotate_rows(
        &transaction,
        &rotating,
        "SELECT token_hash,totp_key_id,totp_ciphertext FROM admin_mfa_enrollments",
        "UPDATE admin_mfa_enrollments SET totp_key_id=?2,totp_ciphertext=?3 WHERE token_hash=?1",
        |stable_id| format!("admin_mfa_enrollments.totp:{stable_id}"),
    )?;
    transaction.commit()?;

    // Once all rows durably reference the new key, old keys can be forgotten.
    stored.keys.retain(|id, _| *id == new_key_id);
    write_keyring_atomic(&keyring_path, directory, &stored)
}

fn rotate_rows(
    transaction: &rusqlite::Transaction<'_>,
    keyring: &Keyring,
    select_sql: &str,
    update_sql: &str,
    aad: impl Fn(&str) -> String,
) -> rusqlite::Result<()> {
    let rows = {
        let mut statement = transaction.prepare(select_sql)?;
        let collected = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        collected
    };
    let mut update = transaction.prepare(update_sql)?;
    for (stable_id, old_key_id, old_ciphertext) in rows {
        let associated_data = aad(&stable_id);
        let plaintext = Zeroizing::new(keyring.decrypt(
            old_key_id,
            &old_ciphertext,
            associated_data.as_bytes(),
        )?);
        let (new_key_id, new_ciphertext) =
            keyring.encrypt(&plaintext, associated_data.as_bytes())?;
        if update.execute(rusqlite::params![stable_id, new_key_id, new_ciphertext])? != 1 {
            return Err(keyring_error("secret rotation database invariant failed"));
        }
    }
    Ok(())
}

fn new_stored_keyring() -> StoredKeyring {
    let mut key = [0u8; KEY_BYTES];
    rand::rng().fill(&mut key);
    let mut keys = BTreeMap::new();
    keys.insert(1, STANDARD_NO_PAD.encode(key));
    key.fill(0);
    StoredKeyring {
        version: KEYRING_VERSION,
        active_key_id: 1,
        keys,
    }
}

fn read_stored_keyring(path: &Path) -> rusqlite::Result<StoredKeyring> {
    let mut file = OpenOptions::new().read(true).open(path).map_err(io_error)?;
    validate_private_regular_file(path, &file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes).map_err(io_error)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| keyring_error(format!("invalid secrets.keyring: {error}")))
}

fn write_keyring_atomic(
    path: &Path,
    directory: &Path,
    stored: &StoredKeyring,
) -> rusqlite::Result<()> {
    let mut random_suffix = [0u8; 8];
    rand::rng().fill(&mut random_suffix);
    let temporary_path: PathBuf = directory.join(format!(
        ".secrets.keyring.{}.{}.tmp",
        std::process::id(),
        data_encoding::HEXLOWER.encode(&random_suffix)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary_path).map_err(io_error)?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(stored)
            .map_err(|error| keyring_error(format!("cannot encode secrets.keyring: {error}")))?,
    );
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    if let Err(error) = std::fs::rename(&temporary_path, path) {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(io_error(error));
    }
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn open_private_file(path: &Path, create: bool) -> rusqlite::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create).mode(0o600);
    let file = options.open(path).map_err(io_error)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    validate_private_regular_file(path, &file)?;
    Ok(file)
}

fn validate_private_regular_file(path: &Path, file: &File) -> rusqlite::Result<()> {
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(keyring_error(format!(
            "{} must be a service-owned, single-link regular file with mode 0600",
            path.display()
        )));
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(KeyringFailure::Io(error)))
}

#[derive(Debug)]
enum KeyringFailure {
    Message(String),
    Io(std::io::Error),
}

impl std::fmt::Display for KeyringFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for KeyringFailure {}

pub(crate) fn is_crypto_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::ToSqlConversionFailure(source)
            if source.downcast_ref::<KeyringFailure>().is_some()
    )
}

fn keyring_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(KeyringFailure::Message(message.into())))
}
