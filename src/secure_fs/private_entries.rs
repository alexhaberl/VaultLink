use std::{
    collections::HashSet,
    ffi::OsStr,
    sync::{Mutex, MutexGuard, OnceLock},
};

pub(super) type ActiveUploadFragmentKey = String;

const UPLOAD_FRAGMENT_PREFIX: &str = ".vaultlink-";
const UPLOAD_FRAGMENT_SUFFIX: &str = ".part";
const UPLOAD_FRAGMENT_TOKEN_LENGTH: usize = 24;

static ACTIVE_UPLOAD_FRAGMENTS: OnceLock<Mutex<HashSet<ActiveUploadFragmentKey>>> = OnceLock::new();

fn active_upload_fragments() -> &'static Mutex<HashSet<ActiveUploadFragmentKey>> {
    ACTIVE_UPLOAD_FRAGMENTS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(super) fn active_upload_fragment_guard() -> MutexGuard<'static, HashSet<ActiveUploadFragmentKey>>
{
    active_upload_fragments()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn unregister_upload_fragment(key: &str) {
    active_upload_fragment_guard().remove(key);
}

/// Generates the private filename used while an upload is incomplete.
pub fn upload_fragment_name() -> String {
    format!(
        "{UPLOAD_FRAGMENT_PREFIX}{}{UPLOAD_FRAGMENT_SUFFIX}",
        crate::auth::random_token(18)
    )
}

/// Matches only filenames in VaultLink's private upload-fragment namespace.
pub fn is_upload_fragment_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(token) = name
        .strip_prefix(UPLOAD_FRAGMENT_PREFIX)
        .and_then(|name| name.strip_suffix(UPLOAD_FRAGMENT_SUFFIX))
    else {
        return false;
    };
    token.len() == UPLOAD_FRAGMENT_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
