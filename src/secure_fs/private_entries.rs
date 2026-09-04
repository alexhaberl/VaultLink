use std::{
    collections::HashSet,
    ffi::OsStr,
    sync::{Mutex, MutexGuard, OnceLock},
};

use super::{
    is_deletion_tombstone_name, PRIVATE_STORAGE_RANDOM_BYTES, PRIVATE_STORAGE_TOKEN_LENGTH,
    UPLOAD_FRAGMENT_PREFIX, UPLOAD_FRAGMENT_SUFFIX,
};

pub(super) type ActiveUploadFragmentKey = String;

static ACTIVE_UPLOAD_FRAGMENTS: OnceLock<Mutex<HashSet<ActiveUploadFragmentKey>>> = OnceLock::new();

fn active_upload_fragments() -> &'static Mutex<HashSet<ActiveUploadFragmentKey>> {
    ACTIVE_UPLOAD_FRAGMENTS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(super) fn active_upload_fragment_guard() -> MutexGuard<'static, HashSet<ActiveUploadFragmentKey>>
{
    let fragments = active_upload_fragments();
    match fragments.lock() {
        Ok(active) => active,
        Err(poisoned) => {
            tracing::error!("recovering poisoned active-upload map");
            let mut active = poisoned.into_inner();
            // Preserve only names that can actually belong to an upload or a
            // committed deletion. Keeping valid entries is fail-closed for the
            // cleanup worker; removing malformed keys prevents permanent junk.
            active.retain(|key| {
                let key = OsStr::new(key);
                is_upload_fragment_name(key) || is_deletion_tombstone_name(key)
            });
            fragments.clear_poison();
            active
        }
    }
}

pub(super) fn unregister_upload_fragment(key: &str) {
    active_upload_fragment_guard().remove(key);
}

/// Generates the private filename used while an upload is incomplete.
pub fn upload_fragment_name() -> String {
    format!(
        "{UPLOAD_FRAGMENT_PREFIX}{}{UPLOAD_FRAGMENT_SUFFIX}",
        crate::auth::random_token(PRIVATE_STORAGE_RANDOM_BYTES)
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
    token.len() == PRIVATE_STORAGE_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestKeys(Vec<String>);

    impl Drop for TestKeys {
        fn drop(&mut self) {
            let mut active = active_upload_fragment_guard();
            for key in &self.0 {
                active.remove(key);
            }
        }
    }

    #[test]
    fn active_upload_map_discards_invalid_entries_after_poisoning() {
        // Normalize any poison left by another concurrently running recovery
        // test before deliberately injecting this test's unwind.
        drop(active_upload_fragment_guard());
        let valid = upload_fragment_name();
        let invalid = format!("invalid-active-upload-{}", crate::auth::random_token(12));
        let _cleanup = TestKeys(vec![valid.clone(), invalid.clone()]);
        let fragments = active_upload_fragments();

        let panic = std::panic::catch_unwind(|| {
            let mut active = fragments.lock().unwrap();
            active.insert(valid.clone());
            active.insert(invalid.clone());
            panic!("inject active-upload map poisoning");
        });
        assert!(panic.is_err());

        let active = active_upload_fragment_guard();
        assert!(active.contains(&valid));
        assert!(!active.contains(&invalid));
        drop(active);
        assert!(!fragments.is_poisoned());
    }
}
