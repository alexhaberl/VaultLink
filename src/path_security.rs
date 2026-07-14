use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

pub const INTERNAL_STORAGE_DIRECTORY_NAME: &str = ".vaultlink-internal";
pub const SHARE_ALIAS_MIN_LENGTH: usize = 12;
pub const SHARE_ALIAS_MAX_LENGTH: usize = 32;

/// SMB servers can expose case-insensitive names and commonly ignore trailing
/// dots or spaces. Treat every such spelling as the private namespace so a
/// normal client path can never alias VaultLink's staging directory.
pub fn is_internal_storage_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.trim_end_matches(['.', ' '])
            .eq_ignore_ascii_case(INTERNAL_STORAGE_DIRECTORY_NAME)
    })
}

#[derive(Debug, Error, PartialEq)]
pub enum PathError {
    #[error("invalid relative path")]
    Invalid,
}

pub fn validate_relative(raw: &str) -> Result<PathBuf, PathError> {
    if raw.contains('\0') || raw.contains('\\') {
        return Err(PathError::Invalid);
    }
    // HTTP extractors decode query/form percent-encoding exactly once before this
    // function is called. Decoding again would turn legitimate '%' filenames into
    // ambiguous paths and could make uploaded files unreachable.
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(PathError::Invalid);
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(v) if v != OsStr::new("") && !is_internal_storage_name(v) => {
                clean.push(v)
            }
            Component::CurDir => {}
            _ => return Err(PathError::Invalid),
        }
    }
    Ok(clean)
}

pub fn safe_filename(name: &str) -> Result<&str, PathError> {
    let windows_stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let windows_reserved = matches!(windows_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || windows_stem.strip_prefix("COM").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || windows_stem.strip_prefix("LPT").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        });
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || is_internal_storage_name(OsStr::new(name))
        || name.contains(['/', '\\', '\0', ':', '<', '>', '"', '|', '?', '*'])
        || name.chars().any(|c| c.is_control())
        || windows_reserved
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
        || Path::new(name).components().count() != 1
    {
        return Err(PathError::Invalid);
    }
    Ok(name)
}

pub fn safe_admin_filename(name: &str) -> Result<&str, PathError> {
    let name = safe_filename(name)?;
    if private_token_name(name, ".vaultlink-", ".part")
        || private_token_name(name, ".vaultlink-delete-", ".tombstone")
        || private_token_name(name, ".vaultlink-delete-pending-", ".pending")
        || is_internal_storage_name(OsStr::new(name))
    {
        return Err(PathError::Invalid);
    }
    Ok(name)
}

/// Validates the canonical share-alias policy for both creation and lookup.
pub fn validate_share_alias(alias: &str) -> Result<&str, PathError> {
    if !(SHARE_ALIAS_MIN_LENGTH..=SHARE_ALIAS_MAX_LENGTH).contains(&alias.len())
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PathError::Invalid);
    }
    Ok(alias)
}

fn private_token_name(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(suffix))
        .is_some_and(|token| {
            token.len() == 24
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal_and_invalid_decoded_paths() {
        for p in [
            "../etc",
            "/etc",
            "a\\..\\b",
            "a\0b",
            ".vaultlink-internal",
            ".VAULTLINK-INTERNAL",
            ".vaultlink-internal.",
            "docs/.vaultlink-internal/uploads",
            "docs/.VaUlTlInK-InTeRnAl /uploads",
        ] {
            assert!(validate_relative(p).is_err(), "{p}");
        }
    }
    #[test]
    fn accepts_normal_path() {
        assert_eq!(
            validate_relative("folder/file.txt").unwrap(),
            PathBuf::from("folder/file.txt")
        );
        assert_eq!(
            validate_relative("100%.txt").unwrap(),
            PathBuf::from("100%.txt")
        );
        assert_eq!(
            validate_relative("%2e%2e").unwrap(),
            PathBuf::from("%2e%2e")
        );
    }
    #[test]
    fn filename_rules() {
        assert!(safe_filename("ok file.txt").is_ok());
        assert!(safe_admin_filename(INTERNAL_STORAGE_DIRECTORY_NAME).is_err());
        assert!(safe_admin_filename(".VAULTLINK-INTERNAL").is_err());
        assert!(safe_admin_filename(".vaultlink-internal.").is_err());
        assert!(safe_filename("../x").is_err());
        for unsafe_name in [
            "C:escape.txt",
            "CON.txt",
            "LPT1",
            "trailing.",
            "trailing ",
            "question?.txt",
        ] {
            assert!(safe_filename(unsafe_name).is_err(), "{unsafe_name}");
        }
    }

    #[test]
    fn new_share_alias_rules() {
        for valid in [
            "alias-123456",
            "alias_123456",
            "abcdefghijklmnopqrstuvwxzy123456",
        ] {
            assert_eq!(validate_share_alias(valid), Ok(valid));
        }
        for invalid in [
            "short-alias",
            "abcdefghijklmnopqrstuvwxzy1234567",
            "alias has spaces",
            "alias.with.dot",
            "ümlaut-alias1",
        ] {
            assert!(validate_share_alias(invalid).is_err(), "{invalid}");
        }
    }
}
