use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum PathError {
    #[error("invalid relative path")]
    Invalid,
    #[error("path is outside the storage root")]
    OutsideRoot,
    #[error("path does not exist")]
    NotFound,
    #[error("I/O error: {0}")]
    Io(String),
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
            Component::Normal(v) if v != OsStr::new("") => clean.push(v),
            Component::CurDir => {}
            _ => return Err(PathError::Invalid),
        }
    }
    Ok(clean)
}

pub fn resolve_existing(root: &Path, raw: &str) -> Result<PathBuf, PathError> {
    let rel = validate_relative(raw)?;
    let target = root.join(rel);
    let canonical = target.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PathError::NotFound
        } else {
            PathError::Io(e.to_string())
        }
    })?;
    if canonical == root || canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(PathError::OutsideRoot)
    }
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
    {
        return Err(PathError::Invalid);
    }
    Ok(name)
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

pub fn display_relative(root: &Path, path: &Path) -> Result<String, PathError> {
    path.strip_prefix(root)
        .map_err(|_| PathError::OutsideRoot)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal_and_invalid_decoded_paths() {
        for p in ["../etc", "/etc", "a\\..\\b", "a\0b"] {
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
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        symlink(outside.path(), root.path().join("link")).unwrap();
        let canonical = root.path().canonicalize().unwrap();
        assert_eq!(
            resolve_existing(&canonical, "link/secret"),
            Err(PathError::OutsideRoot)
        );
    }
}
