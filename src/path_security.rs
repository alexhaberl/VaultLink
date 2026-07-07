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
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| PathError::Invalid)?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return Err(PathError::Invalid);
    }
    if decoded.contains('%') {
        return Err(PathError::Invalid);
    } // reject ambiguous/double encoding
    let path = Path::new(decoded.as_ref());
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
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || name.chars().any(|c| c.is_control())
    {
        return Err(PathError::Invalid);
    }
    Ok(name)
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
    fn rejects_traversal_and_encoding() {
        for p in [
            "../etc",
            "%2e%2e/etc",
            "%252e%252e/etc",
            "/etc",
            "a\\..\\b",
            "a%5cb",
            "a%00b",
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
    }
    #[test]
    fn filename_rules() {
        assert!(safe_filename("ok file.txt").is_ok());
        assert!(safe_filename("../x").is_err());
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
