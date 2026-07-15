use std::{fs::File, io};

use super::{linux, EntryIdentityState, EntryKind};

pub(super) fn entry_identity_state(
    directory: &File,
    name: &str,
    expected: (u64, u64),
    expected_kind: EntryKind,
) -> io::Result<EntryIdentityState> {
    use std::os::unix::fs::MetadataExt;

    let entry = match linux::openat2(directory, name, linux::O_PATH | linux::O_NOFOLLOW) {
        Ok(entry) => entry,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(EntryIdentityState::Missing);
        }
        Err(error) => return Err(error),
    };
    let metadata = entry.metadata()?;
    let matches = (metadata.dev(), metadata.ino()) == expected
        && match expected_kind {
            EntryKind::File => metadata.is_file(),
            EntryKind::Directory => metadata.is_dir(),
        };
    Ok(if matches {
        EntryIdentityState::Expected
    } else {
        EntryIdentityState::Replaced
    })
}

pub(super) fn entry_matches_identity(
    directory: &File,
    name: &str,
    expected: (u64, u64),
    expected_kind: EntryKind,
) -> bool {
    entry_identity_state(directory, name, expected, expected_kind)
        .is_ok_and(|state| state == EntryIdentityState::Expected)
}

pub(super) fn entry_exists(directory: &File, name: &str) -> io::Result<bool> {
    match linux::openat2(directory, name, linux::O_PATH | linux::O_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
