//! Bounded journal parsing and real restart/recovery fixtures, without a DB.

use super::*;

fn assert_visible_path(path: &str) {
    assert!(!path.is_empty());
    assert!(!Path::new(path).is_absolute());
    assert!(!path.contains(['\\', '\0']));
    for component in Path::new(path).components() {
        assert!(matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        ));
    }
}

fn reference_parent(path: &str) -> Vec<&OsStr> {
    // The public path grammar discards CurDir and repeated separators. Compare
    // parent components independently of production's string normalizer.
    let mut components = Path::new(path)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name),
            std::path::Component::CurDir => None,
            other => panic!("accepted journal has an invalid component: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert!(components.pop().is_some());
    components
}

fn check_raw_journal(root: &SecureRoot, input: &[u8]) {
    let name = file_operation_name();
    let path = root
        .display_root
        .join(INTERNAL_DIRECTORY_NAME)
        .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
        .join(&name);
    let mut bytes = input.get(2..).unwrap_or_default().to_vec();
    // Exercise the 64 KiB cap without asking the mutation engine to grow an
    // enormous seed first. Spaces retain a valid JSON prefix when one exists.
    if input.first().copied().unwrap_or(0) & 8 != 0 {
        bytes.resize(
            65_535 + usize::from(input.get(1).copied().unwrap_or(0) % 3),
            b' ',
        );
    }
    std::fs::write(&path, &bytes).unwrap();
    let pending = root.pending_file_operations();
    if bytes.len() > 65_536 {
        assert!(pending.is_err());
    }
    if let Ok(pending) = pending {
        assert_eq!(pending.len(), 1);
        match &pending[0].operation {
            DurableFileOperation::Rename {
                original_path,
                new_path,
                device,
                inode,
                ..
            } => {
                assert_visible_path(original_path);
                assert_visible_path(new_path);
                assert_ne!(original_path, new_path);
                assert_eq!(reference_parent(original_path), reference_parent(new_path));
                assert_ne!(*device, 0);
                assert_ne!(*inode, 0);
            }
            DurableFileOperation::Delete {
                original_path,
                device,
                inode,
                pending_name,
                tombstone_name,
                ..
            } => {
                assert_visible_path(original_path);
                assert_ne!(*device, 0);
                assert_ne!(*inode, 0);
                assert!(is_deletion_pending_name(OsStr::new(pending_name)));
                assert!(is_deletion_tombstone_name(OsStr::new(tombstone_name)));
            }
        }
        let encoded = serde_json::to_vec(&pending[0].operation).unwrap();
        std::fs::write(&path, encoded).unwrap();
        assert_eq!(root.pending_file_operations().unwrap(), pending);
    }
    std::fs::remove_file(path).unwrap();
}

fn contents(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!("fixture read failed: {error}"),
    }
}

fn check_recovery_pass(root: &SecureRoot, first: bool, expect_completion: bool) {
    let operations = root.pending_file_operations().unwrap();
    if first {
        assert_eq!(
            operations.len(),
            1,
            "the fixture journal must reach recovery"
        );
    }
    for pending in operations {
        let outcome = root.recover_file_operation(&pending);
        if expect_completion {
            assert!(
                outcome.is_ok(),
                "consistent recovery fixture was rejected: {outcome:?}"
            );
        }
        if outcome.is_ok() {
            root.complete_file_operation(&pending).unwrap();
        }
    }
    if expect_completion {
        assert!(root.pending_file_operations().unwrap().is_empty());
    }
}

fn check_restarts(
    directory: &Path,
    paths: &[PathBuf],
    replacements: &[PathBuf],
    expected: Option<&[Option<Vec<u8>>]>,
) {
    let before: Vec<_> = paths.iter().map(|path| contents(path)).collect();
    let replacement_identities = replacements
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path).unwrap();
            (metadata.dev(), metadata.ino())
        })
        .collect::<Vec<_>>();
    let mut previous = None;
    for pass in 0..3 {
        match SecureRoot::open(directory) {
            Ok(root) => check_recovery_pass(&root, pass == 0, expected.is_some()),
            Err(error) => {
                // Only a contradictory fixture after its first recovery pass
                // may leave an orphan. The initial valid journal must reopen;
                // consistent positive fixtures must keep reopening afterward.
                assert!(
                    pass != 0 && expected.is_none(),
                    "fixture reopen failed: {error}"
                );
            }
        }
        for (path, identity) in replacements.iter().zip(&replacement_identities) {
            assert_eq!(contents(path).as_deref(), Some(b"replacement".as_slice()));
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!((metadata.dev(), metadata.ino()), *identity);
        }
        let state: Vec<_> = paths.iter().map(|path| contents(path)).collect();
        assert_eq!(
            state.last(),
            before.last(),
            "identity holder must remain intact"
        );
        if let Some(expected) = expected {
            assert_eq!(
                state.as_slice(),
                expected,
                "recovery must reach its specified namespace and preserve payloads"
            );
        }
        if let Some(previous) = &previous {
            assert_eq!(&state, previous, "recovery must converge after one pass");
        }
        previous = Some(state);
    }
    // Recovery never invents file contents; it can only move existing objects.
    for payload in previous.unwrap().iter().flatten() {
        assert!(before.iter().flatten().any(|original| original == payload));
    }
}

fn expected_rename(
    phase: DurableRenamePhase,
    state: u8,
    payload: &[u8],
) -> Option<Vec<Option<Vec<u8>>>> {
    let state = state & 15;
    let names = match (phase, state) {
        (DurableRenamePhase::Intent | DurableRenamePhase::Rollback, 1) => {
            [Some(payload.to_vec()), None]
        }
        (DurableRenamePhase::Intent | DurableRenamePhase::Moved, 2) => {
            [None, Some(payload.to_vec())]
        }
        (DurableRenamePhase::Intent | DurableRenamePhase::Moved, 6) => {
            [Some(b"replacement".to_vec()), Some(payload.to_vec())]
        }
        (DurableRenamePhase::Rollback, 2) => [Some(payload.to_vec()), None],
        _ => return None,
    };
    Some(names.into_iter().chain([Some(payload.to_vec())]).collect())
}

fn expected_delete(
    phase: DurableDeletePhase,
    state: u8,
    payload: &[u8],
) -> Option<Vec<Option<Vec<u8>>>> {
    let state = state & 63;
    let original = match (phase, state) {
        (DurableDeletePhase::Intent | DurableDeletePhase::Rollback, 1 | 2 | 4) => {
            Some(payload.to_vec())
        }
        (DurableDeletePhase::Moved, 1) => Some(payload.to_vec()),
        (DurableDeletePhase::Moved, 0 | 2 | 4) => None,
        (DurableDeletePhase::Moved, 10 | 12) => Some(b"replacement".to_vec()),
        _ => return None,
    };
    Some(vec![original, None, None, Some(payload.to_vec())])
}

fn check_rename(root: SecureRoot, flags: u8, state: u8, payload: &[u8]) {
    let directory = root.display_root.clone();
    let original = directory.join("before");
    let destination = directory.join("after");
    let holder = directory.join("identity-holder");
    std::fs::write(&holder, payload).unwrap();
    let metadata = std::fs::metadata(&holder).unwrap();
    if state & 1 != 0 {
        std::fs::hard_link(&holder, &original).unwrap();
    }
    if state & 2 != 0 {
        std::fs::hard_link(&holder, &destination).unwrap();
    }
    let mut replacements = Vec::new();
    for (bit, path) in [(4, &original), (8, &destination)] {
        if state & bit != 0 {
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
            std::fs::write(path, b"replacement").unwrap();
            replacements.push(path.clone());
        }
    }
    let phase = match flags % 3 {
        0 => DurableRenamePhase::Intent,
        1 => DurableRenamePhase::Moved,
        _ => DurableRenamePhase::Rollback,
    };
    let operation = DurableFileOperation::Rename {
        original_path: "before".into(),
        new_path: "after".into(),
        kind: DurableEntryKind::File,
        device: metadata.dev(),
        inode: metadata.ino(),
        phase,
    };
    journal::write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
    drop(root);
    let expected = expected_rename(phase, state, payload);
    check_restarts(
        &directory,
        &[original, destination, holder],
        &replacements,
        expected.as_deref(),
    );
}

fn check_delete(root: SecureRoot, flags: u8, state: u8, payload: &[u8]) {
    let directory = root.display_root.clone();
    let staging = directory
        .join(INTERNAL_DIRECTORY_NAME)
        .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
    let pending_name = deletion_pending_name();
    let tombstone_name = deletion_tombstone_name();
    let original = directory.join("before");
    let pending = staging.join(&pending_name);
    let tombstone = staging.join(&tombstone_name);
    let holder = directory.join("identity-holder");
    std::fs::write(&holder, payload).unwrap();
    let metadata = std::fs::metadata(&holder).unwrap();
    let paths = [original, pending, tombstone, holder];
    for (index, path) in paths[..3].iter().enumerate() {
        if state & (1 << index) != 0 {
            std::fs::hard_link(&paths[3], path).unwrap();
        }
    }
    let mut replacements = Vec::new();
    for (index, path) in paths[..3].iter().enumerate() {
        if state & (8 << index) != 0 {
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
            std::fs::write(path, b"replacement").unwrap();
            replacements.push(path.clone());
        }
    }
    let phase = match flags % 3 {
        0 => DurableDeletePhase::Intent,
        1 => DurableDeletePhase::Moved,
        _ => DurableDeletePhase::Rollback,
    };
    let operation = DurableFileOperation::Delete {
        original_path: "before".into(),
        kind: DurableEntryKind::File,
        device: metadata.dev(),
        inode: metadata.ino(),
        pending_name,
        tombstone_name,
        allow_recursive: false,
        phase,
    };
    journal::write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
    drop(root);
    let expected = expected_delete(phase, state, payload);
    check_restarts(&directory, &paths, &replacements, expected.as_deref());
}

pub fn check_recovery_journal(input: &[u8]) {
    if input.len() > 65_538 {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("storage");
    std::fs::create_dir(&directory).unwrap();
    let outside = temporary.path().join("outside");
    std::fs::write(&outside, b"outside sentinel").unwrap();
    let root = SecureRoot::open(&directory).unwrap();
    let flags = input.first().copied().unwrap_or(0);
    let state = input.get(1).copied().unwrap_or(0);
    match flags & 3 {
        0 => check_raw_journal(&root, input),
        1 => check_rename(root, flags >> 2, state, &input[2.min(input.len())..]),
        _ => check_delete(root, flags >> 2, state, &input[2.min(input.len())..]),
    }
    assert_eq!(std::fs::read(outside).unwrap(), b"outside sentinel");
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_recovery_fixture_states() {
        for operation in [1u8, 2] {
            for phase in 0..3 {
                for state in 0..64 {
                    super::check_recovery_journal(&[operation | (phase << 2), state, 42]);
                }
            }
        }
        super::check_recovery_journal(b"\0\0{}");
        super::check_recovery_journal(b"\x08\x02{}");
        super::check_recovery_journal(b"\0\0{\"operation\":\"rename\",\"original_path\":\"./before\",\"new_path\":\"after\",\"kind\":\"file\",\"device\":1,\"inode\":1}");
    }
}
