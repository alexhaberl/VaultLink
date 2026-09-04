#[cfg(test)]
use std::sync::Mutex;
use std::{ffi::OsStr, io};

use crate::{
    log_safety::{EscapedLogPath, EscapedLogValue},
    path_security,
};

use super::identity::{entry_identity_state, entry_matches_identity};
use super::journal::{
    remove_file_operation, remove_pending_manifest, replace_delete_operation_phase,
    replace_file_operation, write_file_operation, write_pending_manifest,
};
use super::private_entries::{active_upload_fragment_guard, unregister_upload_fragment};
use super::{
    deletion_pending_name, deletion_tombstone_name, directory_scan_from_file, join_relative, linux,
    split_parent_name, DeleteCommitOutcome, DeleteCommitStageOutcome, DeleteStageOutcome,
    DurableDeletePhase, DurableFileOperation, DurableRenamePhase, EntryIdentityState, EntryKind,
    EntryStatus, PendingDeleteCommit, RenameStageOutcome, SecureDirectory, SecureRoot,
    StagedDelete, StagedRename,
};

enum PendingDeleteStage {
    Ready {
        tombstone_name: String,
        manifest_name: String,
    },
    PublishedUncertain(io::Error),
}

struct PendingDeleteSource<'a> {
    parent: &'a SecureDirectory,
    original_name: &'a str,
    original_path: &'a str,
    identity: (u64, u64),
    kind: EntryKind,
}

include!("staging/rename.rs");
include!("staging/delete.rs");

fn ambiguous_delete_stage_error(
    rename_error: &io::Error,
    pending_state: &io::Result<EntryIdentityState>,
    source_state: &io::Result<EntryIdentityState>,
) -> io::Error {
    fn describe(state: &io::Result<EntryIdentityState>) -> String {
        match state {
            Ok(EntryIdentityState::Expected) => "expected identity".to_string(),
            Ok(EntryIdentityState::Missing) => "missing".to_string(),
            Ok(EntryIdentityState::Replaced) => "different identity".to_string(),
            Err(error) => format!("probe failed: {error}"),
        }
    }

    io::Error::new(
        rename_error.kind(),
        format!(
            "delete staging rename outcome is ambiguous after {rename_error}; pending {}; source {}",
            describe(pending_state),
            describe(source_state)
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn uncertain_delete_rollback_error(
    original_error: &io::Error,
    rollback: &io::Result<()>,
    source_state: &io::Result<EntryIdentityState>,
    pending_state: &io::Result<EntryIdentityState>,
    parent_sync: &io::Result<()>,
    staging_sync: &io::Result<()>,
    manifest_error: Option<&io::Error>,
) -> io::Error {
    fn identity(state: &io::Result<EntryIdentityState>) -> String {
        match state {
            Ok(EntryIdentityState::Expected) => "expected identity".to_string(),
            Ok(EntryIdentityState::Missing) => "missing".to_string(),
            Ok(EntryIdentityState::Replaced) => "different identity".to_string(),
            Err(error) => format!("probe failed: {error}"),
        }
    }
    fn operation(result: &io::Result<()>) -> String {
        match result {
            Ok(()) => "ok".to_string(),
            Err(error) => format!("failed: {error}"),
        }
    }

    let manifest = manifest_error.map_or_else(
        || "not attempted".to_string(),
        |error| format!("failed: {error}"),
    );
    io::Error::new(
        original_error.kind(),
        format!(
            "delete staging cleanup is uncertain after {original_error}; rollback {}; source {}; pending {}; parent sync {}; staging sync {}; manifest cleanup {manifest}",
            operation(rollback),
            identity(source_state),
            identity(pending_state),
            operation(parent_sync),
            operation(staging_sync),
        ),
    )
}

impl PendingDeleteCommit {
    pub fn outcome(&self) -> &DeleteCommitOutcome {
        &self.outcome
    }

    pub fn complete(mut self) -> io::Result<DeleteCommitOutcome> {
        remove_file_operation(&self.staging, &self.operation_name)?;
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
        Ok(self.outcome.clone())
    }
}

impl Drop for PendingDeleteCommit {
    fn drop(&mut self) {
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
    }
}

#[cfg(test)]
fn inject_error_after_successful_rename(
    rename: io::Result<()>,
    next_error: &Mutex<Option<io::ErrorKind>>,
) -> io::Result<()> {
    rename?;
    let kind = next_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    match kind {
        Some(kind) => Err(io::Error::new(kind, "injected rename response loss")),
        None => Ok(()),
    }
}
