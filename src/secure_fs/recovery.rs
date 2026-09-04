use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
};

use crate::log_safety::{EscapedLogPath, EscapedLogValue};

use super::identity::{entry_exists, entry_identity_state, entry_matches_identity};
use super::journal::{
    read_file_operation, read_pending_manifest, remove_file_operation, remove_pending_manifest,
    replace_delete_operation_phase, replace_file_operation,
};
use super::private_entries::{
    active_upload_fragment_guard, is_upload_fragment_name, unregister_upload_fragment,
};
use super::{
    cleanup_segment_name, deletion_manifest_name, deletion_pending_from_manifest_name,
    is_deletion_pending_name, is_deletion_tombstone_name, is_file_operation_name,
    is_file_operation_temporary_name, linux, split_parent_name, split_parent_name_private,
    CleanupDirectory, CleanupPolicy, DurableDeletePhase, DurableFileOperation, DurableRenamePhase,
    EntryIdentityState, EntryKind, FileOperationRecovery, PendingFileOperation, SecureDirectory,
    SecureRoot, UploadFragmentCleanup, UploadFragmentCleanupBatch, MAX_CLEANUP_DIRECTORY_STACK,
    MAX_CLEANUP_VISITED_DIRECTORIES,
};

include!("recovery/fragments.rs");
include!("recovery/validation.rs");
include!("recovery/rename.rs");
include!("recovery/delete.rs");
include!("recovery/cleanup.rs");
