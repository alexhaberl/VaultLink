//! Descriptor-relative storage access. Linux production builds use `openat2(2)`
//! so a path cannot escape the configured root between validation and use.

mod capability;
mod identity;
mod journal;
mod private_entries;
mod recovery;
mod staging;
mod upload;

use capability::{directory_scan_from_file, linux};
use identity::entry_exists;
#[cfg(test)]
use journal::{replace_delete_operation_phase, replace_file_operation, write_file_operation};
use private_entries::ActiveUploadFragmentKey;
#[cfg(test)]
use private_entries::{active_upload_fragment_guard, unregister_upload_fragment};
pub use private_entries::{is_upload_fragment_name, upload_fragment_name};
#[cfg(test)]
use recovery::{rebase_cleanup_directory, start_cleanup_from_directory};
pub use upload::{PendingUpload, PublishOutcome};

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::path_security;

include!("secure_fs/model.rs");
include!("secure_fs/root.rs");
include!("secure_fs/directory.rs");

#[cfg(test)]
mod tests {
    include!("secure_fs/tests/test_support.rs");
    include!("secure_fs/tests/creation.rs");
    include!("secure_fs/tests/rename_recovery.rs");
    include!("secure_fs/tests/delete_recovery.rs");
    include!("secure_fs/tests/upload_security.rs");
}
