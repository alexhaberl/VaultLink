//! Internal cargo-fuzz facade.
//!
//! The feature is disabled in normal and release builds. Targets reach the
//! exact policy types used by VaultLink's handlers and services through this
//! module without presenting them as a supported application interface.

pub use crate::policy::{
    add_upload_bytes, normalize_public_upload_subdir, share_upload_conflict_strategy,
    validate_public_upload_filename, validate_share_password, PublicUploadPolicyError,
    SharePasswordValidation, ShareUploadPolicyError, UploadFormField, UploadFormState,
    UploadFormStateError,
};

pub fn is_private_admin_filename(name: &str) -> bool {
    crate::path_security::is_private_admin_filename(name)
}
