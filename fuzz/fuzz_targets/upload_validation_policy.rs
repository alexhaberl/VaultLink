#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{db::Permission, path_security, runtime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadDecision {
    ShareRejected,
    InvalidPath,
    InvalidFilename,
    BlockedExtension,
    TooLarge,
    Accepted { replace: bool },
}

fn add_upload_bytes(total: u64, chunk: u64, maximum: u64) -> Option<u64> {
    total
        .checked_add(chunk)
        .filter(|new_total| *new_total <= maximum)
}

fn permission_from_byte(value: u8) -> Permission {
    match value % 3 {
        0 => Permission::DownloadOnly,
        1 => Permission::UploadOnly,
        _ => Permission::DownloadUpload,
    }
}

fn decide_upload(
    is_directory: bool,
    permission: &Permission,
    upload_subdir: &str,
    filename: &str,
    blocked_extensions: &[String],
    chunks: &[u16],
    maximum: u64,
    overwrite_allowed: bool,
    checkbox_value: &str,
) -> UploadDecision {
    if !is_directory || !permission.can_upload() {
        return UploadDecision::ShareRejected;
    }

    if permission == &Permission::DownloadUpload
        && path_security::validate_relative(upload_subdir).is_err()
    {
        return UploadDecision::InvalidPath;
    }

    if path_security::safe_filename(filename).is_err() {
        return UploadDecision::InvalidFilename;
    }

    if runtime::extension_is_blocked(filename, blocked_extensions) {
        return UploadDecision::BlockedExtension;
    }

    let mut total = 0u64;
    for chunk in chunks {
        let Some(next) = add_upload_bytes(total, u64::from(*chunk), maximum) else {
            return UploadDecision::TooLarge;
        };
        total = next;
    }

    UploadDecision::Accepted {
        replace: overwrite_allowed && checkbox_value == "1",
    }
}

fuzz_target!(|input: (bool, u8, String, String, String, Vec<u16>, u16, bool, String)| {
    let (
        is_directory,
        permission_byte,
        upload_subdir,
        filename,
        blocked_raw,
        chunks,
        max_raw,
        overwrite_allowed,
        checkbox_value,
    ) = input;
    let permission = permission_from_byte(permission_byte);
    let Ok(blocked_extensions) = runtime::parse_extension_list(&blocked_raw) else {
        return;
    };
    let maximum = u64::from(max_raw).max(1);

    let decision = decide_upload(
        is_directory,
        &permission,
        &upload_subdir,
        &filename,
        &blocked_extensions,
        &chunks,
        maximum,
        overwrite_allowed,
        &checkbox_value,
    );

    if !is_directory || !permission.can_upload() {
        assert_eq!(decision, UploadDecision::ShareRejected);
    }

    if permission == Permission::UploadOnly {
        assert_ne!(decision, UploadDecision::InvalidPath);
    }

    if runtime::extension_is_blocked(&filename, &blocked_extensions)
        && is_directory
        && permission.can_upload()
        && path_security::safe_filename(&filename).is_ok()
        && (permission != Permission::DownloadUpload
            || path_security::validate_relative(&upload_subdir).is_ok())
    {
        assert_eq!(decision, UploadDecision::BlockedExtension);
    }

    if let UploadDecision::Accepted { replace } = decision {
        assert_eq!(replace, overwrite_allowed && checkbox_value == "1");
        assert!(is_directory);
        assert!(permission.can_upload());
        assert!(path_security::safe_filename(&filename).is_ok());
        assert!(!runtime::extension_is_blocked(&filename, &blocked_extensions));
        if permission == Permission::DownloadUpload {
            assert!(path_security::validate_relative(&upload_subdir).is_ok());
        }
        let total = chunks
            .iter()
            .try_fold(0u64, |total, chunk| add_upload_bytes(total, u64::from(*chunk), maximum));
        assert!(total.is_some());
    }
});
