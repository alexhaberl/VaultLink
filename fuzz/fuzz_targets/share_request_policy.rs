#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{
    db::{Permission, UploadConflictStrategy},
    fuzzing::{self, SharePasswordValidation, ShareUploadPolicyError},
    path_security,
    runtime::{self, RuntimeSettings},
};

fn permission_from_byte(value: u8) -> Permission {
    match value % 3 {
        0 => Permission::DownloadOnly,
        1 => Permission::UploadOnly,
        _ => Permission::DownloadUpload,
    }
}

fn settings(min: usize, max: usize) -> RuntimeSettings {
    RuntimeSettings {
        public_base_url: "http://localhost".into(),
        max_upload_size: 1,
        blocked_extensions: Vec::new(),
        share_password_min_length: min,
        share_password_max_length: max,
        share_unlock_minutes: 1,
        max_zip_size: 1,
        max_zip_files: 1,
        max_search_entries: 1,
        max_search_results: 1,
        max_preview_size: 1,
        preview_extensions: vec!["txt".into()],
        image_preview_extensions: vec!["png".into()],
        pdf_preview_enabled: true,
        max_media_preview_size: 1,
        audit_client_ip_enabled: false,
    }
}

fuzz_target!(
    |input: (String, String, String, u8, bool, bool, u8, u8, String)| {
        let (
            share_path,
            alias,
            password,
            permission_byte,
            is_directory,
            overwrite_requested,
            min_raw,
            max_extra_raw,
            extensions_raw,
        ) = input;
        let permission = permission_from_byte(permission_byte);
        let min = usize::from(min_raw % 64).max(8);
        let max = min + usize::from(max_extra_raw % 128);

        let _ = path_security::validate_relative(&share_path);
        let _ = path_security::validate_share_alias(&alias);
        let _ = runtime::parse_extension_list(&extensions_raw);

        match fuzzing::validate_share_password(&settings(min, max), &password) {
            SharePasswordValidation::Valid => {
                assert!((min..=max).contains(&password.chars().count()));
                assert!(password.len() <= vaultlink::auth::MAX_PASSWORD_BYTES);
            }
            SharePasswordValidation::InvalidCharacterLength => {}
            SharePasswordValidation::TooManyBytes => {
                assert!(password.len() > vaultlink::auth::MAX_PASSWORD_BYTES)
            }
        }

        let decision = fuzzing::share_upload_conflict_strategy(
            is_directory,
            permission.clone(),
            overwrite_requested,
            false,
        );
        if permission.can_upload() && !is_directory {
            assert_eq!(
                decision,
                Err(ShareUploadPolicyError::UploadPermissionRequiresDirectory)
            );
        } else if overwrite_requested && is_directory && permission.can_upload() {
            assert_eq!(decision, Ok(UploadConflictStrategy::OverwriteAllowed));
        }

        if overwrite_requested {
            let with_external_writers = fuzzing::share_upload_conflict_strategy(
                is_directory,
                permission,
                overwrite_requested,
                true,
            );
            if is_directory && with_external_writers.is_err() {
                assert_eq!(
                    with_external_writers,
                    Err(ShareUploadPolicyError::OverwriteDisabledForExternalWriters)
                );
            }
        }
    }
);
