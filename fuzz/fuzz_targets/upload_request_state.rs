#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{
    db::Permission,
    fuzzing::{
        self, PublicUploadPolicyError, UploadFormField, UploadFormState, UploadFormStateError,
    },
    runtime,
};

fn permission_from_byte(value: u8) -> Permission {
    match value % 3 {
        0 => Permission::DownloadOnly,
        1 => Permission::UploadOnly,
        _ => Permission::DownloadUpload,
    }
}

fn field_from_byte(value: u8) -> UploadFormField {
    match value % 5 {
        0 => UploadFormField::Path,
        1 => UploadFormField::Overwrite,
        2 => UploadFormField::Csrf,
        3 => UploadFormField::File,
        _ => UploadFormField::Unknown,
    }
}

fuzz_target!(
    |input: (Vec<u8>, u8, String, String, String, Vec<u16>, u16,)| {
        let (fields, permission_byte, upload_subdir, filename, blocked_raw, chunks, max_raw) =
            input;
        let permission = permission_from_byte(permission_byte);
        let maximum_fields = 8usize;
        let mut form = UploadFormState::default();
        for field in fields.into_iter().take(32) {
            let result = form.observe(field_from_byte(field), maximum_fields);
            if matches!(result, Err(UploadFormStateError::TooManyFields)) {
                break;
            }
        }

        let normalized =
            fuzzing::normalize_public_upload_subdir(permission.clone(), &upload_subdir);
        if permission == Permission::UploadOnly {
            assert_eq!(normalized.as_deref(), Ok(""));
        } else if !permission.can_upload() {
            assert_eq!(normalized, Err(PublicUploadPolicyError::ShareRejected));
        }

        let Ok(blocked) = runtime::parse_extension_list(&blocked_raw) else {
            return;
        };
        let filename_result = fuzzing::validate_public_upload_filename(&filename, &blocked);
        if filename_result.is_ok() {
            assert!(!runtime::extension_is_blocked(&filename, &blocked));
        }

        let maximum = u64::from(max_raw).max(1);
        let mut total = 0u64;
        for chunk in chunks {
            match fuzzing::add_upload_bytes(total, u64::from(chunk), maximum) {
                Ok(next) => total = next,
                Err(PublicUploadPolicyError::TooLarge) => break,
                Err(other) => panic!("unexpected byte policy result: {other:?}"),
            }
        }
        assert!(total <= maximum);
    }
);
