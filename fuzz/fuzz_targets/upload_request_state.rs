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
    match value % 6 {
        0 => UploadFormField::Path,
        1 => UploadFormField::Overwrite,
        2 => UploadFormField::Csrf,
        3 => UploadFormField::File,
        4 => UploadFormField::Unknown,
        _ => UploadFormField::FolderPath,
    }
}

fuzz_target!(
    |input: (Vec<u8>, u8, String, String, String, Vec<u64>, u64, u64)| {
        let (
            fields,
            permission_byte,
            upload_subdir,
            filename,
            blocked_raw,
            chunks,
            maximum,
            initial_total,
        ) = input;
        let permission = permission_from_byte(permission_byte);
        let maximum_fields = 8usize;
        let mut form = UploadFormState::default();
        let mut history = Vec::new();
        for (index, field) in fields.into_iter().take(32).map(field_from_byte).enumerate() {
            // A history-based oracle is independent of production's mutable
            // booleans. Continue after errors to check state transitions too.
            let duplicate = history.contains(&field);
            let late = history.contains(&UploadFormField::File);
            let expected = if index >= maximum_fields {
                Err(UploadFormStateError::TooManyFields)
            } else {
                match field {
                    UploadFormField::Path if duplicate || late => {
                        Err(UploadFormStateError::DuplicateOrLatePath)
                    }
                    UploadFormField::FolderPath if duplicate || late => {
                        Err(UploadFormStateError::DuplicateOrLateFolderPath)
                    }
                    UploadFormField::Overwrite if duplicate => {
                        Err(UploadFormStateError::DuplicateOverwrite)
                    }
                    UploadFormField::Csrf if duplicate || late => {
                        Err(UploadFormStateError::DuplicateOrLateCsrf)
                    }
                    UploadFormField::File if duplicate => Err(UploadFormStateError::MultipleFiles),
                    UploadFormField::Unknown => Err(UploadFormStateError::UnknownField),
                    _ => Ok(()),
                }
            };
            assert_eq!(form.observe(field, maximum_fields), expected);
            if index < maximum_fields {
                history.push(field);
            }
            assert_eq!(form.saw_file(), history.contains(&UploadFormField::File));
        }

        // u128 arithmetic supplies an independent oracle for u64 overflow,
        // exact limits, zero-byte chunks, and an already-over-limit total.
        let mut total = initial_total;
        for chunk in chunks.into_iter().take(64) {
            let sum = u128::from(total) + u128::from(chunk);
            let expected = if sum <= u128::from(maximum) && sum <= u128::from(u64::MAX) {
                Ok(sum as u64)
            } else {
                Err(PublicUploadPolicyError::TooLarge)
            };
            let actual = fuzzing::add_upload_bytes(total, chunk, maximum);
            assert_eq!(actual, expected);
            if let Ok(next) = actual {
                total = next;
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
    }
);
