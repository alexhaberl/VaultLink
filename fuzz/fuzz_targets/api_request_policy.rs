#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{
    db::{Permission, UploadConflictStrategy},
    path_security, runtime,
};

fn permission_from_byte(value: u8) -> Permission {
    match value % 3 {
        0 => Permission::DownloadOnly,
        1 => Permission::UploadOnly,
        _ => Permission::DownloadUpload,
    }
}

fn strategy_from_byte(value: u8) -> UploadConflictStrategy {
    if value % 2 == 0 {
        UploadConflictStrategy::Reject
    } else {
        UploadConflictStrategy::OverwriteAllowed
    }
}

fn password_policy_accepts(password: &str, min: usize, max: usize) -> bool {
    let chars = password.chars().count();
    chars >= min && chars <= max && password.len() <= 1024
}

fuzz_target!(|input: (
    String,
    String,
    String,
    String,
    u8,
    u8,
    bool,
    bool,
    u8,
    u8,
    String,
    u16,
)| {
    let (
        share_path,
        public_subpath,
        alias,
        password,
        permission_byte,
        strategy_byte,
        is_directory,
        overwrite_requested,
        min_raw,
        max_extra_raw,
        extensions_raw,
        limit_raw,
    ) = input;

    let permission = permission_from_byte(permission_byte);
    let strategy = strategy_from_byte(strategy_byte);
    let min = usize::from(min_raw % 64).max(8);
    let max = min + usize::from(max_extra_raw % 128);
    let upload_limit = u64::from(limit_raw).max(1);
    let download_limit = upload_limit;
    let media_limit = upload_limit;

    if let Ok(path) = path_security::validate_relative(&share_path) {
        assert!(!path.is_absolute());
        assert!(!path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)));
    }

    if let Ok(path) = path_security::validate_relative(&public_subpath) {
        assert!(!path.is_absolute());
        assert!(!path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)));
    }

    if path_security::validate_share_alias(&alias).is_ok() {
        assert!(
            (path_security::SHARE_ALIAS_MIN_LENGTH..=path_security::SHARE_ALIAS_MAX_LENGTH)
                .contains(&alias.len())
        );
        assert!(!alias.contains('/'));
        assert!(!alias.contains('\\'));
        assert!(!alias.contains('\0'));
    }

    if password_policy_accepts(&password, min, max) {
        assert!(password.chars().count() >= min);
        assert!(password.chars().count() <= max);
        assert!(password.len() <= 1024);
    }

    if let Ok(extensions) = runtime::parse_extension_list(&extensions_raw) {
        for extension in &extensions {
            assert!(!extension.is_empty());
            assert!(!extension.contains('/'));
            assert!(!extension.contains('\\'));
            assert!(!extension.contains('\0'));
            assert!(!extension.chars().any(char::is_control));
        }
    }

    let share_permission_is_accepted = is_directory || !permission.can_upload();
    if !share_permission_is_accepted {
        assert!(!is_directory);
        assert!(permission.can_upload());
    }

    let effective_strategy = if share_permission_is_accepted
        && is_directory
        && permission.can_upload()
        && overwrite_requested
    {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    assert_eq!(
        effective_strategy.can_overwrite(),
        share_permission_is_accepted
            && is_directory
            && permission.can_upload()
            && overwrite_requested
    );
    if !strategy.can_overwrite() {
        assert!(!strategy.can_overwrite());
    }

    assert!(upload_limit > 0);
    assert!(download_limit > 0);
    assert!(media_limit > 0);
});
