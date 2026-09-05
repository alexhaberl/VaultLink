#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use vaultlink::{db::UploadConflictStrategy, path_security, secure_fs::SecureRoot};

fn can_replace(strategy: &UploadConflictStrategy, checkbox_value: &str) -> bool {
    strategy.can_overwrite() && checkbox_value == "1"
}

fuzz_target!(|input: (String, String, String, bool, u8)| {
    let (directory, filename, checkbox_value, strategy_flag, payload_byte) = input;
    let strategy = if strategy_flag {
        UploadConflictStrategy::OverwriteAllowed
    } else {
        UploadConflictStrategy::Reject
    };
    let requested_replace = can_replace(&strategy, &checkbox_value);

    if !strategy.can_overwrite() {
        assert!(!requested_replace);
    }
    if checkbox_value != "1" {
        assert!(!requested_replace);
    }

    let Ok(directory) = path_security::validate_relative(&directory) else {
        return;
    };
    let Ok(filename) = path_security::safe_filename(&filename) else {
        return;
    };
    let filename = filename.as_ref();
    let directory = directory.to_string_lossy().replace('\\', "/");

    let root_dir = tempfile::tempdir().expect("temporary fuzz root");
    let target_dir = if directory.is_empty() {
        root_dir.path().to_path_buf()
    } else {
        root_dir.path().join(&directory)
    };
    if std::fs::create_dir_all(&target_dir).is_err() {
        return;
    }
    let target_path = target_dir.join(filename);
    if std::fs::write(&target_path, b"original").is_err() {
        return;
    }

    let root = SecureRoot::open(root_dir.path()).expect("secure root opens temporary directory");
    let mut upload = match root.begin_upload(&directory) {
        Ok(upload) => upload,
        Err(_) => return,
    };
    let mut file = match upload.take_file() {
        Ok(file) => file,
        Err(_) => return,
    };
    file.write_all(&[payload_byte]).expect("write fuzz payload");
    file.sync_all().expect("sync fuzz payload");
    drop(file);

    let result = if requested_replace {
        upload.publish_replace(filename)
    } else {
        upload.publish(filename)
    };
    drop(upload);

    // Private staging names pass safe_filename but publication must reject them.
    // Keep them in the input space and check the rejection rather than treating
    // the stricter production destination policy as a crash.
    if requested_replace && path_security::safe_admin_filename(filename).is_ok() {
        assert!(result.is_ok());
        assert_eq!(std::fs::read(&target_path).unwrap(), [payload_byte]);
    } else {
        assert!(result.is_err());
        assert_eq!(std::fs::read(&target_path).unwrap(), b"original");
    }

    let staging = root_dir
        .path()
        .join(path_security::INTERNAL_STORAGE_DIRECTORY_NAME)
        .join("uploads");
    let remaining_parts = std::fs::read_dir(staging)
        .unwrap()
        .map(|entry| entry.expect("read staging entry"))
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(remaining_parts, 0);
});
