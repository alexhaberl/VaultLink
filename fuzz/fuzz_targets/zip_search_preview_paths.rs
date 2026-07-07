#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultlink::{path_security, runtime};

fuzz_target!(|input: (String, String, String)| {
    let (base, child, extensions) = input;

    if let Ok(mut base_path) = path_security::validate_relative(&base) {
        if let Ok(child_path) = path_security::validate_relative(&child) {
            base_path.push(child_path);
            let joined = base_path.to_string_lossy().replace('\\', "/");
            let _ = path_security::validate_relative(&joined);
            assert!(!joined.contains('\0'));
        }
    }

    if let Ok(parsed) = runtime::parse_extension_list(&extensions) {
        for extension in parsed {
            assert!(!extension.is_empty());
            assert!(!extension.contains('/'));
            assert!(!extension.contains('\\'));
            assert!(!extension.contains('\0'));
            assert!(!extension.chars().any(char::is_control));
        }
    }
});
