#![no_main]
use libfuzzer_sys::fuzz_target;
use vaultlink::{fuzzing, path_security};

fuzz_target!(|input: &str| {
    if let Ok(name) = path_security::safe_filename(input) {
        assert!(!name.is_empty());
        assert!(name.len() <= 255);
        assert!(!name.contains(['/', '\\', '\0']));
        assert!(!name.chars().any(char::is_control));
    }

    let private = fuzzing::is_private_admin_filename(input);
    match path_security::safe_admin_filename(input) {
        Ok(name) => {
            assert!(path_security::safe_filename(name).is_ok());
            assert!(!private);
        }
        Err(_) if path_security::safe_filename(input).is_ok() => assert!(private),
        Err(_) => {}
    }
});
