#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    if let Ok(name) = vaultlink::path_security::safe_filename(input) {
        assert!(!name.is_empty());
        assert!(!name.contains(['/', '\\', '\0']));
        assert!(!name.chars().any(char::is_control));
    }
});
