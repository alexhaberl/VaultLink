#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    if let Ok(path) = vaultlink::path_security::validate_relative(input) {
        assert!(!path.is_absolute());
        assert!(!path.components().any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))));
    }
});
