#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    vaultlink::fuzzing::check_directory_cursor(input);
});
