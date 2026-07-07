#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, u64)| {
    if let Ok((start, end)) = vaultlink::range::parse_byte_range(input.0, input.1) {
        assert!(input.1 > 0);
        assert!(start <= end);
        assert!(end < input.1);
    }
});
