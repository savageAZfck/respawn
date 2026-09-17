#![no_main]
use libfuzzer_sys::fuzz_target;

// Content-defined chunking on adversarial byte patterns: all-same,
// all-random, boundary-hugging sizes. Slicing must stay in bounds.
fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    if let Ok(chunks) = respawn::cdc::chunk_bytes(data) {
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len(), "chunk lengths must cover input");
    }
});
