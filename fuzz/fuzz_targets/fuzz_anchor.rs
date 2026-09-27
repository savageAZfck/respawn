#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile anchor documents: JSON shape, hex decoders, ed25519 verify,
// payload field validation — every stage must Err, never panic.
fuzz_target!(|data: &[u8]| {
    let _ = respawned::anchor::verify_detached_bytes(data);
});
