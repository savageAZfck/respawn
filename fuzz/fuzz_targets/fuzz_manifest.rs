#![no_main]
use libfuzzer_sys::fuzz_target;
use respawn::snapshot::Manifest;

// Manifests cross the wire — a peer's manifest is attacker bytes.
// deserialize caps size; validate must reject anything unusable.
fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Manifest::deserialize(data) {
        let _ = m.validate();
    }
});
