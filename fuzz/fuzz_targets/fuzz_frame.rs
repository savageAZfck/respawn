#![no_main]
use libfuzzer_sys::fuzz_target;
use respawn::Store;
use std::sync::OnceLock;

// The sync request parser against a real (empty) store: opcode
// dispatch, HAVE-list walking, per-op length guards.
fn store() -> &'static Store {
    static S: OnceLock<Store> = OnceLock::new();
    S.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("respawn-fuzz-{}", std::process::id()));
        let _ = Store::init(&d);
        Store::open(&d).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = respawn::sync::respond_frame(store(), data);
});
