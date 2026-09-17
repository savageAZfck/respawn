#![no_main]
use libfuzzer_sys::fuzz_target;
use respawn::Store;
use std::sync::OnceLock;

// Corrupt/truncated zstd blobs on disk: decompression is bounded, and
// the hash check runs after — any outcome except a panic is legal.
fn store() -> &'static (Store, std::path::PathBuf) {
    static S: OnceLock<(Store, std::path::PathBuf)> = OnceLock::new();
    S.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("respawn-fuzz-obj-{}", std::process::id()));
        let _ = Store::init(&d);
        (Store::open(&d).unwrap(), d)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 * 1024 {
        return;
    }
    let (s, dir) = store();
    let h = [0xABu8; 32];
    let obj = dir.join(".respawn/objects/ab").join("ab".repeat(31));
    std::fs::create_dir_all(obj.parent().unwrap()).unwrap();
    if std::fs::write(&obj, data).is_err() {
        return;
    }
    let _ = s.get_object(&h);
});
