#![no_main]
use libfuzzer_sys::fuzz_target;
use respawn::{audit, Store};
use std::sync::OnceLock;

// The audit log is attacker-writable in the threat model (a hostile
// process with fs access). verify/tip must never panic on garbage,
// truncation, or mid-line tears.
fn store() -> &'static (Store, std::path::PathBuf) {
    static S: OnceLock<(Store, std::path::PathBuf)> = OnceLock::new();
    S.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("respawn-fuzz-audit-{}", std::process::id()));
        let _ = Store::init(&d);
        (Store::open(&d).unwrap(), d)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_000_000 {
        return;
    }
    let (s, dir) = store();
    let log = dir.join(".respawn/audit.jsonl");
    if std::fs::write(&log, data).is_err() {
        return;
    }
    let _ = audit::verify(s);
    if let Ok((len, tip)) = audit::tip(s) {
        let _ = audit::tip_is_prefix(s, len, &tip);
        // And the off-by-one neighborhood — prefix checks must not
        // panic on len-1 or garbage tips either.
        let _ = audit::tip_is_prefix(s, len.saturating_sub(1), "deadbeef");
    }
});
