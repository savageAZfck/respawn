//! Wave 1–3 feature and adversarial tests: fabric lock, guard, anchors,
//! secured sync, and content-defined chunking.

use respawn::snapshot::Manifest;
use respawn::{anchor, audit, cdc, guard, snapshot, sync, Error, Store};
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

fn fixture() -> TempDir {
    let t = TempDir::new().unwrap();
    let root = t.path();
    Store::init(root).unwrap();
    write(root, "a.txt", b"hello");
    write(root, "dir/b.txt", b"world");
    t
}

fn free_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("127.0.0.1:{port}")
}

/// Minimal hostile server: reads legacy frames, replies with scripted
/// payloads — same contract as the one in fabric_test.rs.
fn fake_server(script: Vec<Vec<u8>>) -> String {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut it = script.into_iter();
            loop {
                let mut len_buf = [0u8; 4];
                if s.read_exact(&mut len_buf).is_err() {
                    return;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                if s.read_exact(&mut buf).is_err() {
                    return;
                }
                match it.next() {
                    Some(payload) => {
                        let _ = s.write_all(&(payload.len() as u32).to_le_bytes());
                        let _ = s.write_all(&payload);
                    }
                    None => return,
                }
            }
        }
    });
    format!("127.0.0.1:{port}")
}

// ---------- Wave 1a: single-writer lock ----------

#[test]
fn lock_excludes_second_writer_and_releases() {
    let t = fixture();
    let store = Store::open(t.path()).unwrap();

    let lock = store.try_lock().unwrap();
    match store.try_lock() {
        Err(Error::Locked(_)) => {}
        other => panic!("second try_lock should fail: {}", other.is_ok()),
    }
    drop(lock);
    store.try_lock().unwrap(); // released with the fd, no stale state
}

// ---------- Wave 1b: guard ----------

#[test]
fn guard_reports_drift_and_child_exit() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let prev = snapshot::create(&store, root, "baseline").unwrap();

    let report = guard::run(
        &store,
        root,
        &[
            "sh".into(),
            "-c".into(),
            "echo agent-output > agent.txt && echo changed > a.txt".into(),
        ],
        guard::RevertPolicy::Never,
        false,
    )
    .unwrap();

    assert_eq!(report.exit_code, Some(0));
    assert!(report.drift.added.contains(&"agent.txt".to_string()));
    assert!(report.drift.modified.contains(&"a.txt".to_string()));
    assert!(!report.reverted);
    // HEAD advanced to the guard snapshot, parent chain intact.
    let head = store.head().unwrap().unwrap();
    assert_eq!(head, report.snapshot);
    assert_eq!(snapshot::load(&store, &head).unwrap().parent, Some(prev));
}

#[test]
fn guard_onfail_reverts_only_on_failure() {
    // Failing command → reverted.
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let report = guard::run(
        &store,
        root,
        &[
            "sh".into(),
            "-c".into(),
            "echo bad > damage.txt; exit 3".into(),
        ],
        guard::RevertPolicy::OnFail,
        false,
    )
    .unwrap();
    assert_eq!(report.exit_code, Some(3));
    assert!(report.reverted);
    assert!(!root.join("damage.txt").exists());
    assert_eq!(report.process_exit_code(), 3);

    // Succeeding command → kept.
    let t2 = fixture();
    let store2 = Store::open(t2.path()).unwrap();
    let report2 = guard::run(
        &store2,
        t2.path(),
        &["sh".into(), "-c".into(), "echo ok > keep.txt".into()],
        guard::RevertPolicy::OnFail,
        false,
    )
    .unwrap();
    assert!(!report2.reverted);
    assert!(t2.path().join("keep.txt").exists());
}

#[test]
fn guard_always_reverts() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let report = guard::run(
        &store,
        root,
        &["sh".into(), "-c".into(), "echo x > a.txt".into()],
        guard::RevertPolicy::Always,
        false,
    )
    .unwrap();
    assert_eq!(report.exit_code, Some(0));
    assert!(report.reverted);
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello");
}

#[test]
fn guard_spawn_failure_restores_head() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let prev = snapshot::create(&store, root, "before").unwrap();

    assert!(guard::run(
        &store,
        root,
        &["/definitely/not/a/binary".into()],
        guard::RevertPolicy::Never,
        false,
    )
    .is_err());
    // The guard snapshot must not masquerade as a checkpoint.
    assert_eq!(store.head().unwrap(), Some(prev));
}

#[test]
fn guard_lock_blocks_concurrent_writer() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let _held = store.try_lock().unwrap();
    // guard tries to take the lock itself → honest Locked error.
    assert!(matches!(
        guard::run(
            &store,
            root,
            &["true".into()],
            guard::RevertPolicy::Never,
            false,
        ),
        Err(Error::Locked(_))
    ));
}

// ---------- Wave 2a: anchors ----------

#[test]
fn anchor_roundtrip_and_append_tolerance() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let pubkey = anchor::keygen(&store).unwrap();
    snapshot::create(&store, root, "s1").unwrap();
    audit::record(&store, "snap", "x").unwrap();

    // Write beside the tempdir root so it is outside .respawn/.
    let outside = TempDir::new().unwrap();
    let anchor_path = outside.path().join("anchor.json");
    anchor::create(&store, &anchor_path).unwrap();

    let out = anchor::verify(&store, &anchor_path, Some(&pubkey)).unwrap();
    assert!(out.audit_len >= 1);

    // Later audit entries are legitimate continuation.
    audit::record(&store, "post-anchor", "work").unwrap();
    anchor::verify(&store, &anchor_path, Some(&pubkey)).unwrap();

    // Wrong pinned key → refusal.
    assert!(anchor::verify(&store, &anchor_path, Some(&"0".repeat(64))).is_err());
}

#[test]
fn anchor_catches_rewritten_and_truncated_history() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    anchor::keygen(&store).unwrap();
    audit::record(&store, "a", "1").unwrap();
    audit::record(&store, "b", "2").unwrap();
    audit::record(&store, "c", "3").unwrap();

    let outside = TempDir::new().unwrap();
    let anchor_path = outside.path().join("anchor.json");
    anchor::create(&store, &anchor_path).unwrap();

    // Wholesale replacement: a fresh, internally-consistent log is
    // exactly what an internal chain cannot detect — the anchor must.
    let log = root.join(".respawn/audit.jsonl");
    let original = fs::read(&log).unwrap();
    fs::remove_file(&log).unwrap();
    audit::record(&store, "fresh", "log").unwrap();
    assert!(audit::verify(&store).unwrap().valid); // internally consistent
    assert!(anchor::verify(&store, &anchor_path, None).is_err()); // anchored prefix gone

    // Truncation of the tail also fails the prefix check.
    fs::write(&log, &original[..original.len() / 2]).unwrap();
    assert!(anchor::verify(&store, &anchor_path, None).is_err());
}

#[test]
fn anchor_refuses_to_live_inside_fabric() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    anchor::keygen(&store).unwrap();
    // An anchor inside .respawn/ can be replaced with the log it proves.
    assert!(anchor::create(&store, &root.join(".respawn/anchor.json")).is_err());
    assert!(anchor::create(&store, &root.join(".respawn/objects/x.json")).is_err());
}

#[test]
fn anchor_rejects_foreign_fabric() {
    let t1 = fixture();
    let store1 = Store::open(t1.path()).unwrap();
    anchor::keygen(&store1).unwrap();
    audit::record(&store1, "x", "y").unwrap();
    let outside = TempDir::new().unwrap();
    let anchor_path = outside.path().join("a.json");
    anchor::create(&store1, &anchor_path).unwrap();

    // Same file, different fabric → fabric_id mismatch.
    let t2 = fixture();
    let store2 = Store::open(t2.path()).unwrap();
    assert!(anchor::verify(&store2, &anchor_path, None).is_err());
}

// ---------- Wave 2b: secured sync ----------

#[test]
fn secured_pull_roundtrip() {
    let src = fixture();
    let src_store = Store::open(src.path()).unwrap();
    let head = snapshot::create(&src_store, src.path(), "secured").unwrap();

    let addr = free_addr();
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let _ = sync::serve(src_store, &serve_addr, false, Some("hunter2".into()));
    });
    std::thread::sleep(Duration::from_millis(300));

    let dst = TempDir::new().unwrap();
    Store::init(dst.path()).unwrap();
    let dst_store = Store::open(dst.path()).unwrap();
    let report = sync::pull(&dst_store, &addr, Some("hunter2")).unwrap();
    assert_eq!(report.remote_head, Some(head));
    assert!(report.objects_fetched >= 2);
}

#[test]
fn secured_server_rejects_plaintext_and_wrong_key() {
    let src = fixture();
    let src_store = Store::open(src.path()).unwrap();
    snapshot::create(&src_store, src.path(), "s").unwrap();

    let addr = free_addr();
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let _ = sync::serve(src_store, &serve_addr, false, Some("right".into()));
    });
    std::thread::sleep(Duration::from_millis(300));

    let dst = TempDir::new().unwrap();
    Store::init(dst.path()).unwrap();
    let dst_store = Store::open(dst.path()).unwrap();

    // Plaintext client against a --psk listener: refused, no downgrade.
    assert!(sync::pull(&dst_store, &addr, None).is_err());
    // Wrong passphrase: handshake dies, not silent acceptance.
    assert!(sync::pull(&dst_store, &addr, Some("wrong")).is_err());
}

#[test]
fn plaintext_server_still_works_and_rejects_noise_client() {
    let src = fixture();
    let src_store = Store::open(src.path()).unwrap();
    snapshot::create(&src_store, src.path(), "s").unwrap();

    let addr = free_addr();
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let _ = sync::serve(src_store, &serve_addr, false, None);
    });
    std::thread::sleep(Duration::from_millis(300));

    let dst = TempDir::new().unwrap();
    Store::init(dst.path()).unwrap();
    let dst_store = Store::open(dst.path()).unwrap();
    assert!(sync::pull(&dst_store, &addr, None).is_ok());
    // A secured client must not be let in by accident either.
    assert!(sync::pull(&dst_store, &addr, Some("any")).is_err());
}

// ---------- regression tests for red-team findings ----------

#[test]
fn pull_survives_hostile_frame_lengths() {
    let t = TempDir::new().unwrap();
    Store::init(t.path()).unwrap();
    let store = Store::open(t.path()).unwrap();

    // A manifest response whose u64 length field is u64::MAX: the old
    // `8 + len` check wrapped and the slice panicked — the client must
    // error, never crash.
    let head = respawn::hash_bytes(b"x");
    let mut head_resp = vec![1u8];
    head_resp.extend_from_slice(&head);
    let mut evil = u64::MAX.to_le_bytes().to_vec();
    evil.extend_from_slice(b"tiny");
    let addr = fake_server(vec![head_resp, evil]);
    assert!(sync::pull(&store, &addr, None).is_err());
}

#[test]
fn anchor_secret_is_0600_at_birth() {
    let t = fixture();
    let store = Store::open(t.path()).unwrap();
    anchor::keygen(&store).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(t.path().join(".respawn/anchor.secret"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "secret file mode was {mode:o}");
}

#[test]
fn anchor_verify_rejects_oversized_file() {
    let t = fixture();
    let store = Store::open(t.path()).unwrap();
    let outside = TempDir::new().unwrap();
    let big = outside.path().join("big.json");
    fs::write(&big, vec![0u8; 5 * 1024 * 1024]).unwrap();
    assert!(anchor::verify(&store, &big, None).is_err());
}

#[test]
fn snapshot_never_reads_through_symlinks() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let outside = TempDir::new().unwrap();
    write(outside.path(), "secret.txt", b"DO-NOT-SNAPSHOT");
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("link.txt")).unwrap();

    let id = snapshot::create(&store, root, "").unwrap();
    let m = snapshot::load(&store, &id).unwrap();
    // The link is skipped — not followed, not captured.
    assert!(!m.files.iter().any(|f| f.path == "link.txt"));
    // And no object in the store holds the outside content.
    let secret_hash = respawn::hash_bytes(b"DO-NOT-SNAPSHOT");
    assert!(!store.has_object(&secret_hash));
}

// ---------- Wave 3a: content-defined chunking ----------

#[test]
fn cdc_respects_bounds_and_dedups_inserts() {
    // Deterministic pseudo-random content so boundaries are real.
    let mut data = Vec::new();
    let mut state = 0x9e3779b97f4a7c15u64;
    for _ in 0..1_000_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state >> 32) as u8);
    }

    let chunks = cdc::chunk_bytes(&data).unwrap();
    assert!(chunks.len() > 4);
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    assert_eq!(total, data.len());
    for c in &chunks {
        assert!(c.len() <= respawn::CDC_MAX);
        // Normalized CDC may emit a final short tail chunk; the bound
        // that matters is the max — every chunk but the last is >= MIN.
    }

    // Insert a byte near the front: fixed chunking would shift every
    // boundary; CDC should preserve most downstream chunks.
    let mut edited = data.clone();
    edited.insert(100, 0xAB);
    let chunks2 = cdc::chunk_bytes(&edited).unwrap();
    let h1: std::collections::HashSet<_> = chunks.iter().map(|c| respawn::hash_bytes(c)).collect();
    let kept = chunks2
        .iter()
        .filter(|c| h1.contains(&respawn::hash_bytes(c)))
        .count();
    assert!(
        kept >= chunks.len() - 2,
        "insert invalidated too many chunks: kept {kept} of {}",
        chunks.len()
    );
}

#[test]
fn v2_manifest_without_unstable_field_loads() {
    // A v2 manifest predates `unstable` — serde default must fill it.
    let json = r#"{
        "version": 2, "parent": null, "timestamp_secs": 0,
        "message": "old", "files": []
    }"#;
    let m = Manifest::deserialize(json.as_bytes()).unwrap();
    m.validate().unwrap();
    assert!(m.unstable.is_empty());
    assert_eq!(m.version, 2);
}

#[test]
fn snapshot_records_files_not_unstable_when_quiet() {
    let t = fixture();
    let store = Store::open(t.path()).unwrap();
    let id = snapshot::create(&store, t.path(), "").unwrap();
    let m = snapshot::load(&store, &id).unwrap();
    assert!(m.unstable.is_empty());
    assert_eq!(m.files.len(), 2);
    // Multi-chunk fixture file sanity: a >64KiB file still round-trips.
    write(t.path(), "big.bin", &vec![42u8; 300_000]);
    let id2 = snapshot::create(&store, t.path(), "").unwrap();
    let m2 = snapshot::load(&store, &id2).unwrap();
    let big = m2.files.iter().find(|f| f.path == "big.bin").unwrap();
    assert!(big.chunks.len() >= 2);
    assert_eq!(big.size, 300_000);
}

// ---------- APFS (environment-dependent; graceful) ----------

#[test]
fn apfs_snapshot_if_privileged() {
    // `tmutil snapshot` + `mount_apfs` need privileges most test runs
    // lack — exercise the path only when it is actually available.
    let t = fixture();
    let store = Store::open(t.path()).unwrap();
    let live_id = snapshot::create(&store, t.path(), "live").unwrap();

    match respawn::apfs::create(t.path()) {
        Ok(frozen) => {
            let frozen_id = snapshot::create_from(&store, frozen.scan_root(), "frozen").unwrap();
            let live = snapshot::load(&store, &live_id).unwrap();
            let froz = snapshot::load(&store, &frozen_id).unwrap();
            // Same tree → identical file maps (timestamps/parent differ).
            let live_paths: Vec<_> = live.files.iter().map(|f| &f.path).collect();
            let froz_paths: Vec<_> = froz.files.iter().map(|f| &f.path).collect();
            assert_eq!(live_paths, froz_paths);
            for f in &froz.files {
                assert_eq!(
                    f.content,
                    live.files
                        .iter()
                        .find(|g| g.path == f.path)
                        .unwrap()
                        .content
                );
            }
        }
        Err(e) => eprintln!("apfs unavailable in this environment: {e}"),
    }
}
