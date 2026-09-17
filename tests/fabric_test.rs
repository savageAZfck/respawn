use respawn::{audit, drift, revert, snapshot, sync, Store};
use std::fs;
use std::net::TcpListener;
use std::path::Path;
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
    write(root, "dir/deep/c.bin", &[7u8; 200_000]); // multi-chunk file
    t
}

#[test]
fn snapshot_and_drift() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();

    let id = snapshot::create(&store, root, "first").unwrap();
    assert_eq!(store.head().unwrap(), Some(id));

    let m = snapshot::load(&store, &id).unwrap();
    assert_eq!(m.files.len(), 3);
    assert!(m.parent.is_none());

    // Clean tree → no drift.
    let r = drift::detect(root, &m, false).unwrap();
    assert!(r.clean(), "{:?}", r);

    // Modify, add, delete → all three buckets report.
    write(root, "a.txt", b"changed");
    write(root, "new.txt", b"new");
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    let r = drift::detect(root, &m, false).unwrap();
    assert_eq!(r.added, vec!["new.txt"]);
    assert_eq!(r.modified, vec!["a.txt"]);
    assert_eq!(r.deleted, vec!["dir/b.txt"]);
}

#[test]
fn revert_restores_exact_state() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();

    let v1 = snapshot::create(&store, root, "v1").unwrap();
    write(root, "a.txt", b"v2 content");
    write(root, "extra.txt", b"extra");
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    let v2 = snapshot::create(&store, root, "v2").unwrap();

    // Refused without --force when dirty.
    write(root, "a.txt", b"dirty");
    let m1 = snapshot::load(&store, &v1).unwrap();
    let (_, applied) = revert::check_then_apply(&store, root, &m1, false, false).unwrap();
    assert!(applied.is_none());

    // Forced revert to v1.
    let (_, applied) = revert::check_then_apply(&store, root, &m1, false, true).unwrap();
    let r = applied.unwrap();
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(root.join("dir/b.txt")).unwrap(), b"world");
    assert!(!root.join("extra.txt").exists()); // removed: not in v1
    assert!(r.restored.contains(&"a.txt".to_string()));
    assert!(r.removed.contains(&"extra.txt".to_string()));
    assert_eq!(store.head().unwrap(), Some(v2)); // head unchanged until caller sets it
}

#[test]
fn revert_keep_extra() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let v1 = snapshot::create(&store, root, "v1").unwrap();
    write(root, "keepme.txt", b"keep");
    let m1 = snapshot::load(&store, &v1).unwrap();
    let r = revert::apply(&store, root, &m1, true).unwrap();
    assert!(root.join("keepme.txt").exists());
    assert!(r.skipped_extra.contains(&"keepme.txt".to_string()));
}

#[test]
fn multi_chunk_file_roundtrip() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    snapshot::create(&store, root, "").unwrap();
    fs::remove_file(root.join("dir/deep/c.bin")).unwrap();
    let head = store.head().unwrap().unwrap();
    let m = snapshot::load(&store, &head).unwrap();
    revert::apply(&store, root, &m, false).unwrap();
    assert_eq!(
        fs::read(root.join("dir/deep/c.bin")).unwrap(),
        vec![7u8; 200_000]
    );
}

#[test]
fn tampered_object_detected() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    snapshot::create(&store, root, "").unwrap();
    let head = store.head().unwrap().unwrap();
    let m = snapshot::load(&store, &head).unwrap();
    let chunk = m.files.iter().find(|f| f.path == "a.txt").unwrap().chunks[0];

    // Corrupt the stored object on disk.
    let hex = respawn::hash_hex(&chunk);
    let obj = root
        .join(".respawn/objects")
        .join(&hex[..2])
        .join(&hex[2..]);
    let mut raw = fs::read(&obj).unwrap();
    raw[0] ^= 0xff;
    fs::write(&obj, raw).unwrap();

    // Read path verifies → error, not bad data.
    assert!(store.get_object(&chunk).is_err());
}

#[test]
fn audit_chain_detects_tamper() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    audit::record(&store, "init", "test").unwrap();
    audit::record(&store, "snap", "abc").unwrap();
    let r = audit::verify(&store).unwrap();
    assert!(r.valid && r.entries == 2);

    // Edit a line → chain breaks.
    let p = root.join(".respawn/audit.jsonl");
    let content = fs::read_to_string(&p).unwrap();
    let tampered = content.replace("\"snap\"", "\"span\"");
    fs::write(&p, tampered).unwrap();
    let r = audit::verify(&store).unwrap();
    assert!(!r.valid);
}

#[test]
fn sync_pull_replicates_objects() {
    // Source fabric with content.
    let src = fixture();
    let src_store = Store::open(src.path()).unwrap();
    let head = snapshot::create(&src_store, src.path(), "src v1").unwrap();

    // Serve on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let _ = sync::serve(src_store, &serve_addr, false, None);
    });
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Fresh destination pulls everything.
    let dst = TempDir::new().unwrap();
    Store::init(dst.path()).unwrap();
    let dst_store = Store::open(dst.path()).unwrap();
    let report = sync::pull(&dst_store, &addr, None).unwrap();

    assert_eq!(report.remote_head, Some(head));
    assert!(report.manifests_fetched >= 1);
    assert!(report.objects_fetched >= 3);

    // Destination can materialize the remote snapshot locally.
    let m = snapshot::load(&dst_store, &head).unwrap();
    write(dst.path(), "seed.txt", b"seed"); // something to overwrite is fine
    let r = revert::apply(&dst_store, dst.path(), &m, false).unwrap();
    assert!(!r.restored.is_empty());
    assert_eq!(fs::read(dst.path().join("a.txt")).unwrap(), b"hello");
    assert_eq!(
        fs::read(dst.path().join("dir/deep/c.bin")).unwrap(),
        vec![7u8; 200_000]
    );
}

// ---------- adversarial tests ----------

use respawn::snapshot::{FileEntry, Manifest};
use std::io::{Read, Write};

fn manifest_with(path: &str, mode: u32) -> Manifest {
    Manifest {
        version: respawn::snapshot::MANIFEST_VERSION,
        parent: None,
        timestamp_secs: 0,
        message: String::new(),
        files: vec![FileEntry {
            path: path.to_string(),
            mode,
            size: 5,
            mtime_secs: 0,
            mtime_nanos: 0,
            content: respawn::hash_bytes(b"hello"),
            chunks: vec![],
        }],
        unstable: Vec::new(),
    }
}

/// Minimal hostile server: reads frames, replies with scripted payloads.
fn fake_server(script: Vec<Vec<u8>>) -> String {
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

fn len_frame(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

#[test]
fn manifest_traversal_rejected() {
    for bad in [
        "../escape.txt",
        "../../etc/x",
        "/abs/x",
        "a/../../b",
        "a/./b",
        "",
    ] {
        let m = manifest_with(bad, 0o644);
        assert!(m.validate().is_err(), "accepted {bad:?}");
    }

    // Even if a bad manifest reaches the store (e.g. written directly),
    // load() and apply() both refuse it.
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let m = manifest_with("../escape.txt", 0o644);
    let bytes = m.serialize().unwrap();
    let id = store.put_manifest(&bytes).unwrap();
    assert!(snapshot::load(&store, &id).is_err());
    assert!(revert::apply(&store, root, &m, false).is_err());
    assert!(!root.parent().unwrap().join("escape.txt").exists());
}

#[test]
fn manifest_setuid_mode_stripped() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();

    let chunk = store.put_object(b"hello").unwrap();
    let mut m = manifest_with("evil.sh", 0o4777); // setuid + rwxrwxrwx
    m.files[0].chunks = vec![chunk];
    revert::apply(&store, root, &m, false).unwrap();

    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(root.join("evil.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7000, 0, "special bits propagated: {mode:o}");
}

#[test]
fn revert_replaces_symlink_not_target() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let outside = TempDir::new().unwrap();
    write(outside.path(), "victim.txt", b"SECRET");

    let id = snapshot::create(&store, root, "").unwrap();
    fs::remove_file(root.join("a.txt")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("victim.txt"), root.join("a.txt")).unwrap();

    let m = snapshot::load(&store, &id).unwrap();
    revert::apply(&store, root, &m, false).unwrap();
    // The link was replaced by the snapshotted file; the target is untouched.
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello");
    assert_eq!(
        fs::read(outside.path().join("victim.txt")).unwrap(),
        b"SECRET"
    );
}

#[test]
fn revert_blocks_symlink_ancestor() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let outside = TempDir::new().unwrap();

    // Manifest legitimately wants to write under dir/ — but dir is now
    // a symlink out of the worktree.
    let chunk = store.put_object(b"payload").unwrap();
    let mut m = manifest_with("dir/pwned.txt", 0o644);
    m.files[0].chunks = vec![chunk];
    m.files[0].content = respawn::hash_bytes(b"payload");
    fs::remove_dir_all(root.join("dir")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("dir")).unwrap();

    assert!(revert::apply(&store, root, &m, false).is_err());
    assert!(!outside.path().join("pwned.txt").exists());
}

#[test]
fn pull_short_frames_error_not_panic() {
    let t = TempDir::new().unwrap();
    Store::init(t.path()).unwrap();
    let store = Store::open(t.path()).unwrap();

    // Truncated HEAD response.
    let addr = fake_server(vec![vec![1u8, 0xAA]]); // 2 bytes, need 33
    assert!(sync::pull(&store, &addr, None).is_err());

    // Valid HEAD, then a 3-byte manifest response.
    let head = respawn::hash_bytes(b"x");
    let mut head_resp = vec![1u8];
    head_resp.extend_from_slice(&head);
    let addr = fake_server(vec![head_resp, vec![0, 1, 2]]);
    assert!(sync::pull(&store, &addr, None).is_err());
}

#[test]
fn pull_rejects_traversal_manifest_over_wire() {
    let t = TempDir::new().unwrap();
    Store::init(t.path()).unwrap();
    let store = Store::open(t.path()).unwrap();

    let evil = manifest_with("../owned.txt", 0o644);
    let bytes = evil.serialize().unwrap();
    let id = respawn::hash_bytes(&bytes);
    let mut head_resp = vec![1u8];
    head_resp.extend_from_slice(&id);
    let addr = fake_server(vec![head_resp, len_frame(&bytes)]);
    assert!(sync::pull(&store, &addr, None).is_err());
}

#[test]
fn mtime_forgery_caught_by_full_scan() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let id = snapshot::create(&store, root, "").unwrap();
    let m = snapshot::load(&store, &id).unwrap();
    let fe = m.files.iter().find(|f| f.path == "a.txt").unwrap();

    // Attacker modifies content but restores size+mtime exactly.
    write(root, "a.txt", b"FORGE");
    filetime::set_file_mtime(
        root.join("a.txt"),
        filetime::FileTime::from_unix_time(fe.mtime_secs as i64, fe.mtime_nanos),
    )
    .unwrap();

    assert!(drift::detect(root, &m, false).unwrap().clean());
    let r = drift::detect(root, &m, true).unwrap();
    assert_eq!(r.modified, vec!["a.txt"]);
}

#[test]
fn junk_files_dont_break_store_scans() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let id = snapshot::create(&store, root, "").unwrap();

    // Drop foreign files into the fan-out dirs.
    let hex = respawn::hash_hex(&id);
    fs::write(
        root.join(".respawn/manifests").join(&hex[..2]).join("junk"),
        b"x",
    )
    .unwrap();
    fs::write(root.join(".respawn/objects/zz"), b"x").unwrap();
    fs::create_dir_all(root.join(".respawn/objects/notahex")).unwrap();

    assert_eq!(
        snapshot::resolve(&store, &respawn::hash_hex(&id)).unwrap(),
        id
    );
    assert!(snapshot::list(&store)
        .unwrap()
        .iter()
        .any(|(i, _)| *i == id));
}

#[test]
fn manifest_diff() {
    let t = fixture();
    let root = t.path();
    let store = Store::open(root).unwrap();
    let v1 = snapshot::create(&store, root, "v1").unwrap();
    write(root, "a.txt", b"changed");
    write(root, "added.txt", b"x");
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    let v2 = snapshot::create(&store, root, "v2").unwrap();

    let m1 = snapshot::load(&store, &v1).unwrap();
    let m2 = snapshot::load(&store, &v2).unwrap();
    assert_eq!(m2.parent, Some(v1));
    let (added, modified, deleted) = snapshot::diff_manifests(&m2, &m1);
    assert_eq!(added, vec!["added.txt"]);
    assert_eq!(modified, vec!["a.txt"]);
    assert_eq!(deleted, vec!["dir/b.txt"]);
}
