use state_fabric::{audit, drift, revert, snapshot, sync, Store};
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
    let r = drift::detect(root, &m).unwrap();
    assert!(r.clean(), "{:?}", r);

    // Modify, add, delete → all three buckets report.
    write(root, "a.txt", b"changed");
    write(root, "new.txt", b"new");
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    let r = drift::detect(root, &m).unwrap();
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
    let hex = state_fabric::hash_hex(&chunk);
    let obj = root
        .join(".state_fabric/objects")
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
    let p = root.join(".state_fabric/audit.jsonl");
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
        let _ = sync::serve(src_store, &serve_addr, false);
    });
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Fresh destination pulls everything.
    let dst = TempDir::new().unwrap();
    Store::init(dst.path()).unwrap();
    let dst_store = Store::open(dst.path()).unwrap();
    let report = sync::pull(&dst_store, &addr).unwrap();

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
