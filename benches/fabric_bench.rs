use criterion::{criterion_group, criterion_main, Criterion};
use respawn::{drift, snapshot, Store};
use std::fs;
use tempfile::TempDir;

fn make_tree(n_files: usize, file_size: usize) -> TempDir {
    let t = TempDir::new().unwrap();
    Store::init(t.path()).unwrap();
    for i in 0..n_files {
        let p = t.path().join(format!("dir{}/file{}.bin", i % 20, i));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        // Semi-random content so compression doesn't trivially win.
        let data: Vec<u8> = (0..file_size).map(|b| (b * 31 + i) as u8).collect();
        fs::write(p, data).unwrap();
    }
    t
}

fn bench_snapshot(c: &mut Criterion) {
    let t = make_tree(200, 16 * 1024); // 200 files × 16 KiB
    let store = Store::open(t.path()).unwrap();
    c.bench_function("snapshot 200×16KiB", |b| {
        b.iter(|| snapshot::create(&store, t.path(), "bench").unwrap())
    });
}

fn bench_drift_clean(c: &mut Criterion) {
    let t = make_tree(200, 16 * 1024);
    let store = Store::open(t.path()).unwrap();
    snapshot::create(&store, t.path(), "bench").unwrap();
    let m = snapshot::load(&store, &store.head().unwrap().unwrap()).unwrap();
    c.bench_function("drift clean 200 files", |b| {
        b.iter(|| drift::detect(t.path(), &m, false).unwrap())
    });
}

fn bench_drift_dirty(c: &mut Criterion) {
    let t = make_tree(200, 16 * 1024);
    let store = Store::open(t.path()).unwrap();
    snapshot::create(&store, t.path(), "bench").unwrap();
    // Touch 10% of files — forces rehash of those.
    for i in 0..20 {
        fs::write(
            t.path().join(format!("dir{}/file{}.bin", i % 20, i)),
            vec![9u8; 16 * 1024],
        )
        .unwrap();
    }
    let m = snapshot::load(&store, &store.head().unwrap().unwrap()).unwrap();
    c.bench_function("drift 10% dirty 200 files", |b| {
        b.iter(|| drift::detect(t.path(), &m, false).unwrap())
    });
}

fn bench_chunk_throughput(c: &mut Criterion) {
    let t = TempDir::new().unwrap();
    Store::init(t.path()).unwrap();
    let store = Store::open(t.path()).unwrap();
    let data = vec![0xabu8; 64 * 1024];
    c.bench_function("store put 64KiB chunk", |b| {
        b.iter(|| store.put_object(&data).unwrap())
    });
}

criterion_group!(
    benches,
    bench_snapshot,
    bench_drift_clean,
    bench_drift_dirty,
    bench_chunk_throughput
);
criterion_main!(benches);
