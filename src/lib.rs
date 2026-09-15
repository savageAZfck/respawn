//! respawn — a versioned fabric for filesystem state.
//!
//! Content-addressed snapshots of a directory tree, stored in `.respawn/`
//! under the worktree root. Reverting is a HEAD pointer swap plus atomic
//! per-file materialization; drift is a manifest diff; sync is object
//! replication between peers over the LAN. Every mutation is recorded in a
//! hash-chained audit log.

pub mod audit;
pub mod drift;
pub mod revert;
pub mod snapshot;
pub mod store;
pub mod sync;
pub mod watch;

pub use store::Store;

use std::io;

/// 256-bit content address.
pub type Hash = [u8; 32];

/// Directory inside the worktree that holds all fabric state.
pub const FABRIC_DIR: &str = ".respawn";

/// Fixed chunk size for file content. Content-defined chunking is a
/// possible future optimization; fixed chunks keep dedup predictable.
pub const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Corrupt(String),
    MissingObject(Hash),
    NotInitialized,
    BadHash(String),
    Sync(String),
    UnsafePath(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Corrupt(m) => write!(f, "corrupt state: {m}"),
            Error::MissingObject(h) => write!(f, "missing object {}", hex::encode(h)),
            Error::NotInitialized => {
                write!(f, "not a respawn worktree (run `respawn init`)")
            }
            Error::BadHash(m) => write!(f, "bad hash: {m}"),
            Error::Sync(m) => write!(f, "sync error: {m}"),
            Error::UnsafePath(p) => write!(f, "unsafe path in manifest: {p:?}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<walkdir::Error> for Error {
    fn from(e: walkdir::Error) -> Self {
        Error::Io(e.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Corrupt(format!("json: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Hash bytes with BLAKE3.
pub fn hash_bytes(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Parse a 64-char hex string into a Hash.
pub fn parse_hash(s: &str) -> Result<Hash> {
    let bytes = hex::decode(s).map_err(|_| Error::BadHash(s.to_string()))?;
    let arr: Hash = bytes
        .try_into()
        .map_err(|_| Error::BadHash(s.to_string()))?;
    Ok(arr)
}

/// Format a hash as lowercase hex.
pub fn hash_hex(h: &Hash) -> String {
    hex::encode(h)
}

/// Short hash prefix for display.
pub fn short(h: &Hash) -> String {
    hex::encode(&h[..6])
}

/// A relative path is only acceptable if every component is a plain
/// directory/file name — no root, no `..`, no `.`, no NUL or separators
/// that could escape the worktree or smuggle a host-absolute path.
pub fn sanitize_rel(p: &str) -> Result<std::path::PathBuf> {
    use std::path::Component;
    if p.is_empty() || p.len() > 1024 || p.contains('\0') || p.contains('\\') {
        return Err(Error::UnsafePath(p.to_string()));
    }
    let path = std::path::Path::new(p);
    if path.is_absolute() {
        return Err(Error::UnsafePath(p.to_string()));
    }
    for c in path.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(Error::UnsafePath(p.to_string()));
        }
    }
    Ok(path.to_path_buf())
}

/// True if `name` is exactly 64 lowercase hex chars — the on-disk shape
/// of object and manifest ids. Used to skip foreign files (`.tmp`,
/// editor droppings) inside store fan-out dirs.
pub fn is_hash_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Unique tmp filename inside `dir` — unpredictable enough that a
/// pre-planted file or concurrent writer cannot collide with it.
pub fn tmp_path(dir: &std::path::Path, tag: &str) -> std::path::PathBuf {
    let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    dir.join(format!(".tmp-{}-{n}-{tag}", std::process::id()))
}
