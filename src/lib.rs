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
