//! Snapshot graph: manifests of file trees.
//!
//! A manifest is a serialized (bincode) record of every file under the
//! worktree root: path, mode, size, mtime, content hash, and the ordered
//! chunk hashes the content is split into. The manifest bytes live in the
//! store; the snapshot id is the BLAKE3 of those bytes — so the id itself
//! is tamper-evident and replication-safe.

use crate::{Error, Hash, Result, Store, CHUNK_SIZE, FABRIC_DIR};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

pub const MANIFEST_VERSION: u32 = 2;

/// Hard caps applied when accepting a manifest — chiefly from `pull`,
/// where a hostile peer controls the bytes.
pub const MAX_MANIFEST_FILES: usize = 2_000_000;
pub const MAX_MANIFEST_CHUNKS: usize = 8_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path from worktree root, '/'-separated.
    pub path: String,
    /// Permission bits only (masked with 0o777 on apply — special bits
    /// like setuid are never honored).
    pub mode: u32,
    pub size: u64,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    /// BLAKE3 of the full file content.
    pub content: Hash,
    /// Ordered chunk hashes; file content = concat(chunk bytes).
    pub chunks: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub parent: Option<Hash>,
    pub timestamp_secs: u64,
    pub message: String,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }

    /// Manifests are JSON — inspectable with any tool. A size bound on
    /// the bytes keeps a hostile peer from driving decode allocations
    /// with a huge length prefix.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() > 256 * 1024 * 1024 {
            return Err(Error::Corrupt("manifest exceeds size cap".into()));
        }
        serde_json::from_slice(data).map_err(Error::from)
    }

    /// Reject manifests that could not have been produced by `create`:
    /// wrong version, unsafe paths, or absurd counts. Called on every
    /// load and again before `revert` writes anything — a manifest that
    /// arrived over the wire is attacker-controlled bytes.
    pub fn validate(&self) -> Result<()> {
        if self.version != MANIFEST_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported manifest version {}",
                self.version
            )));
        }
        if self.files.len() > MAX_MANIFEST_FILES {
            return Err(Error::Corrupt("manifest exceeds file count cap".into()));
        }
        let mut total_chunks = 0usize;
        for f in &self.files {
            crate::sanitize_rel(&f.path)?;
            total_chunks += f.chunks.len();
            if total_chunks > MAX_MANIFEST_CHUNKS {
                return Err(Error::Corrupt("manifest exceeds chunk count cap".into()));
            }
            if f.chunks.is_empty() && f.size > 0 {
                return Err(Error::Corrupt(format!(
                    "non-empty file with no chunks: {}",
                    f.path
                )));
            }
        }
        Ok(())
    }
}

/// Load a manifest by snapshot id. Validates before returning — the
/// caller can trust paths are safe to join under the worktree root.
pub fn load(store: &Store, id: &Hash) -> Result<Manifest> {
    let bytes = store.get_manifest_bytes(id)?;
    let m = Manifest::deserialize(&bytes)?;
    m.validate()?;
    Ok(m)
}

/// Resolve a snapshot reference: full hex, unique hex prefix, or "head".
pub fn resolve(store: &Store, reference: &str) -> Result<Hash> {
    if reference == "head" || reference == "HEAD" {
        return store
            .head()?
            .ok_or_else(|| Error::Corrupt("no HEAD snapshot".into()));
    }
    if reference.len() == 64 {
        return crate::parse_hash(reference);
    }
    // Prefix search over manifests dir.
    let prefix = reference.to_lowercase();
    if prefix.len() < 4 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadHash(reference.to_string()));
    }
    let mut hits = Vec::new();
    let mdir = store.fabric_dir().join("manifests");
    if mdir.is_dir() {
        for fan in fs::read_dir(&mdir)? {
            let fan = fan?;
            if !fan.file_type()?.is_dir() {
                continue;
            }
            let fan_hex = fan.file_name().to_string_lossy().to_string();
            for e in fs::read_dir(fan.path())? {
                let e = e?;
                let full = format!("{}{}", fan_hex, e.file_name().to_string_lossy());
                if full.starts_with(&prefix) && crate::is_hash_name(&full) {
                    hits.push(crate::parse_hash(&full)?);
                }
            }
        }
    }
    match hits.len() {
        0 => Err(Error::BadHash(format!("no snapshot matches '{reference}'"))),
        1 => Ok(hits[0]),
        _ => Err(Error::BadHash(format!("ambiguous prefix '{reference}'"))),
    }
}

/// Should this path be excluded from snapshots?
fn excluded(rel: &Path) -> bool {
    rel.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == FABRIC_DIR || s == ".git" || s == ".DS_Store"
    })
}

/// Read `.fabricignore` patterns (one glob-ish substring per line, `#`
/// comments allowed). Matching is substring-on-path for v0.1 — simple and
/// predictable, documented as such.
fn ignore_patterns(root: &Path) -> Vec<String> {
    fs::read_to_string(root.join(".fabricignore"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Chunk a file into the store, returning (content_hash, chunk_hashes, size).
fn chunk_file(store: &Store, path: &Path) -> Result<(Hash, Vec<Hash>, u64)> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        chunks.push(store.put_object(&buf[..n])?);
        size += n as u64;
    }
    Ok((*hasher.finalize().as_bytes(), chunks, size))
}

/// Walk the worktree and snapshot it. Returns the new snapshot id.
pub fn create(store: &Store, root: &Path, message: &str) -> Result<Hash> {
    let patterns = ignore_patterns(root);
    let mut files = Vec::new();

    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(root).unwrap().to_path_buf();
        if excluded(&rel) {
            continue;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if patterns.iter().any(|p| rel_str.contains(p.as_str())) {
            continue;
        }
        crate::sanitize_rel(&rel_str)?;
        let meta = entry.metadata()?;
        let (content, chunks, size) = chunk_file(store, entry.path())?;
        let (mtime_secs, mtime_nanos) = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (d.as_secs(), d.subsec_nanos()))
            .unwrap_or((0, 0));
        let mode = unix_mode(&meta);
        files.push(FileEntry {
            path: rel_str,
            mode,
            size,
            mtime_secs,
            mtime_nanos,
            content,
            chunks,
        });
    }

    let manifest = Manifest {
        version: MANIFEST_VERSION,
        parent: store.head()?,
        timestamp_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        message: message.to_string(),
        files,
    };
    let bytes = manifest.serialize()?;
    let id = store.put_manifest(&bytes)?;
    store.set_head(Some(&id))?;
    Ok(id)
}

/// Enumerate snapshot ids by walking HEAD's parent chain, then any
/// manifests not reachable from HEAD (e.g. pulled from a peer).
pub fn list(store: &Store) -> Result<Vec<(Hash, Manifest)>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    let mut cur = store.head()?;
    while let Some(id) = cur {
        if !seen.insert(id) {
            break; // cycle guard
        }
        let m = load(store, &id)?;
        cur = m.parent;
        out.push((id, m));
    }

    // Orphans (peer-pulled manifests whose chain we may not fully have).
    let mdir = store.fabric_dir().join("manifests");
    if mdir.is_dir() {
        for fan in fs::read_dir(&mdir)? {
            let fan = fan?;
            if !fan.file_type()?.is_dir() {
                continue;
            }
            let fan_hex = fan.file_name().to_string_lossy().to_string();
            for e in fs::read_dir(fan.path())? {
                let e = e?;
                let full = format!("{}{}", fan_hex, e.file_name().to_string_lossy());
                if !crate::is_hash_name(&full) {
                    continue;
                }
                let id = crate::parse_hash(&full)?;
                if seen.insert(id) {
                    if let Ok(m) = load(store, &id) {
                        out.push((id, m));
                    }
                }
            }
        }
    }

    out.sort_by_key(|e| std::cmp::Reverse(e.1.timestamp_secs));
    Ok(out)
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o777
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata) -> u32 {
    0o644
}

/// Files in `a` that differ from `b`: (added, modified, deleted).
/// `a` and `b` are manifests; diff is computed b→a (a is "newer").
pub fn diff_manifests(a: &Manifest, b: &Manifest) -> (Vec<String>, Vec<String>, Vec<String>) {
    let amap: std::collections::HashMap<&str, &FileEntry> =
        a.files.iter().map(|f| (f.path.as_str(), f)).collect();
    let bmap: std::collections::HashMap<&str, &FileEntry> =
        b.files.iter().map(|f| (f.path.as_str(), f)).collect();

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    for (p, fa) in &amap {
        match bmap.get(p) {
            None => added.push(p.to_string()),
            Some(fb) if fb.content != fa.content => modified.push(p.to_string()),
            _ => {}
        }
    }
    for p in bmap.keys() {
        if !amap.contains_key(p) {
            deleted.push(p.to_string());
        }
    }
    added.sort();
    modified.sort();
    deleted.sort();
    (added, modified, deleted)
}
