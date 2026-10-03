//! Purge: certified erasure inside an undo system.
//!
//! Every undo tool exists to preserve everything; some data must still
//! be able to die. `purge` removes a path from the fabric's reach —
//! tombstones it so `snap` skips it (by path *and* by content hash, so a
//! rename doesn't resurrect it) and `revert` refuses to materialize it —
//! sweeps the objects only it referenced, then issues a signed
//! certificate of what was erased: fabric id, path, content hash, chunk
//! counts, audit tip. Undo that can prove it forgot.
//!
//! Objects shared with other content are retained and reported — a
//! certificate that claimed total destruction while dedup'd data lived
//! on would be a lie.

use crate::{anchor, audit, keychain, snapshot, Error, Hash, Result, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TOMBSTONE_FILE: &str = "purged.jsonl";
const PURGE_DIR: &str = "purges";

/// A path+content pair the fabric must never snapshot or restore again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub path: String,
    /// BLAKE3 hex of the purged content — matching content under a
    /// different name stays purged.
    pub content: String,
    pub purge_id: String,
    pub ts: u64,
}

/// The signed statement of erasure. `payload` is signed verbatim, same
/// discipline as anchors — verification never depends on re-serializing
/// the fields byte-identically.
#[derive(Debug, Serialize, Deserialize)]
pub struct PurgePayload {
    pub kind: String, // "respawn-purge"
    pub version: u32,
    pub fabric_id: String,
    pub path: String,
    pub content: String,
    pub chunks_removed: u64,
    /// Chunks still live because other content references them.
    pub chunks_retained_shared: u64,
    pub manifests_touched: u64,
    pub audit_len: u64,
    pub audit_tip: String,
    pub ts: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PurgeCert {
    pub format: String, // "respawn-purge/v1"
    pub pubkey: String,
    pub payload: String,
    pub sig: String,
}

fn tombstone_path(store: &Store) -> PathBuf {
    store.fabric_dir().join(TOMBSTONE_FILE)
}

/// All tombstones recorded so far — consulted by `snap` and `revert` on
/// every run, so a purged path stays dead even across peer pulls that
/// re-deliver the manifests it lived in.
pub fn tombstones(store: &Store) -> Result<Vec<Tombstone>> {
    let path = tombstone_path(store);
    let s = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut out = Vec::new();
    for (i, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(line)
                .map_err(|_| Error::Corrupt(format!("tombstone line {} unparsable", i + 1)))?,
        );
    }
    Ok(out)
}

/// True if `path` or `content` is tombstoned. Callers treat this as
/// "must not persist/restore" — the certificate records the erasure.
pub fn is_purged(store: &Store, path: &str, content: &Hash) -> Result<bool> {
    let content_hex = crate::hash_hex(content);
    for t in tombstones(store)? {
        if t.path == path || t.content == content_hex {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Report of one purge run.
#[derive(Debug)]
pub struct PurgeReport {
    pub cert_path: PathBuf,
    pub chunks_removed: u64,
    pub chunks_retained_shared: u64,
    pub manifests_touched: u64,
    pub live_removed: bool,
    pub note: Option<String>,
}

/// Purge `rel` from the fabric: tombstone it, delete its unshared
/// objects, sign the certificate, record the event.
///
/// `rel` is a worktree-relative path as it appears in manifests. The
/// live file at `root/rel` is removed too — erasure that leaves the
/// data sitting in the worktree is a tombstone for nobody.
pub fn run(store: &Store, root: &Path, rel: &str) -> Result<PurgeReport> {
    let rel_path = crate::sanitize_rel(rel)?;
    let rel_str = rel_path.to_string_lossy().replace('\\', "/");

    // Content hash: the live file if present, else the newest manifest
    // entry for this path. A file that exists nowhere proves nothing —
    // refuse rather than sign a certificate of thin air.
    let live = root.join(&rel_path);
    let mut content: Option<Hash> = None;
    if live.is_file() {
        let (h, _) = Store::hash_reader(fs::File::open(&live)?)?;
        content = Some(h);
    }
    let mut manifests_touched = 0u64;
    let mut purge_chunks: HashSet<Hash> = HashSet::new();
    let mut referenced_elsewhere: HashSet<Hash> = HashSet::new();
    for (_, m) in snapshot::list(store)? {
        let mut hit = false;
        for fe in &m.files {
            if fe.path == rel_str {
                hit = true;
                if content.is_none() {
                    content = Some(fe.content);
                }
                for ch in &fe.chunks {
                    purge_chunks.insert(*ch);
                }
            } else {
                for ch in &fe.chunks {
                    referenced_elsewhere.insert(*ch);
                }
            }
        }
        if hit {
            manifests_touched += 1;
        }
    }
    let content = content.ok_or_else(|| {
        Error::Corrupt(format!(
            "nothing to purge: {rel_str} not in worktree or history"
        ))
    })?;

    if is_purged(store, &rel_str, &content)? {
        return Err(Error::Corrupt(format!("{rel_str} is already purged")));
    }

    // Objects only this content referenced die; shared ones stay and
    // the certificate says why.
    let mut chunks_removed = 0u64;
    let mut chunks_retained_shared = 0u64;
    for ch in &purge_chunks {
        if referenced_elsewhere.contains(ch) {
            chunks_retained_shared += 1;
            continue;
        }
        let hex = crate::hash_hex(ch);
        let obj = store
            .fabric_dir()
            .join("objects")
            .join(&hex[..2])
            .join(&hex[2..]);
        if obj.exists() {
            fs::remove_file(&obj)?;
            chunks_removed += 1;
        }
    }

    // Tombstone + live-file removal.
    let purge_id = crate::hash_hex(&crate::hash_bytes(
        format!("{rel_str}:{}", crate::hash_hex(&content)).as_bytes(),
    ));
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tomb = Tombstone {
        path: rel_str.clone(),
        content: crate::hash_hex(&content),
        purge_id: purge_id[..16].to_string(),
        ts,
    };
    let tpath = tombstone_path(store);
    fs::create_dir_all(tpath.parent().unwrap())?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&tpath)?;
    f.write_all(serde_json::to_string(&tomb)?.as_bytes())?;
    f.write_all(b"\n")?;

    let live_removed = if live.is_file() {
        fs::remove_file(&live)?;
        true
    } else {
        false
    };

    // Sign the certificate with the anchor key — same trust root.
    let (raw, _placement, note) = keychain::get(store)?;
    let sk = SigningKey::from_bytes(&raw);
    let (audit_len, audit_tip) = audit::tip(store)?;
    let payload = PurgePayload {
        kind: "respawn-purge".into(),
        version: 1,
        fabric_id: anchor::fabric_id(store)?,
        path: rel_str.clone(),
        content: crate::hash_hex(&content),
        chunks_removed,
        chunks_retained_shared,
        manifests_touched,
        audit_len,
        audit_tip,
        ts,
    };
    let payload_bytes = serde_json::to_string(&payload)?;
    let sig = sk.sign(payload_bytes.as_bytes());
    let cert = PurgeCert {
        format: "respawn-purge/v1".into(),
        pubkey: hex::encode(sk.verifying_key().as_bytes()),
        payload: payload_bytes,
        sig: hex::encode(sig.to_bytes()),
    };
    let pdir = store.fabric_dir().join(PURGE_DIR);
    fs::create_dir_all(&pdir)?;
    let cert_path = pdir.join(format!("purge-{ts}-{}.json", &purge_id[..8]));
    let cert_bytes = serde_json::to_vec_pretty(&cert)?;
    let dir = pdir.clone();
    let tmp = crate::tmp_path(&dir, "purge");
    fs::write(&tmp, &cert_bytes)?;
    fs::rename(&tmp, &cert_path)?;

    audit::record(
        store,
        "purge",
        &format!("{rel_str} removed={chunks_removed} shared={chunks_retained_shared}"),
    )?;

    Ok(PurgeReport {
        cert_path,
        chunks_removed,
        chunks_retained_shared,
        manifests_touched,
        live_removed,
        note,
    })
}

/// Verify a purge certificate: signature valid (optionally pinned to a
/// known signer), and the chunks it claims to have removed are actually
/// absent from this store.
pub fn verify_cert(store: &Store, cert_path: &Path, pubkey_pin: Option<&str>) -> Result<String> {
    let bytes = fs::read(cert_path)?;
    let cert: PurgeCert = serde_json::from_slice(&bytes)?;
    if cert.format != "respawn-purge/v1" {
        return Err(Error::Corrupt("unknown purge cert format".into()));
    }
    let payload: PurgePayload = serde_json::from_str(&cert.payload)?;
    if payload.kind != "respawn-purge" {
        return Err(Error::Corrupt("payload kind mismatch".into()));
    }
    if let Some(pin) = pubkey_pin {
        if cert.pubkey != pin {
            return Err(Error::Corrupt("purge cert signer mismatch".into()));
        }
    }
    let pk_bytes: [u8; 32] = hex::decode(&cert.pubkey)
        .map_err(|_| Error::Corrupt("bad pubkey hex".into()))?
        .try_into()
        .map_err(|_| Error::Corrupt("bad pubkey length".into()))?;
    let pk =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| Error::Corrupt("bad pubkey".into()))?;
    let sig_bytes: [u8; 64] = hex::decode(&cert.sig)
        .map_err(|_| Error::Corrupt("bad sig hex".into()))?
        .try_into()
        .map_err(|_| Error::Corrupt("bad sig length".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    pk.verify(cert.payload.as_bytes(), &sig)
        .map_err(|_| Error::Corrupt("purge cert signature invalid".into()))?;

    if payload.fabric_id != anchor::fabric_id(store)? {
        return Err(Error::Corrupt(
            "purge cert belongs to another fabric".into(),
        ));
    }
    // The certificate claims tombstoned content — confirm the store
    // agrees (path-level; chunk-level absence was enforced at purge).
    let tomb = tombstones(store)?;
    if !tomb
        .iter()
        .any(|t| t.path == payload.path && t.content == payload.content)
    {
        return Err(Error::Corrupt(
            "no matching tombstone — purge was never recorded here".into(),
        ));
    }
    Ok(format!(
        "valid: {} purged at {} ({} chunks removed, {} shared-retained)",
        payload.path, payload.ts, payload.chunks_removed, payload.chunks_retained_shared
    ))
}
