//! Anchors: signed checkpoints of fabric state, held *outside* the
//! fabric they describe.
//!
//! The audit chain proves internal consistency, not continuity — an
//! attacker with write access to `.respawn/` can replace the whole log
//! with a fresh, self-consistent one. An anchor closes that: a signed
//! statement of (fabric_id, HEAD, audit length, audit tip) written to a
//! path the operator chooses — another machine, a git repo, an object
//! store. `anchor verify` later confirms the signature *and* that the
//! anchored tip is still a valid prefix of the live log, which catches
//! truncation, splicing, and wholesale replacement.
//!
//! The signing key lives at `.respawn/anchor.secret` (mode 0600). The
//! pubkey is printed once at `anchor keygen` — record it. `verify`
//! checks the signer identity so a swapped key produces a swapped key,
//! not a passed check.

use crate::{audit, Error, Result, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET_FILE: &str = "anchor.secret";
const FABRIC_ID_FILE: &str = "fabric_id";
/// BLAKE3 hex of the most recently minted anchor file — the link the
/// next anchor signs. Anchors form a chain: verify pairwise and a
/// deleted, spliced, or substituted anchor file breaks the sequence.
const LAST_ANCHOR_FILE: &str = "last_anchor";
const ANCHOR_VERSION: u32 = 1;

/// Canonical signed statement. Serialized into `payload` inside the
/// anchor file — the signature covers the payload *string*, so
/// verification never depends on re-serialization byte-compatibility.
#[derive(Debug, Serialize, Deserialize)]
struct AnchorPayload {
    #[serde(rename = "type")]
    kind: String, // "respawn-anchor"
    version: u32,
    fabric_id: String,
    /// Number of audit entries the anchor covers — also the anchor seq.
    audit_len: u64,
    /// Hash of the last covered audit entry; empty when the log was empty.
    audit_tip: String,
    /// HEAD snapshot at anchor time (hex), or null.
    head: Option<String>,
    /// BLAKE3 of the previous anchor *file* (the whole signed document,
    /// signature included). None on the first anchor, and absent in
    /// anchors written before chaining existed — `serde(default)` keeps
    /// those readable.
    #[serde(default)]
    prev_anchor: Option<String>,
    ts: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnchorFile {
    format: String, // "respawn-anchor/v1"
    pubkey: String,
    payload: String,
    sig: String,
}

fn secret_path(store: &Store) -> PathBuf {
    store.fabric_dir().join(SECRET_FILE)
}

fn fabric_id_path(store: &Store) -> PathBuf {
    store.fabric_dir().join(FABRIC_ID_FILE)
}

fn random_hex32() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    Ok(hex::encode(b))
}

/// Fabric identity: a random id minted at init (or lazily on first
/// anchor use for fabrics created before anchors existed). Anchors are
/// bound to it, so a checkpoint from one fabric cannot be replayed
/// against another.
pub fn fabric_id(store: &Store) -> Result<String> {
    let path = fabric_id_path(store);
    match fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = random_hex32()?;
            atomic_write(&path, id.as_bytes())?;
            Ok(id)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = crate::tmp_path(dir, "anchor");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Write the signing key atomically AND with mode 0600 from birth —
/// a create-then-chmod sequence leaves a window where the key file is
/// readable to other users on the machine.
#[cfg(unix)]
fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = crate::tmp_path(dir, "secret");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data)
}

/// Generate the anchor signing key. Refuses to overwrite — a swapped
/// key is indistinguishable from an attacker swapping keys unless the
/// original pubkey was recorded off-fabric, so clobbering is never
/// done silently.
pub fn keygen(store: &Store) -> Result<String> {
    let path = secret_path(store);
    if path.exists() {
        return Err(Error::Corrupt(format!(
            "anchor key already exists at {}",
            path.display()
        )));
    }
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    let sk = SigningKey::from_bytes(&raw);
    write_secret(&path, hex::encode(raw).as_bytes())?;
    let _ = fabric_id(store)?; // ensure the identity exists alongside the key
    Ok(hex::encode(sk.verifying_key().as_bytes()))
}

fn load_key(store: &Store) -> Result<SigningKey> {
    let path = secret_path(store);
    let s = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Corrupt("no anchor key — run `respawn anchor keygen`".into())
        } else {
            Error::Io(e)
        }
    })?;
    let raw =
        hex::decode(s.trim()).map_err(|_| Error::Corrupt("anchor secret is not hex".into()))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::Corrupt("anchor secret is not 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&raw))
}

/// The current public key, if a key exists.
pub fn pubkey(store: &Store) -> Result<String> {
    let sk = load_key(store)?;
    Ok(hex::encode(sk.verifying_key().as_bytes()))
}

/// Sign a checkpoint of current fabric state and write it to `out`.
/// `out` should live outside `.respawn/` — an anchor inside the thing
/// it anchors can be replaced alongside it. Returns the number of
/// audit entries the anchor covers.
pub fn create(store: &Store, out: &Path) -> Result<u64> {
    // An anchor inside the fabric it anchors can be replaced alongside
    // the log it claims to prove — refuse the footgun outright. The file
    // may not exist yet, so canonicalize the parent, not the path.
    let parent = out.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(canon_parent) = parent.canonicalize() {
        let candidate = canon_parent.join(out.file_name().unwrap_or_default());
        let fabric = store
            .fabric_dir()
            .canonicalize()
            .unwrap_or_else(|_| store.fabric_dir());
        if candidate.starts_with(&fabric) {
            return Err(Error::Corrupt(
                "anchor must live outside .respawn/ — inside the fabric it proves nothing".into(),
            ));
        }
    }
    let sk = load_key(store)?;
    let (audit_len, audit_tip) = audit::tip(store)?;
    // Chain link: this anchor signs the hash of the previous anchor
    // file. last_anchor is a convenience marker — its value is checked
    // against the signed payload at verify-link time, so tampering with
    // the marker only ever desynchronizes, never forges.
    let prev_anchor = match fs::read_to_string(store.fabric_dir().join(LAST_ANCHOR_FILE)) {
        Ok(s) => Some(s.trim().to_string()),
        Err(_) => None,
    };
    let payload = AnchorPayload {
        kind: "respawn-anchor".into(),
        version: ANCHOR_VERSION,
        fabric_id: fabric_id(store)?,
        audit_len,
        audit_tip,
        head: store.head()?.map(hex::encode),
        prev_anchor,
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let payload_bytes = serde_json::to_string(&payload)?;
    let sig = sk.sign(payload_bytes.as_bytes());
    let file = AnchorFile {
        format: "respawn-anchor/v1".into(),
        pubkey: hex::encode(sk.verifying_key().as_bytes()),
        payload: payload_bytes,
        sig: hex::encode(sig.to_bytes()),
    };
    let bytes = serde_json::to_vec_pretty(&file)?;
    atomic_write(out, &bytes)?;
    atomic_write(
        &store.fabric_dir().join(LAST_ANCHOR_FILE),
        hex::encode(crate::hash_bytes(&bytes)).as_bytes(),
    )?;
    Ok(payload.audit_len)
}

#[derive(Debug)]
pub struct VerifyOutcome {
    pub signer_pubkey: String,
    pub audit_len: u64,
    /// HEAD recorded in the anchor.
    pub anchored_head: Option<String>,
    /// HEAD right now — divergence is normal (new snapshots), reported
    /// for visibility, not treated as tampering.
    pub current_head: Option<String>,
    /// BLAKE3 hex of the anchor file itself — the link the next anchor
    /// in the chain should carry.
    pub file_hash: String,
    /// Hash of the previous anchor this one chains to, if any.
    pub prev_anchor: Option<String>,
}

/// Anchors are tiny JSON; a cap rejects memory-exhaustion inputs before
/// they are read, not after.
const MAX_ANCHOR_BYTES: u64 = 4 * 1024 * 1024;

fn read_anchor_file(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).map_err(Error::Io)?;
    if meta.len() > MAX_ANCHOR_BYTES {
        return Err(Error::Corrupt(format!(
            "anchor file exceeds {} bytes",
            MAX_ANCHOR_BYTES
        )));
    }
    fs::read(path).map_err(Error::Io)
}

/// Parse an anchor file and verify its signature: format check, key
/// and signature decoding, ed25519 verify over the payload string.
/// Returns the file and its decoded payload — the shared front half of
/// every verification entry point.
fn checked_anchor(bytes: &[u8]) -> Result<(AnchorFile, AnchorPayload)> {
    let file: AnchorFile = serde_json::from_slice(bytes)
        .map_err(|e| Error::Corrupt(format!("anchor file unparsable: {e}")))?;
    if file.format != "respawn-anchor/v1" {
        return Err(Error::Corrupt(format!(
            "unknown anchor format {}",
            file.format
        )));
    }
    let pk_raw =
        hex::decode(&file.pubkey).map_err(|_| Error::Corrupt("anchor pubkey is not hex".into()))?;
    let pk_raw: [u8; 32] = pk_raw
        .try_into()
        .map_err(|_| Error::Corrupt("anchor pubkey is not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_raw)
        .map_err(|_| Error::Corrupt("anchor pubkey is not a valid ed25519 key".into()))?;
    let sig_raw =
        hex::decode(&file.sig).map_err(|_| Error::Corrupt("anchor sig is not hex".into()))?;
    let sig_raw: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| Error::Corrupt("anchor sig is not 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_raw);
    use ed25519_dalek::Verifier;
    vk.verify(file.payload.as_bytes(), &sig)
        .map_err(|_| Error::Corrupt("anchor signature invalid".into()))?;

    let payload: AnchorPayload = serde_json::from_str(&file.payload)
        .map_err(|e| Error::Corrupt(format!("anchor payload unparsable: {e}")))?;
    if payload.kind != "respawn-anchor" || payload.version != ANCHOR_VERSION {
        return Err(Error::Corrupt(
            "anchor payload version/type mismatch".into(),
        ));
    }
    Ok((file, payload))
}

/// Verify an anchor file: signature over the payload, signer identity
/// (optionally pinned via `expected_pubkey`), fabric id match, and —
/// the actual point — that the anchored audit tip is still a valid
/// prefix of the live log.
pub fn verify(store: &Store, path: &Path, expected_pubkey: Option<&str>) -> Result<VerifyOutcome> {
    let bytes = read_anchor_file(path)?;
    let (file, payload) = checked_anchor(&bytes)?;

    if let Some(want) = expected_pubkey {
        if !want.eq_ignore_ascii_case(&file.pubkey) {
            return Err(Error::Corrupt(format!(
                "anchor signer {} does not match expected key {}",
                file.pubkey, want
            )));
        }
    }

    if payload.fabric_id != fabric_id(store)? {
        return Err(Error::Corrupt(
            "anchor belongs to a different fabric".into(),
        ));
    }

    // The anchored tip must still be a *prefix* of the live log:
    // extension after anchoring is legal work; a shorter log or a tip
    // that no longer matches is tampering.
    audit::tip_is_prefix(store, payload.audit_len, &payload.audit_tip)?;

    let current_head = store.head()?.map(hex::encode);
    Ok(VerifyOutcome {
        signer_pubkey: file.pubkey,
        audit_len: payload.audit_len,
        anchored_head: payload.head,
        current_head,
        file_hash: hex::encode(crate::hash_bytes(&bytes)),
        prev_anchor: payload.prev_anchor,
    })
}

/// Verify that `cur` chains to `prev`: both must be well-formed signed
/// anchors, and `cur`'s signed `prev_anchor` must equal the BLAKE3 of
/// `prev`'s exact bytes. Pairwise application over a stored anchor
/// series proves the *sequence* was not spliced, substituted, or had
/// members deleted — shrinking the unverifiable window to "since the
/// last anchor" instead of "since anchoring began."
pub fn verify_link(cur: &Path, prev: &Path) -> Result<()> {
    let prev_bytes = read_anchor_file(prev)?;
    let prev_hash = hex::encode(crate::hash_bytes(&prev_bytes));
    // prev must itself be a valid signed anchor — a link into garbage
    // is not a link.
    checked_anchor(&prev_bytes)?;

    let cur_bytes = read_anchor_file(cur)?;
    let (_file, payload) = checked_anchor(&cur_bytes)?;
    match &payload.prev_anchor {
        Some(h) if h == &prev_hash => Ok(()),
        Some(_) => Err(Error::Corrupt(
            "anchor does not chain to the given predecessor".into(),
        )),
        None => Err(Error::Corrupt(
            "anchor has no chain link (first anchor, or pre-chain format)".into(),
        )),
    }
}

/// Sanity: the file reads and its signature verifies without touching a
/// fabric — used when checking an anchor away from its worktree.
pub fn verify_detached(path: &Path) -> Result<String> {
    let bytes = read_anchor_file(path)?;
    let (file, _payload) = checked_anchor(&bytes)?;
    Ok(file.pubkey)
}
