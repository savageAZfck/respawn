//! Fleet: signed revert orders for peers under one key.
//!
//! `fleet order` mints a small signed instruction — fabric id, target
//! snapshot, timestamp, nonce — that any peer can carry home by any
//! channel (a pull, a shared dir, a git commit, a paste). `fleet apply`
//! on a peer verifies the signature against the pinned fleet key,
//! pulls the target snapshot if needed, and reverts locally. One
//! signed order, every box returns to the same anchored state.
//!
//! Trust model: the order's signer must match `.respawn/fleet.pub`,
//! pinned once by `fleet trust` — like `--pubkey` on anchor verify,
//! but persistent. An order for another fabric refuses outright; an
//! order whose target can't be fetched waits for `--from`.

use crate::{anchor, audit, keychain, revert, snapshot, sync, Error, Result, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FLEET_KEY_FILE: &str = "fleet.pub";
const FLEET_SEEN_FILE: &str = "fleet_seen";

#[derive(Debug, Serialize, Deserialize)]
pub struct OrderPayload {
    pub kind: String, // "respawn-fleet-order"
    pub fabric_id: String,
    /// Snapshot id every applying peer should land on.
    pub target: String,
    pub ts: u64,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FleetOrder {
    pub format: String, // "respawn-fleet-order/v1"
    pub pubkey: String,
    pub payload: String,
    pub sig: String,
}

fn fleet_key_path(store: &Store) -> PathBuf {
    store.fabric_dir().join(FLEET_KEY_FILE)
}

/// Pin the order-signing pubkey. First pin wins — re-pinning requires
/// deleting `.respawn/fleet.pub` by hand, so a rogue order can't
/// rotate the trust root under you.
pub fn trust(store: &Store, pubkey: &str) -> Result<()> {
    if pubkey.len() != 64 || hex::decode(pubkey).is_err() {
        return Err(Error::Corrupt("fleet pubkey must be 64 hex chars".into()));
    }
    let path = fleet_key_path(store);
    if path.exists() {
        let cur = fs::read_to_string(&path)?;
        if cur.trim() == pubkey {
            return Ok(());
        }
        return Err(Error::Corrupt(
            "fleet key already pinned — remove .respawn/fleet.pub to re-pin".into(),
        ));
    }
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, format!("{pubkey}\n"))?;
    audit::record(store, "fleet-trust", pubkey)?;
    Ok(())
}

/// Mint a signed order instructing the fleet to land on `target`.
/// `out` can go anywhere — the order is self-verifying, transport is
/// the operator's choice.
pub fn order(store: &Store, target: &str, out: &Path) -> Result<PathBuf> {
    let id = snapshot::resolve(store, target)?;
    if !store.has_manifest(&id) {
        return Err(Error::Corrupt("target snapshot not in store".into()));
    }
    let (raw, _placement, note) = keychain::get(store)?;
    let sk = SigningKey::from_bytes(&raw);
    if let Some(n) = &note {
        eprintln!("note: {n}");
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let nonce = crate::hash_hex(&crate::hash_bytes(
        format!("{ts}:{}", std::process::id()).as_bytes(),
    ));
    let payload = OrderPayload {
        kind: "respawn-fleet-order".into(),
        fabric_id: anchor::fabric_id(store)?,
        target: crate::hash_hex(&id),
        ts,
        nonce: nonce[..16].to_string(),
    };
    let payload_bytes = serde_json::to_string(&payload)?;
    let sig = sk.sign(payload_bytes.as_bytes());
    let order = FleetOrder {
        format: "respawn-fleet-order/v1".into(),
        pubkey: hex::encode(sk.verifying_key().as_bytes()),
        payload: payload_bytes,
        sig: hex::encode(sig.to_bytes()),
    };
    let dir = out.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = crate::tmp_path(dir, "fleet-order");
    fs::write(&tmp, serde_json::to_vec_pretty(&order)?)?;
    fs::rename(&tmp, out)?;
    Ok(out.to_path_buf())
}

/// Apply a signed order: verify signer + fabric binding, pull the
/// target if given `--from`, revert. Returns the snapshot id applied.
pub fn apply(
    store: &Store,
    root: &Path,
    order_path: &Path,
    from: Option<&str>,
    psk: Option<&str>,
    force: bool,
) -> Result<crate::Hash> {
    let bytes = fs::read(order_path)?;
    let order: FleetOrder = serde_json::from_slice(&bytes)?;
    if order.format != "respawn-fleet-order/v1" {
        return Err(Error::Corrupt("unknown fleet order format".into()));
    }
    let payload: OrderPayload = serde_json::from_str(&order.payload)?;
    if payload.kind != "respawn-fleet-order" {
        return Err(Error::Corrupt("payload kind mismatch".into()));
    }

    // Signer must be the pinned fleet key — no pin, no trust.
    let pinned = match fs::read_to_string(fleet_key_path(store)) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            return Err(Error::Corrupt(
                "no pinned fleet key — `respawn fleet trust <pubkey>` first".into(),
            ))
        }
    };
    if order.pubkey != pinned {
        return Err(Error::Corrupt(
            "fleet order signer is not the pinned fleet key".into(),
        ));
    }
    let pk_bytes: [u8; 32] = hex::decode(&order.pubkey)
        .map_err(|_| Error::Corrupt("bad pubkey hex".into()))?
        .try_into()
        .map_err(|_| Error::Corrupt("bad pubkey length".into()))?;
    let pk =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| Error::Corrupt("bad pubkey".into()))?;
    let sig_bytes: [u8; 64] = hex::decode(&order.sig)
        .map_err(|_| Error::Corrupt("bad sig hex".into()))?
        .try_into()
        .map_err(|_| Error::Corrupt("bad sig length".into()))?;
    pk.verify(order.payload.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Error::Corrupt("fleet order signature invalid".into()))?;

    // Orders are fabric-bound — an order minted against another fabric
    // must not rewrite this worktree.
    if payload.fabric_id != anchor::fabric_id(store)? {
        return Err(Error::Corrupt(
            "fleet order targets a different fabric".into(),
        ));
    }

    // Monotonic apply: a replayed order older than the newest one
    // already applied must not drag the peer backward again.
    let seen_path = store.fabric_dir().join(FLEET_SEEN_FILE);
    let last_seen: u64 = fs::read_to_string(&seen_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if payload.ts < last_seen {
        return Err(Error::Corrupt(format!(
            "stale fleet order (ts {} < last applied {}) — replay refused",
            payload.ts, last_seen
        )));
    }
    let target = crate::parse_hash(&payload.target)?;

    if !store.has_manifest(&target) {
        match from {
            Some(addr) => {
                sync::pull(store, addr, psk)?;
            }
            None => {
                return Err(Error::Corrupt(
                    "target snapshot not in store — pass --from <peer> to pull it".into(),
                ))
            }
        }
    }
    let m = snapshot::load(store, &target)?;
    let (_drift, applied) = revert::check_then_apply(store, root, &m, false, force)?;
    if applied.is_none() {
        return Err(Error::Corrupt(
            "fleet revert refused: un-snapshotted changes (retry with --force)".into(),
        ));
    }
    store.set_head(Some(&target))?;
    fs::write(&seen_path, format!("{}\n", payload.ts.max(last_seen)))?;
    audit::record(
        store,
        "fleet-revert",
        &format!("order {} -> {}", payload.nonce, crate::short(&target)),
    )?;
    Ok(target)
}
