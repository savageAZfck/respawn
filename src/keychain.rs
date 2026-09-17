//! Signing-secret storage for anchors.
//!
//! On macOS the anchor key prefers the login Keychain: a Keychain item
//! inherits the OS's unlock/ACL machinery instead of relying on
//! permission bits alone. The `.respawn/anchor.secret` file (0600)
//! remains the store of last resort — on non-macOS, and on macOS
//! sessions where the Keychain refuses interaction (SSH without a GUI
//! session, daemons outside the user context). Falling back is
//! reported, never silent.
//!
//! Keychain items are generic passwords: service `com.respawn.anchor`,
//! account = fabric id, value = the raw 32-byte ed25519 seed. First
//! access by a new unsigned build may prompt macOS's ACL dialog once;
//! "Always Allow" binds it to the binary.

use crate::{Error, Result, Store};
use std::fs;
use std::path::PathBuf;

const SECRET_FILE: &str = "anchor.secret";

/// `RESPAWN_NO_KEYCHAIN=1` forces file storage — for SSH/headless
/// sessions, CI, and tests (which must never write real Keychain
/// items). Checked at call time so a session can set it per-process.
#[cfg(target_os = "macos")]
fn keychain_disabled() -> bool {
    std::env::var_os("RESPAWN_NO_KEYCHAIN").is_some()
}

/// Where a secret landed / was found — surfaced so the operator knows
/// which protection actually applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// macOS login Keychain.
    Keychain,
    /// `.respawn/anchor.secret`, mode 0600.
    File,
}

pub fn secret_path(store: &Store) -> PathBuf {
    store.fabric_dir().join(SECRET_FILE)
}

/// Write the key file atomically AND with mode 0600 from birth — a
/// create-then-chmod sequence leaves a window where the file is
/// readable to other users on the machine.
#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
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
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = crate::tmp_path(dir, "secret");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// True if a signing key exists in either store — keygen refuses to
/// overwrite, and a swapped key must never look like a passed check.
pub fn exists(store: &Store) -> bool {
    if secret_path(store).exists() {
        return true;
    }
    #[cfg(target_os = "macos")]
    if !keychain_disabled() {
        if let Ok(id) = crate::anchor::fabric_id(store) {
            if macos::get(&id).ok().flatten().is_some() {
                return true;
            }
        }
    }
    false
}

/// Store a freshly generated key. Prefers Keychain on macOS; any
/// Keychain failure falls back to the file and says so.
/// Returns where the key actually lives.
pub fn put(store: &Store, raw: &[u8; 32]) -> Result<(Placement, Option<String>)> {
    #[cfg(target_os = "macos")]
    {
        if keychain_disabled() {
            write_secret_file(&secret_path(store), hex::encode(raw).as_bytes())?;
            return Ok((Placement::File, None));
        }
        let id = crate::anchor::fabric_id(store)?;
        match macos::set(&id, raw) {
            Ok(()) => Ok((Placement::Keychain, None)),
            Err(e) => {
                write_secret_file(&secret_path(store), hex::encode(raw).as_bytes())?;
                Ok((
                    Placement::File,
                    Some(format!(
                        "Keychain unavailable ({e}) — key stored in {} (0600)",
                        secret_path(store).display()
                    )),
                ))
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        write_secret_file(&secret_path(store), hex::encode(raw).as_bytes())?;
        Ok((Placement::File, None))
    }
}

/// Load the key. macOS order: Keychain → file → file migrated into
/// Keychain. The migration removes the on-disk copy — on APFS/SSD an
/// "overwrite-then-delete" shred is theater, so we simply remove it;
/// the file was only ever as protected as the volume underneath.
/// Returns the key, where it came from, and an optional operator note
/// (migration or fallback).
pub fn get(store: &Store) -> Result<([u8; 32], Placement, Option<String>)> {
    #[cfg(target_os = "macos")]
    {
        if keychain_disabled() {
            return match read_secret_file(store)? {
                Some(raw) => Ok((raw, Placement::File, None)),
                None => Err(Error::Corrupt(
                    "no anchor key — run `respawn anchor keygen`".into(),
                )),
            };
        }
        let id = crate::anchor::fabric_id(store)?;
        let mut kc_err: Option<String> = None;
        match macos::get(&id) {
            Ok(Some(raw)) => {
                // Keychain is authoritative — a leftover file would
                // silently resurrect the OLD key in a later session
                // where the Keychain is unreachable.
                let _ = fs::remove_file(secret_path(store));
                return Ok((raw, Placement::Keychain, None));
            }
            Ok(None) => {}
            Err(e) => kc_err = Some(e),
        }
        // Keychain miss — try the file, then move it into the Keychain
        // if we can.
        if let Some(raw) = read_secret_file(store)? {
            return match macos::set(&id, &raw) {
                Ok(()) => {
                    let _ = fs::remove_file(secret_path(store));
                    Ok((
                        raw,
                        Placement::Keychain,
                        Some(
                            "migrated anchor key from .respawn/anchor.secret into login Keychain"
                                .into(),
                        ),
                    ))
                }
                Err(e) => Ok((
                    raw,
                    Placement::File,
                    Some(format!("Keychain unavailable ({e}) — using key file")),
                )),
            };
        }
        if let Some(e) = kc_err {
            Err(Error::Corrupt(format!(
                "anchor key lookup failed ({e}) and no key file — \
                 if the key lives in Keychain, this session cannot reach it \
                 (locked keychain or no GUI session)"
            )))
        } else {
            Err(Error::Corrupt(
                "no anchor key — run `respawn anchor keygen`".into(),
            ))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        match read_secret_file(store)? {
            Some(raw) => Ok((raw, Placement::File, None)),
            None => Err(Error::Corrupt(
                "no anchor key — run `respawn anchor keygen`".into(),
            )),
        }
    }
}

fn read_secret_file(store: &Store) -> Result<Option<[u8; 32]>> {
    let path = secret_path(store);
    let s = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let raw =
        hex::decode(s.trim()).map_err(|_| Error::Corrupt("anchor secret is not hex".into()))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::Corrupt("anchor secret is not 32 bytes".into()))?;
    Ok(Some(raw))
}

#[cfg(target_os = "macos")]
mod macos {
    use security_framework::passwords::{get_generic_password, set_generic_password};

    const SERVICE: &str = "com.respawn.anchor";
    /// errSecItemNotFound — the item simply is not there; every other
    /// error means the Keychain itself is unreachable in this session.
    const ERR_ITEM_NOT_FOUND: i32 = -25300;

    /// Ok(None) = not stored; Err = Keychain unreachable (locked,
    /// headless, denied) — distinct cases, not interchangeable.
    pub fn get(account: &str) -> Result<Option<[u8; 32]>, String> {
        match get_generic_password(SERVICE, account) {
            Ok(bytes) => {
                let raw: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "Keychain anchor item is not 32 bytes".to_string())?;
                Ok(Some(raw))
            }
            Err(e) if e.code() == ERR_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(format!("{e}")),
        }
    }

    pub fn set(account: &str, raw: &[u8; 32]) -> Result<(), String> {
        set_generic_password(SERVICE, account, raw).map_err(|e| format!("{e}"))
    }
}
