//! APFS point-in-time snapshots (macOS).
//!
//! `respawn snap --apfs` freezes the whole volume at the APFS layer and
//! snapshots the frozen view: every file is captured at the same
//! instant, which serial reads cannot promise. The mechanism:
//!
//!   1. `tmutil snapshot` — mint an APFS local snapshot of the boot
//!      volume group (the *Data* volume on modern macOS, where all
//!      writable firmlinked content actually lives)
//!   2. `mount_apfs -s <name> <data-vol> <mnt>` — mount it read-only
//!   3. snapshot::create reads through the mount instead of the live tree
//!   4. on drop: unmount, then delete the cut (`tmutil
//!      deletelocalsnapshots` needs no root; diskutil is the fallback)
//!
//! Mounting a snapshot requires root — this module returns an honest
//! error when it lacks privilege rather than silently degrading to a
//! non-atomic read.

use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A mounted APFS local snapshot. Drop cleans up: unmount, remove the
/// temp dir, delete the APFS snapshot so Time Machine space is not held.
pub struct ApfsSnap {
    /// Snapshot name as APFS knows it (com.apple.TimeMachine.<stamp>).
    name: String,
    /// Device node of the snapped volume (e.g. /dev/disk3s1s1).
    device: String,
    /// Temp mount point of the frozen view.
    mount: PathBuf,
    /// Path inside the mount that mirrors the worktree root — the
    /// directory snapshot::create should read instead of the live tree.
    scan_root: PathBuf,
}

impl ApfsSnap {
    pub fn scan_root(&self) -> &Path {
        &self.scan_root
    }
}

#[cfg(target_os = "macos")]
fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().map_err(Error::Io)?;
    if !out.status.success() {
        return Err(Error::Corrupt(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Find the APFS (device, mountpoint) that actually *backs* `path`.
/// Prefix-matching the mount table is wrong on modern macOS: the
/// worktree reaches the Data volume through firmlinks (`/Users/x` is
/// really `/System/Volumes/Data/Users/x`), so paths never carry the
/// volume's own mountpoint as a prefix. st_dev equality is the truth —
/// a path and its backing volume share a device id.
#[cfg(target_os = "macos")]
fn volume_of(path: &Path) -> Result<(String, PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    let want = std::fs::metadata(path)?.dev();
    let table = run("/sbin/mount", &[])?;
    for line in table.lines() {
        // /dev/disk3s5 on /System/Volumes/Data (apfs, local, ...)
        let Some((dev, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mp, attrs)) = rest.split_once(" (") else {
            continue;
        };
        if !attrs.starts_with("apfs") {
            continue;
        }
        let mpp = Path::new(mp.trim());
        let Ok(md) = std::fs::metadata(mpp) else {
            continue;
        };
        if md.dev() == want {
            return Ok((dev.to_string(), mpp.to_path_buf()));
        }
    }
    Err(Error::Corrupt(format!(
        "no APFS volume backs {}",
        path.display()
    )))
}

/// The volume `tmutil snapshot` actually cuts: the member of the
/// boot volume group flagged "root data" in the mount table (the
/// Data volume — `/dev/disk3s5 on /System/Volumes/Data ... root
/// data`). On pre-split macOS with no Data volume, `/` itself.
/// st_dev cannot distinguish group members — firmlinks make them
/// one filesystem — so the flag, not the device id, identifies it.
#[cfg(target_os = "macos")]
fn data_volume() -> Result<(String, PathBuf)> {
    let table = run("/sbin/mount", &[])?;
    let mut boot: Option<(String, PathBuf)> = None;
    for line in table.lines() {
        let Some((dev, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mp, attrs)) = rest.split_once(" (") else {
            continue;
        };
        if !attrs.starts_with("apfs") {
            continue;
        }
        if attrs.contains("root data") {
            return Ok((dev.to_string(), Path::new(mp.trim()).to_path_buf()));
        }
        if mp.trim() == "/" {
            boot = Some((dev.to_string(), Path::new("/").to_path_buf()));
        }
    }
    boot.ok_or_else(|| Error::Corrupt("no APFS boot volume found".into()))
}

/// tmutil snapshots the boot volume group — the Data volume in
/// practice, since the system volume itself is sealed. A worktree on
/// another device (external disk, second partition) has a different
/// st_dev — group members share one — and is refused honestly.
#[cfg(target_os = "macos")]
fn on_boot_volume_group(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let want = std::fs::metadata(path)?.dev();
    Ok(std::fs::metadata("/")?.dev() == want)
}

/// Parse the snapshot name tmutil itself reports. Output shape:
/// `Created local snapshot with date: com.apple.TimeMachine.<stamp>`.
/// Parsing the name (rather than diffing the snapshot list before and
/// after) avoids a race where a *concurrent* Time Machine snapshot —
/// or another respawn — is mistaken for ours and later mounted or
/// deleted.
#[cfg(target_os = "macos")]
fn snapshot_name_from_output(out: &str) -> Result<String> {
    for token in out.split_whitespace() {
        let name =
            token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.');
        if name.starts_with("com.apple.TimeMachine.") && name.len() > 22 {
            return Ok(name.to_string());
        }
        // Older tmutil prints only the date portion:
        // "Created local snapshot with date: 2023-10-15-143022".
        // The APFS name is the same string under the TimeMachine prefix.
        let is_date = {
            let parts: Vec<&str> = name.split('-').collect();
            parts.len() == 4
                && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
                && parts[0].len() == 4
        };
        if is_date {
            return Ok(format!("com.apple.TimeMachine.{name}"));
        }
    }
    Err(Error::Corrupt(format!(
        "could not parse snapshot name from tmutil output: {out}"
    )))
}

/// The parsed candidate and reality can differ — tmutil prints a
/// bare date (`2026-09-17-174527`) while APFS knows the snapshot as
/// `com.apple.TimeMachine.<date>.local`. Resolve against the volume's
/// own snapshot list rather than guessing a naming convention.
#[cfg(target_os = "macos")]
fn resolve_snapshot_name(device: &str, candidate: &str) -> Result<String> {
    let list = run("diskutil", &["apfs", "listSnapshots", device])?;
    let names: Vec<String> = list
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Name:").map(|n| n.trim().to_string()))
        .collect();
    for want in [candidate.to_string(), format!("{candidate}.local")] {
        if names.iter().any(|n| n == &want) {
            return Ok(want);
        }
    }
    Err(Error::Corrupt(format!(
        "snapshot {candidate} not found on {device} (have: {})",
        names.join(", ")
    )))
}

/// Create + mount an APFS snapshot covering `root`, returning the
/// mounted view. Errors are explicit: no privilege, non-APFS volume, or
/// a worktree outside the boot volume group (tmutil snapshots the
/// Data volume, which is where writable content actually lives).
#[cfg(target_os = "macos")]
pub fn create(root: &Path) -> Result<ApfsSnap> {
    if !on_boot_volume_group(root)? {
        let (_, mountpoint) = volume_of(root)?;
        return Err(Error::Corrupt(format!(
            "--apfs snapshots the boot volume group; {} lives on {}",
            root.display(),
            mountpoint.display()
        )));
    }
    let (device, mountpoint) = data_volume()?;

    let candidate = snapshot_name_from_output(&run("tmutil", &["snapshot"])?)?;
    let name = resolve_snapshot_name(&device, &candidate)?;

    // Mount the frozen view. Requires root — mount_apfs refuses otherwise.
    // Random suffix: a predictable name could be pre-created by another
    // process; the mount target must be ours.
    let mut rand = [0u8; 8];
    let suffix = match getrandom::getrandom(&mut rand) {
        Ok(()) => hex::encode(rand),
        Err(_) => format!("{}", std::process::id()),
    };
    let mnt = std::env::temp_dir().join(format!("respawn-apfs-{suffix}"));
    std::fs::create_dir_all(&mnt)?;
    let mres = run(
        "/sbin/mount_apfs",
        &["-s", &name, &device, &mnt.to_string_lossy()],
    );
    if let Err(e) = mres {
        let _ = std::fs::remove_dir(&mnt);
        delete_snapshot(&device, &name);
        let msg = format!("{e}");
        if msg.contains("Operation not permitted") {
            // EPERM *as root* — not a privilege problem. Since macOS 26
            // the kernel refuses to mount snapshots of the boot Data
            // volume: a mounted Data snapshot would bypass TCC on all
            // user data, so the boundary is enforced below userland.
            return Err(Error::Corrupt(
                "the kernel refused to mount the boot volume's snapshot \
                 (macOS 26+ blocks this even for root) — point-in-time \
                 capture is unavailable on this volume; a plain `snap` \
                 still gets per-file quiescence"
                    .into(),
            ));
        }
        return Err(Error::Corrupt(format!(
            "APFS snapshot created but mounting needs root (run with sudo or --ask-admin): {e}"
        )));
    }

    // Path inside the frozen volume. If the worktree was addressed
    // through the volume's own mountpoint (/System/Volumes/Data/...),
    // strip that. Otherwise it arrived via a firmlink — /Users/x —
    // and the in-volume path is the synthetic path minus its slash.
    let canon = root.canonicalize()?;
    let rel = canon
        .strip_prefix(&mountpoint)
        .unwrap_or_else(|_| canon.strip_prefix("/").unwrap_or(canon.as_path()));
    let scan_root = mnt.join(rel);
    if !scan_root.is_dir() {
        // Never scan the wrong tree silently — a firmlink edge case
        // we didn't model is a loud error, not a wrong snapshot.
        let _ = run("umount", &[&mnt.to_string_lossy()]);
        let _ = std::fs::remove_dir(&mnt);
        delete_snapshot(&device, &name);
        return Err(Error::Corrupt(format!(
            "worktree {} is not visible inside the frozen volume",
            canon.display()
        )));
    }
    Ok(ApfsSnap {
        name,
        device,
        mount: mnt.clone(),
        scan_root,
    })
}

/// Delete a tmutil local snapshot. `tmutil deletelocalsnapshots`
/// needs no root, so it is the first choice — Drop paths and failure
/// cleanups often run unprivileged. Falls back to `diskutil apfs
/// deleteSnapshot` (root) for names the date-parse cannot express.
#[cfg(target_os = "macos")]
fn delete_snapshot(device: &str, name: &str) {
    let date = name
        .strip_prefix("com.apple.TimeMachine.")
        .and_then(|d| d.strip_suffix(".local"));
    let ok = date
        .map(|d| run("tmutil", &["deletelocalsnapshots", d]).is_ok())
        .unwrap_or(false);
    if !ok {
        let _ = run(
            "diskutil",
            &["apfs", "deleteSnapshot", device, "-name", name],
        );
    }
}

#[cfg(not(target_os = "macos"))]
pub fn create(_root: &Path) -> Result<ApfsSnap> {
    Err(Error::Corrupt(
        "--apfs point-in-time snapshots are macOS-only".into(),
    ))
}

impl Drop for ApfsSnap {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            let _ = run("umount", &[&self.mount.to_string_lossy()]);
            let _ = std::fs::remove_dir(&self.mount);
            delete_snapshot(&self.device, &self.name);
        }
    }
}
