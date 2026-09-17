//! APFS point-in-time snapshots (macOS).
//!
//! `respawn snap --apfs` freezes the whole volume at the APFS layer and
//! snapshots the frozen view: every file is captured at the same
//! instant, which serial reads cannot promise. The mechanism:
//!
//!   1. `tmutil snapshot` — mint an APFS local snapshot of the volume
//!   2. `mount_apfs -s <name> <vol> <mnt>` — mount it read-only
//!   3. snapshot::create reads through the mount instead of the live tree
//!   4. on drop: unmount, then `diskutil apfs deleteSnapshot` the cut
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

/// Parse `/sbin/mount` output for the (device, mountpoint) covering
/// `path` — longest mountpoint prefix wins, so a worktree on a nested
/// volume resolves to its own device, not `/`.
#[cfg(target_os = "macos")]
fn volume_of(path: &Path) -> Result<(String, PathBuf)> {
    let table = run("/sbin/mount", &[])?;
    let canon = path.canonicalize()?;
    let mut best: Option<(String, PathBuf)> = None;
    for line in table.lines() {
        // /dev/disk3s1s1 on / (apfs, local, journaled)
        let Some((dev, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mp, _attrs)) = rest.split_once(" (") else {
            continue;
        };
        let mp = mp.trim();
        let mpp = Path::new(mp);
        if canon.starts_with(mpp) {
            let better = match &best {
                None => true,
                Some((_, bp)) => mpp.components().count() > bp.components().count(),
            };
            if better {
                best = Some((dev.to_string(), mpp.to_path_buf()));
            }
        }
    }
    best.ok_or_else(|| Error::Corrupt(format!("no mount covers {}", canon.display())))
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

/// Create + mount an APFS snapshot covering `root`, returning the
/// mounted view. Errors are explicit: no privilege, non-APFS volume, or
/// a worktree on a non-boot volume (tmutil snapshots `/` only).
#[cfg(target_os = "macos")]
pub fn create(root: &Path) -> Result<ApfsSnap> {
    let (device, mountpoint) = volume_of(root)?;
    if mountpoint != Path::new("/") {
        return Err(Error::Corrupt(format!(
            "--apfs snapshots the boot volume; {} lives on {}",
            root.display(),
            mountpoint.display()
        )));
    }

    let name = snapshot_name_from_output(&run("tmutil", &["snapshot"])?)?;

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
        let _ = run(
            "diskutil",
            &["apfs", "deleteSnapshot", &device, "-name", &name],
        );
        return Err(Error::Corrupt(format!(
            "APFS snapshot created but mounting needs root (run with sudo): {e}"
        )));
    }

    let canon = root.canonicalize()?;
    let rel = canon.strip_prefix(&mountpoint).unwrap_or(Path::new(""));
    Ok(ApfsSnap {
        name,
        device,
        mount: mnt.clone(),
        scan_root: mnt.join(rel),
    })
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
            let _ = run(
                "diskutil",
                &["apfs", "deleteSnapshot", &self.device, "-name", &self.name],
            );
        }
    }
}
