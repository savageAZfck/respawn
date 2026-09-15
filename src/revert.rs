//! Revert: materialize a manifest into the worktree.
//!
//! Files are written to a temp file in the target directory and renamed
//! over the destination — each file swap is atomic at the VFS level, so a
//! crash mid-revert leaves per-file torn state, never half-written files.
//! Files absent from the manifest are removed unless `keep_extra` is set.
//! Empty directories left behind are pruned.

use crate::drift;
use crate::snapshot::Manifest;
use crate::{Error, Result, Store, FABRIC_DIR};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct RevertReport {
    pub restored: Vec<String>,
    pub removed: Vec<String>,
    pub skipped_extra: Vec<String>,
}

fn excluded(rel: &Path) -> bool {
    rel.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == FABRIC_DIR || s == ".git" || s == ".DS_Store"
    })
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Materialize `manifest` into `root`. Verifies content hashes as it
/// writes — a tampered object aborts the revert before the swap.
pub fn apply(
    store: &Store,
    root: &Path,
    manifest: &Manifest,
    keep_extra: bool,
) -> Result<RevertReport> {
    let mut report = RevertReport::default();
    let wanted: HashSet<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();

    for fe in &manifest.files {
        let dest = root.join(&fe.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        // Skip rewrite if the live file already matches the manifest.
        let needs_write = match fs::metadata(&dest) {
            Ok(m) if m.is_file() => {
                let h = drift_file_hash(&dest)?;
                h != fe.content
            }
            _ => true,
        };
        if !needs_write {
            continue;
        }

        let tmp = dest.with_extension("sf-tmp");
        {
            let mut out = fs::File::create(&tmp)?;
            let mut hasher = blake3::Hasher::new();
            for ch in &fe.chunks {
                let data = store.get_object(ch)?;
                hasher.update(&data);
                out.write_all(&data)?;
            }
            let digest = hasher.finalize();
            if digest.as_bytes() != &fe.content {
                let _ = fs::remove_file(&tmp);
                return Err(Error::Corrupt(format!(
                    "reconstructed content mismatch for {}",
                    fe.path
                )));
            }
            out.sync_all()?;
        }
        fs::rename(&tmp, &dest)?;
        set_mode(&dest, fe.mode)?;
        report.restored.push(fe.path.clone());
    }

    // Remove files the manifest doesn't know about.
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
        if !wanted.contains(rel_str.as_str()) {
            if keep_extra {
                report.skipped_extra.push(rel_str);
            } else {
                fs::remove_file(entry.path())?;
                report.removed.push(rel_str);
            }
        }
    }

    prune_empty_dirs(root)?;
    Ok(report)
}

fn drift_file_hash(path: &Path) -> Result<crate::Hash> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut f, &mut hasher)?;
    Ok(*hasher.finalize().as_bytes())
}

/// Remove empty directories under root (excluding fabric internals).
fn prune_empty_dirs(root: &Path) -> Result<()> {
    let mut dirs: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .filter(|p| p != root)
        .collect();
    // Deepest first.
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs {
        let rel = d.strip_prefix(root).unwrap();
        if excluded(rel) {
            continue;
        }
        let _ = fs::remove_dir(&d); // only succeeds when empty
    }
    Ok(())
}

/// Drift check then revert: convenience used by the CLI to refuse a
/// revert that would silently destroy un-snapshotted work.
pub fn check_then_apply(
    store: &Store,
    root: &Path,
    manifest: &Manifest,
    keep_extra: bool,
    force: bool,
) -> Result<(drift::DriftReport, Option<RevertReport>)> {
    let head = store.head()?;
    let report = if let Some(h) = head {
        let cur = crate::snapshot::load(store, &h)?;
        drift::detect(root, &cur)?
    } else {
        drift::detect(
            root,
            &Manifest {
                version: 1,
                parent: None,
                timestamp_secs: 0,
                message: String::new(),
                files: Vec::new(),
            },
        )?
    };

    let dirty =
        !report.added.is_empty() || !report.modified.is_empty() || !report.deleted.is_empty();
    if dirty && !force {
        return Ok((report, None));
    }
    let r = apply(store, root, manifest, keep_extra)?;
    Ok((report, Some(r)))
}
