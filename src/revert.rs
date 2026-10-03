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
    // Only plain permission bits are honored — a manifest carrying
    // setuid/setgid/sticky bits must not propagate them to the disk.
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Resolve a manifest path to a destination inside `root`, verifying
/// that no existing ancestor component is a symlink — a planted link
/// (e.g. from an extracted archive or a malicious script) must not let
/// a revert write outside the worktree. Path syntax itself was already
/// validated by `Manifest::validate`; this guards the on-disk reality.
/// Resolve a manifest-relative path to a safe on-disk destination:
/// rejects escapes, unsafe components, and any ancestor that is a
/// symlink (the write boundary's path defense, usable by callers that
/// remove or inspect paths under the same rules).
pub fn resolve_dest(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel = crate::sanitize_rel(rel)?;
    let dest = root.join(&rel);

    // Walk each ancestor between root and dest: if it exists, it must
    // be a real directory or a plain file that will be replaced.
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp.as_os_str());
        if cur == dest {
            break;
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Error::UnsafePath(format!(
                    "{} passes through symlink {}",
                    rel.display(),
                    cur.display()
                )));
            }
            Ok(m) if m.is_dir() => continue,
            Ok(_) => {
                return Err(Error::UnsafePath(format!(
                    "{} blocked by non-directory {}",
                    rel.display(),
                    cur.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(dest)
}

/// Materialize `manifest` into `root`. Verifies content hashes as it
/// writes — a tampered object aborts the revert before the swap.
pub fn apply(
    store: &Store,
    root: &Path,
    manifest: &Manifest,
    keep_extra: bool,
) -> Result<RevertReport> {
    // Defense in depth: callers normally hand us a manifest already
    // validated by load(), but apply is the write boundary — a manifest
    // that escapes validation anywhere must still not write here.
    manifest.validate()?;

    // Purged content never comes back — tombstones outlive the
    // manifests that carried the data.
    let tombstones = crate::purge::tombstones(store)?;
    for fe in &manifest.files {
        if tombstones
            .iter()
            .any(|t| t.path == fe.path || t.content == crate::hash_hex(&fe.content))
        {
            return Err(Error::Corrupt(format!(
                "manifest contains purged content ({}) — erasure cannot be reverted",
                fe.path
            )));
        }
    }

    let mut report = RevertReport::default();
    let wanted: HashSet<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    let tmp_dir = store.fabric_dir().join("tmp");
    fs::create_dir_all(&tmp_dir)?;

    for fe in &manifest.files {
        let dest = resolve_dest(root, &fe.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        // Skip rewrite if the live file already matches the manifest.
        // symlink_metadata: a symlink at dest is NOT a match — it gets
        // replaced rather than followed.
        let needs_write = match fs::symlink_metadata(&dest) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => {
                let h = drift_file_hash(&dest)?;
                h != fe.content
            }
            _ => true,
        };
        if !needs_write {
            continue;
        }

        // Materialize inside the fabric dir (same filesystem as the
        // worktree) so rename stays atomic and a pre-planted file at a
        // predictable tmp name can't be followed.
        let tmp = crate::tmp_path(&tmp_dir, "revert");
        {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let mut hasher = blake3::Hasher::new();
            for ch in &fe.chunks {
                let data = store.get_object(ch)?;
                hasher.update(&data);
                out.write_all(&data)?;
            }
            let digest = hasher.finalize();
            if digest.as_bytes() != &fe.content {
                drop(out);
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

    // Remove files the manifest doesn't know about. Symlinks count as
    // removable entries — a link the manifest doesn't know about gets
    // unlinked (the link itself, never its target).
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("respawn: skipping unreadable entry: {e}");
                continue;
            }
        };
        let ft = entry.file_type();
        if !ft.is_file() && !ft.is_symlink() {
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
        // Full rehash: this gate decides whether to destroy work, so the
        // mtime fast path is not trusted here.
        drift::detect(root, &cur, true)?
    } else {
        drift::detect(
            root,
            &Manifest {
                version: crate::snapshot::MANIFEST_VERSION,
                parent: None,
                timestamp_secs: 0,
                message: String::new(),
                files: Vec::new(),
                unstable: Vec::new(),
                actor: None,
            },
            false,
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

/// Build the manifest HEAD would have if `actor`'s snapshots had never
/// run — undo what one actor did, keep everyone else's work.
///
/// A path is "touched" wherever an actor-tagged snapshot disagrees with
/// its parent. Touched paths resolve to the newest state recorded by a
/// NON-actor snapshot (or drop if no non-actor snapshot carries them) —
/// so later work by other actors on the same path survives the undo.
/// Untouched paths keep their HEAD state.
///
/// Only the HEAD chain is considered; pulled branches are out of scope
/// for v1 (documented — surgical undo reasons about local authorship).
pub fn surgical_manifest(store: &Store, actor: &str) -> Result<(Manifest, Vec<String>)> {
    use std::collections::{BTreeSet, HashMap};

    let mut chain = Vec::new();
    let mut cur = store.head()?;
    let mut guard = 0usize;
    while let Some(id) = cur {
        if guard > 2_000_000 {
            return Err(Error::Corrupt("manifest chain too long".into()));
        }
        guard += 1;
        let m = crate::snapshot::load(store, &id)?;
        cur = m.parent;
        chain.push(m);
    }
    chain.reverse(); // oldest → newest
    let head_m = match chain.last() {
        Some(m) => m.clone(),
        None => return Err(Error::Corrupt("no HEAD snapshot".into())),
    };

    // touched: paths where an actor snapshot disagrees with whatever
    // snapshot preceded it. `pre` keeps the pre-touch entry (or absence)
    // from the FIRST touch — the state to fall back to.
    let mut touched: BTreeSet<String> = BTreeSet::new();
    let mut pre: HashMap<String, Option<crate::snapshot::FileEntry>> = HashMap::new();
    // Content hashes the actor actually wrote per path — a later
    // non-actor snapshot that merely *captured* the actor's bytes is
    // not "someone else's work" and must not resurrect them.
    let mut actor_content: HashMap<String, std::collections::HashSet<crate::Hash>> = HashMap::new();
    // `effective`: newest entry per path from non-actor snapshots whose
    // content the actor didn't write.
    let mut effective: HashMap<String, crate::snapshot::FileEntry> = HashMap::new();
    let mut prev: HashMap<String, &crate::snapshot::FileEntry> = HashMap::new();
    for m in &chain {
        let cur_map: HashMap<String, &crate::snapshot::FileEntry> =
            m.files.iter().map(|f| (f.path.clone(), f)).collect();
        if m.actor.as_deref() == Some(actor) {
            for (p, fe) in &cur_map {
                if prev.get(p).map(|pe| pe.content) != Some(fe.content) {
                    touched.insert(p.clone());
                    pre.entry(p.clone())
                        .or_insert_with(|| prev.get(p).map(|e| (*e).clone()));
                }
                actor_content
                    .entry(p.clone())
                    .or_default()
                    .insert(fe.content);
            }
            for p in prev.keys() {
                if !cur_map.contains_key(p) {
                    touched.insert(p.clone());
                    pre.entry(p.clone())
                        .or_insert_with(|| prev.get(p).map(|e| (*e).clone()));
                }
            }
        } else {
            for fe in &m.files {
                let actor_bytes = actor_content
                    .get(&fe.path)
                    .map(|s| s.contains(&fe.content))
                    .unwrap_or(false);
                if !actor_bytes {
                    effective.insert(fe.path.clone(), fe.clone());
                }
            }
        }
        prev = cur_map;
    }
    if touched.is_empty() {
        return Err(Error::Corrupt(format!(
            "no changes by actor '{actor}' in the HEAD chain"
        )));
    }

    // Resolution per touched path: newest non-actor entry that isn't
    // the actor's bytes, else the pre-touch entry, else the path drops
    // (the actor created it).
    let resolve = |p: &String| -> Option<crate::snapshot::FileEntry> {
        effective
            .get(p)
            .cloned()
            .or_else(|| pre.get(p).cloned().flatten())
    };

    let mut files = Vec::new();
    for f in &head_m.files {
        if touched.contains(&f.path) {
            if let Some(e) = resolve(&f.path) {
                files.push(e);
            } // else: actor created it — drops out
        } else {
            files.push(f.clone());
        }
    }
    // Paths the actor deleted (absent from HEAD but in touched): bring
    // back whatever resolve finds, if anything.
    let head_paths: std::collections::HashSet<&str> =
        head_m.files.iter().map(|f| f.path.as_str()).collect();
    for p in &touched {
        if !head_paths.contains(p.as_str()) {
            if let Some(e) = resolve(p) {
                files.push(e);
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let mut vm = head_m;
    vm.files = files;
    vm.message = format!("surgical undo of actor '{actor}'");
    Ok((vm, touched.into_iter().collect()))
}
