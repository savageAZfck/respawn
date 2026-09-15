//! Drift detection: compare the live worktree against a manifest.
//!
//! Fast path trusts (size, mtime) to skip hashing unchanged files; any
//! file whose metadata differs is rehashed. The report is the same shape
//! as a manifest diff: added / modified / deleted.

use crate::snapshot::{FileEntry, Manifest};
use crate::{Hash, Result, FABRIC_DIR};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct DriftReport {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    /// Files whose metadata changed but content did not.
    pub touched: Vec<String>,
}

impl DriftReport {
    pub fn clean(&self) -> bool {
        self.added.is_empty()
            && self.modified.is_empty()
            && self.deleted.is_empty()
            && self.touched.is_empty()
    }
}

fn file_hash(path: &Path) -> Result<Hash> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn excluded(rel: &Path) -> bool {
    rel.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == FABRIC_DIR || s == ".git" || s == ".DS_Store"
    })
}

/// Compute drift of the live worktree vs `manifest`.
pub fn detect(root: &Path, manifest: &Manifest) -> Result<DriftReport> {
    let expected: HashMap<&str, &FileEntry> = manifest
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut report = DriftReport::default();

    let ignore: Vec<String> = fs::read_to_string(root.join(".fabricignore"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel: PathBuf = entry.path().strip_prefix(root).unwrap().to_path_buf();
        if excluded(&rel) {
            continue;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if ignore.iter().any(|p| rel_str.contains(p.as_str())) {
            continue;
        }
        seen.insert(rel_str.clone());

        let meta = entry.metadata()?;
        match expected.get(rel_str.as_str()) {
            None => report.added.push(rel_str),
            Some(fe) => {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if meta.len() == fe.size && mtime == fe.mtime_secs {
                    continue; // fast path: untouched
                }
                let h = file_hash(entry.path())?;
                if h != fe.content {
                    report.modified.push(rel_str);
                } else {
                    report.touched.push(rel_str);
                }
            }
        }
    }

    for p in expected.keys() {
        if !seen.contains(*p) {
            report.deleted.push(p.to_string());
        }
    }

    report.added.sort();
    report.modified.sort();
    report.deleted.sort();
    report.touched.sort();
    Ok(report)
}
