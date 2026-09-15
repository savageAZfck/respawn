//! Hash-chained audit log.
//!
//! Every state-changing operation appends a JSON line to
//! `.respawn/audit.jsonl`. Each entry's `hash` covers the previous
//! hash plus the entry body — deleting, editing, or reordering lines
//! breaks the chain and is detected by `verify`.
//!
//! This is the same model as sovereign_ledger; the fabric keeps its own
//! lightweight chain so the CLI stays self-contained.

use crate::{hash_bytes, Result, Store};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub event: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

fn entry_hash(seq: u64, ts: u64, event: &str, detail: &str, prev: &str) -> String {
    // Serialize the tuple rather than joining with a separator — a
    // delimiter inside a field could otherwise collide two different
    // entries onto the same hash input.
    let body = serde_json::to_string(&(seq, ts, event, detail, prev))
        .unwrap_or_else(|_| format!("{seq}{ts}"));
    hex::encode(hash_bytes(body.as_bytes()))
}

fn audit_path(store: &Store) -> std::path::PathBuf {
    store.fabric_dir().join("audit.jsonl")
}

/// Append an event. `detail` is a short free-form string (snapshot id,
/// peer addr, drift counts, ...).
pub fn record(store: &Store, event: &str, detail: &str) -> Result<()> {
    let path = audit_path(store);
    fs::create_dir_all(path.parent().unwrap())?;

    let (mut seq, mut prev) = (0u64, String::new());
    if let Ok(f) = fs::File::open(&path) {
        for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
            if let Ok(e) = serde_json::from_str::<AuditEntry>(&line) {
                seq = e.seq + 1;
                prev = e.hash;
            }
        }
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hash = entry_hash(seq, ts, event, detail, &prev);
    let entry = AuditEntry {
        seq,
        ts,
        event: event.to_string(),
        detail: detail.to_string(),
        prev,
        hash,
    };
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(serde_json::to_string(&entry)?.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub valid: bool,
    pub first_bad: Option<u64>,
}

/// Recompute the chain from the first line. Detects edits, deletes,
/// reordering, and truncation of the tail only if the file was replaced
/// wholesale — a chain that is internally valid but *shorter* than the
/// last-seen state cannot be distinguished from a fresh log without an
/// external anchor. Same caveat as sovereign_ledger's unsigned mode.
pub fn verify(store: &Store) -> Result<VerifyReport> {
    let path = audit_path(store);
    let mut report = VerifyReport {
        entries: 0,
        valid: true,
        first_bad: None,
    };
    if !path.exists() {
        return Ok(report);
    }
    let f = fs::File::open(&path)?;
    let mut prev = String::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let e: AuditEntry = serde_json::from_str(&line)
            .map_err(|_| crate::Error::Corrupt(format!("audit line {} unparsable", i + 1)))?;
        let expected = entry_hash(e.seq, e.ts, &e.event, &e.detail, &prev);
        if e.seq != report.entries || e.prev != prev || e.hash != expected {
            report.valid = false;
            report.first_bad = Some(e.seq);
            return Ok(report);
        }
        prev = e.hash;
        report.entries += 1;
    }
    Ok(report)
}
