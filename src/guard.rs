//! Guard: snapshot the worktree, run a command, report what it changed.
//!
//! The agent-era use case: wrap anything that writes to the tree —
//! `respawn guard -- cargo test`, `respawn guard -- ./agent run` — and
//! get a before-state, a drift report, and a one-command undo path
//! (`revert head --force` restores the guard snapshot). The fabric lock
//! is held for the child's whole lifetime: nothing else may mutate the
//! fabric while a guarded process is mid-write.

use crate::{audit, drift, revert, snapshot, Error, Hash, Result, Store};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertPolicy {
    /// Leave the tree as the command left it.
    Never,
    /// Restore the guard snapshot only if the command failed.
    OnFail,
    /// Always restore the guard snapshot (ephemeral run).
    Always,
}

#[derive(Debug)]
pub struct GuardReport {
    /// The pre-command snapshot; restoring it undoes everything the
    /// command wrote.
    pub snapshot: Hash,
    /// Child exit code; None if the child was killed by a signal.
    pub exit_code: Option<i32>,
    /// Signal that killed the child, if any.
    pub signal: Option<i32>,
    /// What the command changed, relative to the guard snapshot.
    pub drift: drift::DriftReport,
    /// Whether the worktree was restored to the guard snapshot.
    pub reverted: bool,
}

impl GuardReport {
    /// Process exit code suitable for propagating out of `main`: the
    /// child's own code, or 128+signal — the shell convention — so a
    /// guard-wrapped pipeline sees the same status as the bare command.
    pub fn process_exit_code(&self) -> i32 {
        match (self.exit_code, self.signal) {
            (Some(c), _) => c,
            (None, Some(sig)) => 128 + sig,
            (None, None) => 1,
        }
    }
}

/// Snapshot `root`, run `argv[0..]` *with the worktree root as cwd*
/// and inherited stdio, then diff the tree against the snapshot. The
/// root-as-cwd contract is deliberate: `respawn guard` protects the
/// worktree, so the command sees that tree regardless of where the CLI
/// was invoked. If `policy` calls for a revert, the guard snapshot is
/// materialized back over whatever the command wrote.
pub fn run(
    store: &Store,
    root: &Path,
    argv: &[String],
    policy: RevertPolicy,
    full_drift: bool,
) -> Result<GuardReport> {
    if argv.is_empty() {
        return Err(Error::Corrupt("guard requires a command".into()));
    }
    let _lock = store.try_lock()?;

    let cmd_display = argv.join(" ");
    let prev_head = store.head()?;
    let snap = snapshot::create(store, root, &format!("guard: {cmd_display}"))?;

    let spawned = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(root)
        .status();
    let status = match spawned {
        Ok(s) => s,
        Err(e) => {
            // Nothing ran — put HEAD back so the guard snap does not
            // masquerade as a checkpoint of a run that never happened.
            store.set_head(prev_head.as_ref())?;
            return Err(Error::Io(e));
        }
    };

    let manifest = snapshot::load(store, &snap)?;
    let report = drift::detect(root, &manifest, full_drift)?;

    let failed = !status.success();
    let should_revert = match policy {
        RevertPolicy::Always => true,
        RevertPolicy::OnFail => failed,
        RevertPolicy::Never => false,
    };
    let reverted = if should_revert {
        revert::apply(store, root, &manifest, false)?;
        store.set_head(Some(&snap))?;
        true
    } else {
        false
    };

    let (exit_code, signal) = status_parts(&status);
    audit::record(
        store,
        "guard",
        &format!(
            "{cmd_display} exit {} drift +{} ~{} -{}{}",
            exit_code.unwrap_or(-1),
            report.added.len(),
            report.modified.len(),
            report.deleted.len(),
            if reverted { " reverted" } else { "" }
        ),
    )?;

    Ok(GuardReport {
        snapshot: snap,
        exit_code,
        signal,
        drift: report,
        reverted,
    })
}

#[cfg(unix)]
fn status_parts(status: &std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    (status.code(), status.signal())
}

#[cfg(not(unix))]
fn status_parts(status: &std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    (status.code(), None)
}
