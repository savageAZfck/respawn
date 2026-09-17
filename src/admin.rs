//! `snap --apfs --ask-admin` — re-run the snapshot through macOS admin
//! authorization instead of requiring `sudo respawn`.
//!
//! `mount_apfs` needs root, and `do shell script ... with
//! administrator privileges` is the smallest honest escalation: one
//! GUI prompt, one privileged child, no installed helper. The
//! privileged command is `respawn snap --apfs` itself, followed by a
//! `chown -R` of `.respawn/` back to the invoking user — without it,
//! root-written objects and HEAD would poison every later unprivileged
//! snap.
//!
//! Two distinct escape layers keep paths safe: each argv element is
//! single-quoted for `/bin/sh` (what `do shell script` runs), then the
//! assembled command is escaped for the AppleScript string literal.
//! Nothing is ever interpolated raw.

use crate::{Error, Result};
use std::path::Path;
use std::process::Command;

/// Single-quote a string for POSIX sh: wrap in `'…'`, each embedded
/// `'` becomes `'\''`. Inside single quotes nothing expands — no `$`,
/// no backticks, no escapes.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape a string for an AppleScript double-quoted literal — only
/// `\` and `"` are special there.
pub fn as_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn run_capture(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(cmd).args(args).output().map_err(Error::Io)
}

fn uid() -> Result<String> {
    let out = run_capture("id", &["-u"])?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn gid() -> Result<String> {
    let out = run_capture("id", &["-g"])?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build the AppleScript — separated from execution so tests can
/// inspect exactly what would run.
#[cfg(target_os = "macos")]
fn admin_script(exe: &Path, worktree: &Path, fabric: &Path, message: &str) -> Result<String> {
    let uid = uid()?;
    let gid = gid()?;
    let shell = format!(
        "cd {wt} && {exe} snap --apfs -m {msg} && /usr/sbin/chown -R {uid}:{gid} {fab}",
        wt = sh_quote(&worktree.to_string_lossy()),
        exe = sh_quote(&exe.to_string_lossy()),
        msg = sh_quote(message),
        fab = sh_quote(&fabric.to_string_lossy()),
    );
    Ok(format!(
        "do shell script \"{}\" with administrator privileges",
        as_escape(&shell)
    ))
}

/// Run `respawn snap --apfs` as an admin-authorized child, streaming
/// its output through. Cancelled authorization (osascript -128) is a
/// distinct honest error from a failed snapshot.
#[cfg(target_os = "macos")]
pub fn snap_as_admin(exe: &Path, worktree: &Path, fabric: &Path, message: &str) -> Result<()> {
    let script = admin_script(exe, worktree, fabric, message)?;
    let out = run_capture("/usr/bin/osascript", &["-e", &script])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        if stderr.contains("-128") || stderr.contains("User canceled") {
            return Err(Error::Corrupt("admin authorization cancelled".into()));
        }
        return Err(Error::Corrupt(format!(
            "privileged snapshot failed: {}",
            stderr.trim()
        )));
    }
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn snap_as_admin(_exe: &Path, _worktree: &Path, _fabric: &Path, _message: &str) -> Result<()> {
    Err(Error::Corrupt(
        "--ask-admin uses macOS administrator authorization — macOS-only".into(),
    ))
}

/// True when euid is 0 — `--ask-admin` is pointless (and the osascript
/// round-trip needless) when already root.
pub fn is_root() -> bool {
    uid().map(|u| u == "0").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_blocks_expansion() {
        // The classic breakouts all collapse to literal bytes.
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("`id`"), "'`id`'");
    }

    #[test]
    fn as_escape_covers_both_metachars() {
        assert_eq!(as_escape(r#"a\b"c"#), r#"a\\b\"c"#);
    }
}
