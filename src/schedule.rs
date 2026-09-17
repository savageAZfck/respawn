//! `respawn anchor schedule` — a launchd LaunchAgent that mints
//! chained anchors on an interval, shrinking the unverifiable tail of
//! the audit log to the interval itself.
//!
//! The agent runs `respawn anchor next <dir>` with the worktree as its
//! WorkingDirectory, so it anchors exactly the fabric it was installed
//! for. Plist generation is pure and cross-platform (it is just XML);
//! install/uninstall are launchd operations and macOS-only.

use crate::{anchor, Error, Result, Store};
use std::fs;
use std::path::{Path, PathBuf};

/// Floor on StartInterval — anchoring more often than once a minute is
/// churn, not coverage.
pub const MIN_INTERVAL_SECS: u64 = 60;

/// Everything install needs, resolved and validated up front — the
/// plist is generated only from checked values.
pub struct ScheduleSpec {
    /// LaunchAgent label: com.respawn.anchor.<fabric-id prefix>.
    pub label: String,
    /// Absolute path to the respawn binary that will run.
    pub exe: PathBuf,
    /// Worktree root — the agent's WorkingDirectory.
    pub worktree: PathBuf,
    /// Directory the timestamped anchors land in.
    pub anchor_dir: PathBuf,
    /// StartInterval seconds.
    pub every: u64,
    /// stdout/stderr target for the agent.
    pub log: PathBuf,
    /// ~/Library/LaunchAgents/<label>.plist
    pub plist_path: PathBuf,
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| Error::Corrupt("HOME is not set — cannot locate LaunchAgents".into()))
}

fn launch_agents_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join("Library/LaunchAgents"))
}

/// Default anchor directory: outside every fabric, per-fabric, and in
/// the macOS-idiomatic Application Support location (a dotdir
/// elsewhere). `anchor next` uses the same default so manual and
/// scheduled runs share a chain.
pub fn default_anchor_dir(fabric_id: &str) -> Result<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        home_dir()?.join("Library/Application Support/respawn/anchors")
    } else {
        home_dir()?.join(".respawn-anchors")
    };
    Ok(base.join(&fabric_id[..fabric_id.len().min(12)]))
}

/// Resolve and validate a schedule install: real fabric, loadable
/// anchor key (an agent without one just fails every interval), sane
/// interval, anchor dir outside the fabric, executable binary.
pub fn plan(
    store: &Store,
    worktree: &Path,
    dir: Option<PathBuf>,
    every: u64,
) -> Result<ScheduleSpec> {
    if every < MIN_INTERVAL_SECS {
        return Err(Error::Corrupt(format!(
            "--every must be >= {MIN_INTERVAL_SECS}s"
        )));
    }
    // A schedule whose key cannot load produces failures forever —
    // check it now, while a human is watching.
    anchor::pubkey(store)
        .map_err(|_| Error::Corrupt("no anchor key — run `respawn anchor keygen` first".into()))?;
    let fabric_id = anchor::fabric_id(store)?;
    let anchor_dir = dir.unwrap_or(default_anchor_dir(&fabric_id)?);

    // Same rule as `anchor create`: anchors inside the fabric they
    // protect can be replaced alongside it. The dir may not exist yet,
    // so canonicalize the parent, not the path.
    let parent = anchor_dir.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(canon_parent) = parent.canonicalize() {
        let candidate = canon_parent.join(anchor_dir.file_name().unwrap_or_default());
        let fabric = store
            .fabric_dir()
            .canonicalize()
            .unwrap_or_else(|_| store.fabric_dir());
        if candidate.starts_with(&fabric) {
            return Err(Error::Corrupt(
                "anchor dir must live outside .respawn/".into(),
            ));
        }
    }

    let exe = std::env::current_exe()?.canonicalize()?;
    if !exe.exists() {
        return Err(Error::Corrupt(format!(
            "respawn binary not found at {}",
            exe.display()
        )));
    }
    let label = format!(
        "com.respawn.anchor.{}",
        &fabric_id[..fabric_id.len().min(12)]
    );
    Ok(ScheduleSpec {
        plist_path: launch_agents_dir()?.join(format!("{label}.plist")),
        log: home_dir()?
            .join("Library/Logs/respawn")
            .join(format!("anchor-{label}.log")),
        label,
        exe,
        worktree: worktree.to_path_buf(),
        anchor_dir,
        every,
    })
}

/// XML-escape a plist string value. Paths and labels are user data —
/// an unescaped `<`/`&` produces a plist launchd silently refuses.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The plist document. `RunAtLoad` gives immediate feedback — install
/// either anchors at once or fails where the operator can see it.
pub fn plist_xml(spec: &ScheduleSpec) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n<dict>\n",
            "\t<key>Label</key>\n\t<string>{label}</string>\n",
            "\t<key>ProgramArguments</key>\n\t<array>\n",
            "\t\t<string>{exe}</string>\n",
            "\t\t<string>anchor</string>\n",
            "\t\t<string>next</string>\n",
            "\t\t<string>{dir}</string>\n",
            "\t</array>\n",
            "\t<key>WorkingDirectory</key>\n\t<string>{wt}</string>\n",
            "\t<key>StartInterval</key>\n\t<integer>{every}</integer>\n",
            "\t<key>RunAtLoad</key>\n\t<true/>\n",
            "\t<key>StandardOutPath</key>\n\t<string>{log}</string>\n",
            "\t<key>StandardErrorPath</key>\n\t<string>{log}</string>\n",
            "</dict>\n</plist>\n"
        ),
        label = xml_escape(&spec.label),
        exe = xml_escape(&spec.exe.to_string_lossy()),
        dir = xml_escape(&spec.anchor_dir.to_string_lossy()),
        wt = xml_escape(&spec.worktree.to_string_lossy()),
        every = spec.every,
        log = xml_escape(&spec.log.to_string_lossy()),
    )
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(Error::Io)?;
    if !out.status.success() {
        return Err(Error::Corrupt(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = crate::tmp_path(dir, "plist");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Install the agent: write the plist, then hand it to launchd.
/// `bootstrap` is the modern verb but returns "Input/output error" on
/// some systems — `load -w` still works there, so it is the fallback,
/// not a failure.
#[cfg(target_os = "macos")]
pub fn install(spec: &ScheduleSpec) -> Result<()> {
    fs::create_dir_all(&spec.anchor_dir)?;
    if let Some(d) = spec.log.parent() {
        fs::create_dir_all(d)?;
    }
    fs::create_dir_all(launch_agents_dir()?)?;
    atomic_write(&spec.plist_path, plist_xml(spec).as_bytes())?;

    let uid = run("id", &["-u"]).map(|s| s.trim().to_string())?;
    let domain = format!("gui/{uid}");
    let plist = spec.plist_path.to_string_lossy().to_string();
    if run("launchctl", &["bootstrap", &domain, &plist]).is_err() {
        run("launchctl", &["load", "-w", &plist]).inspect_err(|_| {
            let _ = fs::remove_file(&spec.plist_path);
        })?;
    }
    Ok(())
}

/// Remove the agent: bootout (or unload), then delete exactly the
/// plist this fabric would have installed — the path is derived from
/// the fabric id, never taken from input, so it cannot escape
/// ~/Library/LaunchAgents.
#[cfg(target_os = "macos")]
pub fn uninstall(store: &Store) -> Result<PathBuf> {
    let fabric_id = anchor::fabric_id(store)?;
    let label = format!(
        "com.respawn.anchor.{}",
        &fabric_id[..fabric_id.len().min(12)]
    );
    let plist = launch_agents_dir()?.join(format!("{label}.plist"));
    if !plist.exists() {
        return Err(Error::Corrupt(format!(
            "no scheduled anchor for this fabric ({})",
            plist.display()
        )));
    }
    let uid = run("id", &["-u"]).map(|s| s.trim().to_string())?;
    // bootout fails if not loaded — that is fine, removal is the point.
    if run("launchctl", &["bootout", &format!("gui/{uid}/{label}")]).is_err() {
        let _ = run("launchctl", &["unload", &plist.to_string_lossy()]);
    }
    fs::remove_file(&plist)?;
    Ok(plist)
}

#[cfg(not(target_os = "macos"))]
pub fn install(_spec: &ScheduleSpec) -> Result<()> {
    Err(Error::Corrupt(
        "anchor schedule uses launchd — macOS-only (use systemd timers or cron elsewhere)".into(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall(_store: &Store) -> Result<PathBuf> {
    Err(Error::Corrupt(
        "anchor schedule uses launchd — macOS-only".into(),
    ))
}
