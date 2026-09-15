use clap::{Parser, Subcommand};
use respawn::snapshot;
use respawn::{audit, drift, revert, sync, watch, Error, Result, Store};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "respawn",
    about = "Versioned respawn: snapshots, atomic revert, drift detection, LAN sync",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a fabric in DIR (default: current directory)
    Init {
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    /// Snapshot the worktree
    Snap {
        /// Snapshot message
        #[arg(short, long, default_value = "")]
        message: String,
    },
    /// List snapshots, newest first
    Log {
        /// Max entries
        #[arg(short, long, default_value = "20")]
        n: usize,
    },
    /// Show a manifest's contents
    Show {
        /// Snapshot ref: hex id, unique prefix, or 'head'
        #[arg(default_value = "head")]
        id: String,
    },
    /// Drift between the live worktree and HEAD (or a given snapshot)
    Status {
        #[arg(default_value = "head")]
        id: String,
    },
    /// Diff two snapshots (old -> new)
    Diff {
        old: String,
        #[arg(default_value = "head")]
        new: String,
    },
    /// Revert the worktree to a snapshot
    Revert {
        /// Snapshot ref
        id: String,
        /// Keep files the snapshot doesn't know about
        #[arg(long)]
        keep_extra: bool,
        /// Revert even with un-snapshotted changes
        #[arg(long)]
        force: bool,
    },
    /// Watch the worktree and print drift events live
    Watch,
    /// Verify the audit chain and (with --objects) all stored content
    Verify {
        /// Rehash every object — slow on large stores
        #[arg(long)]
        objects: bool,
    },
    /// Serve objects to peers on ADDR (default :4789)
    Serve {
        #[arg(default_value = "0.0.0.0:4789")]
        addr: String,
        /// Broadcast a UDP discovery beacon
        #[arg(long)]
        announce: bool,
    },
    /// Discover announcing peers on the LAN
    Peers {
        /// Seconds to listen
        #[arg(short, long, default_value = "3")]
        secs: u64,
    },
    /// Pull a peer's history into the local store
    Pull {
        /// Peer address, host:port
        addr: String,
    },
}

fn open_store() -> Result<(Store, PathBuf)> {
    let root = Store::find_root(&std::env::current_dir()?)?;
    Ok((Store::open(&root)?, root))
}

fn print_drift(r: &drift::DriftReport) {
    if r.clean() {
        println!("clean — worktree matches snapshot");
        return;
    }
    for p in &r.added {
        println!("  + {p}");
    }
    for p in &r.modified {
        println!("  ~ {p}");
    }
    for p in &r.deleted {
        println!("  - {p}");
    }
    for p in &r.touched {
        println!("  . {p} (metadata only)");
    }
    println!(
        "{} added, {} modified, {} deleted",
        r.added.len(),
        r.modified.len(),
        r.deleted.len()
    );
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { dir } => {
            let dir = dir.canonicalize()?;
            Store::init(&dir)?;
            let store = Store::open(&dir)?;
            audit::record(&store, "init", dir.to_string_lossy().as_ref())?;
            println!("initialized respawn in {}", dir.display());
        }
        Cmd::Snap { message } => {
            let (store, root) = open_store()?;
            let id = snapshot::create(&store, &root, &message)?;
            audit::record(&store, "snap", &respawn::hash_hex(&id))?;
            println!("snapshot {}", respawn::hash_hex(&id));
        }
        Cmd::Log { n } => {
            let (store, _) = open_store()?;
            let head = store.head()?;
            for (id, m) in snapshot::list(&store)?.into_iter().take(n) {
                let mark = if Some(id) == head { " <-- HEAD" } else { "" };
                let msg = if m.message.is_empty() {
                    String::new()
                } else {
                    format!("  {}", m.message)
                };
                println!(
                    "{}  {}{}  ({} files){}",
                    respawn::short(&id),
                    chrono_ts(m.timestamp_secs),
                    msg,
                    m.files.len(),
                    mark
                );
            }
        }
        Cmd::Show { id } => {
            let (store, _) = open_store()?;
            let id = snapshot::resolve(&store, &id)?;
            let m = snapshot::load(&store, &id)?;
            println!("snapshot {}", respawn::hash_hex(&id));
            if let Some(p) = m.parent {
                println!("parent   {}", respawn::hash_hex(&p));
            }
            println!("time     {}", chrono_ts(m.timestamp_secs));
            if !m.message.is_empty() {
                println!("message  {}", m.message);
            }
            println!("files    {}", m.files.len());
            for f in &m.files {
                println!("  {:>10}  {}", f.size, f.path);
            }
        }
        Cmd::Status { id } => {
            let (store, root) = open_store()?;
            let id = snapshot::resolve(&store, &id)?;
            let m = snapshot::load(&store, &id)?;
            let r = drift::detect(&root, &m)?;
            println!("drift vs {}:", respawn::short(&id));
            print_drift(&r);
        }
        Cmd::Diff { old, new } => {
            let (store, _) = open_store()?;
            let a = snapshot::load(&store, &snapshot::resolve(&store, &old)?)?;
            let b = snapshot::load(&store, &snapshot::resolve(&store, &new)?)?;
            let (added, modified, deleted) = snapshot::diff_manifests(&b, &a);
            for p in &added {
                println!("  + {p}");
            }
            for p in &modified {
                println!("  ~ {p}");
            }
            for p in &deleted {
                println!("  - {p}");
            }
            println!(
                "{} added, {} modified, {} deleted",
                added.len(),
                modified.len(),
                deleted.len()
            );
        }
        Cmd::Revert {
            id,
            keep_extra,
            force,
        } => {
            let (store, root) = open_store()?;
            let id = snapshot::resolve(&store, &id)?;
            let m = snapshot::load(&store, &id)?;
            let (drift_r, applied) =
                revert::check_then_apply(&store, &root, &m, keep_extra, force)?;
            match applied {
                None => {
                    eprintln!("worktree has un-snapshotted changes:");
                    print_drift(&drift_r);
                    eprintln!("use --force to revert anyway");
                    return Err(Error::Corrupt("revert refused".into()));
                }
                Some(r) => {
                    store.set_head(Some(&id))?;
                    audit::record(
                        &store,
                        "revert",
                        &format!(
                            "{} restored {} removed {}",
                            respawn::short(&id),
                            r.restored.len(),
                            r.removed.len()
                        ),
                    )?;
                    println!(
                        "reverted to {}: {} restored, {} removed, {} extra kept",
                        respawn::short(&id),
                        r.restored.len(),
                        r.removed.len(),
                        r.skipped_extra.len()
                    );
                }
            }
        }
        Cmd::Watch => {
            let (store, root) = open_store()?;
            println!("watching {} — ctrl-c to stop", root.display());
            watch::watch_loop(&root, |paths| {
                for p in &paths {
                    println!("  ~ {p}");
                }
                println!("{} paths changed", paths.len());
            })?;
            drop(store);
        }
        Cmd::Verify { objects } => {
            let (store, _) = open_store()?;
            let r = audit::verify(&store)?;
            if r.valid {
                println!("audit chain valid ({} entries)", r.entries);
            } else {
                println!("audit chain BROKEN at seq {:?}", r.first_bad);
            }
            if objects {
                let mut checked = 0u64;
                let mut bad = 0u64;
                let odir = store.fabric_dir().join("objects");
                for fan in std::fs::read_dir(&odir)? {
                    let fan = fan?;
                    let fan_hex = fan.file_name().to_string_lossy().to_string();
                    for e in std::fs::read_dir(fan.path())? {
                        let e = e?;
                        let full = format!("{}{}", fan_hex, e.file_name().to_string_lossy());
                        let h = respawn::parse_hash(&full)?;
                        match store.get_object(&h) {
                            Ok(_) => checked += 1,
                            Err(_) => bad += 1,
                        }
                    }
                }
                println!("objects: {} verified, {} corrupt", checked, bad);
                if bad > 0 {
                    return Err(Error::Corrupt("object verification failed".into()));
                }
            }
            if !r.valid {
                return Err(Error::Corrupt("audit chain invalid".into()));
            }
        }
        Cmd::Serve { addr, announce } => {
            let (store, _) = open_store()?;
            println!(
                "serving on {addr}{}",
                if announce { " (announcing)" } else { "" }
            );
            sync::serve(store, &addr, announce)?;
        }
        Cmd::Peers { secs } => {
            println!("listening {secs}s for beacons…");
            for p in sync::discover(secs)? {
                println!("  {p}");
            }
        }
        Cmd::Pull { addr } => {
            let (store, _) = open_store()?;
            let r = sync::pull(&store, &addr)?;
            match r.remote_head {
                Some(h) => {
                    audit::record(
                        &store,
                        "pull",
                        &format!(
                            "{addr} head {} objects {}",
                            respawn::short(&h),
                            r.objects_fetched
                        ),
                    )?;
                    println!(
                        "pulled {} manifests, {} objects ({} skipped) from {addr}",
                        r.manifests_fetched, r.objects_fetched, r.objects_skipped
                    );
                    println!("remote head: {}", respawn::hash_hex(&h));
                }
                None => println!("remote has no snapshots"),
            }
        }
    }
    Ok(())
}

fn chrono_ts(secs: u64) -> String {
    // Minimal UTC timestamp without a chrono dep.
    let days = secs / 86400;
    let rem = secs % 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Howard Hinnant's civil-from-days algorithm.
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
