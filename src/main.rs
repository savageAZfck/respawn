use clap::{Parser, Subcommand, ValueEnum};
use respawned::snapshot;
use respawned::{
    admin, anchor, apfs, audit, drift, fleet, guard, purge, revert, schedule, sync, watch, Error,
    Result, Store,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "respawn",
    about = "respawn: content-addressed snapshots, atomic revert, drift detection, LAN sync",
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
        /// Tag this snapshot with an actor name (RESPAWN_ACTOR works too)
        #[arg(long)]
        actor: Option<String>,
        /// Capture a true point-in-time cut via an APFS snapshot
        /// (macOS, requires root for mount_apfs)
        #[arg(long)]
        apfs: bool,
        /// Ask for admin authorization via the macOS GUI prompt
        /// instead of requiring sudo (only with --apfs)
        #[arg(long, requires = "apfs")]
        ask_admin: bool,
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
        /// Rehash every file — don't trust size+mtime (slower, airtight)
        #[arg(long)]
        full: bool,
    },
    /// Diff two snapshots (old -> new)
    Diff {
        old: String,
        #[arg(default_value = "head")]
        new: String,
    },
    /// Revert the worktree to a snapshot — or surgically undo one actor
    Revert {
        /// Snapshot ref (not needed with --actor)
        id: Option<String>,
        /// Undo only this actor's changes, keep everyone else's
        #[arg(long)]
        actor: Option<String>,
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
    /// Serve objects to peers on ADDR (default loopback only)
    Serve {
        #[arg(default_value = "127.0.0.1:4789")]
        addr: String,
        /// Broadcast a UDP discovery beacon
        #[arg(long)]
        announce: bool,
        /// Passphrase securing the transport (Noise NNpsk0). When set,
        /// plaintext connections are refused outright.
        #[arg(long)]
        psk: Option<String>,
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
        /// Passphrase the peer's `serve` was started with
        #[arg(long)]
        psk: Option<String>,
    },
    /// Snapshot, run a command, report its drift, optionally revert.
    /// Everything after `--` is the command.
    Guard {
        /// When to restore the pre-command snapshot
        #[arg(long, value_enum, default_value = "never")]
        revert: RevertArg,
        /// Rehash every file for the drift report (don't trust mtime)
        #[arg(long)]
        full: bool,
        /// Command to run under guard
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Signed external checkpoints of fabric state
    Anchor {
        #[command(subcommand)]
        sub: AnchorCmd,
    },
    /// Erase a path from the fabric's reach — tombstone it, sweep its
    /// objects, and issue a signed certificate of erasure
    Purge {
        /// Worktree-relative path to erase (omit with --verify)
        path: Option<String>,
        /// Verify a purge certificate instead of purging
        #[arg(long)]
        verify: Option<PathBuf>,
        /// Pin the expected signer public key (hex) when verifying
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Signed revert orders for peers under one fleet key
    Fleet {
        #[command(subcommand)]
        sub: FleetCmd,
    },
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Pin the fleet order-signing pubkey (first pin wins — remove
    /// .respawn/fleet.pub to re-pin)
    Trust { pubkey: String },
    /// Mint a signed order telling the fleet to land on SNAPSHOT
    Order {
        /// Snapshot ref every applying peer should land on
        to: String,
        /// Where the signed order file goes
        out: PathBuf,
    },
    /// Verify and apply a signed fleet order locally
    Apply {
        /// The signed order file
        file: PathBuf,
        /// Pull the target snapshot from this peer if missing
        #[arg(long)]
        from: Option<String>,
        /// Passphrase the peer's `serve` was started with
        #[arg(long)]
        psk: Option<String>,
        /// Apply even with un-snapshotted changes
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RevertArg {
    /// Leave the tree as the command left it
    Never,
    /// Restore only if the command exited non-zero
    OnFail,
    /// Always restore (ephemeral run)
    Always,
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Generate the anchor signing key (once — refuses to overwrite)
    Keygen,
    /// Print the anchor public key — record it off-fabric
    Pubkey,
    /// Sign a checkpoint of current state and write it to FILE
    Create {
        /// Where the anchor file goes — should live outside .respawn/
        file: PathBuf,
    },
    /// Write the next chained anchor into DIR under a timestamped
    /// name — what `anchor schedule`'s LaunchAgent invokes
    Next {
        /// Anchor directory (default: per-fabric dir under
        /// ~/Library/Application Support/respawn on macOS)
        dir: Option<PathBuf>,
    },
    /// Install (or --uninstall) a launchd agent that mints a chained
    /// anchor every N seconds — shrinks the unverifiable tail
    Schedule {
        /// Seconds between anchors (min 60)
        #[arg(long, default_value = "300")]
        every: u64,
        /// Anchor directory (default: per-fabric dir under
        /// ~/Library/Application Support/respawn)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Remove the scheduled agent
        #[arg(long)]
        uninstall: bool,
    },
    /// Verify an anchor against the live fabric
    Verify {
        /// Anchor file to check
        file: PathBuf,
        /// Pin the expected signer public key (hex)
        #[arg(long)]
        pubkey: Option<String>,
        /// Also verify this anchor chains to PREV (the previous anchor
        /// file) — apply pairwise over a stored series
        #[arg(long)]
        prev: Option<PathBuf>,
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

fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { dir } => {
            let dir = dir.canonicalize()?;
            Store::init(&dir)?;
            let store = Store::open(&dir)?;
            audit::record(&store, "init", dir.to_string_lossy().as_ref())?;
            println!("initialized respawn in {}", dir.display());
        }
        Cmd::Snap {
            message,
            actor,
            apfs,
            ask_admin,
        } => {
            let (store, root) = open_store()?;
            if ask_admin && !admin::is_root() {
                // Re-exec this snapshot through the macOS admin
                // prompt; the privileged child runs the ordinary
                // --apfs path and chowns the fabric back to us.
                let exe = std::env::current_exe()?.canonicalize()?;
                return admin::snap_as_admin(&exe, &root, &store.fabric_dir(), &message).map(|_| 0);
            }
            let _lock = store.try_lock()?;
            let actor = actor.or_else(|| std::env::var("RESPAWN_ACTOR").ok());
            let id = if apfs {
                // Frozen view: the ApfsSnap Drop unmounts and deletes
                // the cut however create_from returns — success or not.
                let frozen = apfs::create(&root)?;
                snapshot::create_from_actor(&store, frozen.scan_root(), &message, actor.as_deref())?
            } else {
                snapshot::create_from_actor(&store, &root, &message, actor.as_deref())?
            };
            audit::record(&store, "snap", &respawned::hash_hex(&id))?;
            println!("snapshot {}", respawned::hash_hex(&id));
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
                    respawned::short(&id),
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
            println!("snapshot {}", respawned::hash_hex(&id));
            if let Some(p) = m.parent {
                println!("parent   {}", respawned::hash_hex(&p));
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
        Cmd::Status { id, full } => {
            let (store, root) = open_store()?;
            let id = snapshot::resolve(&store, &id)?;
            let m = snapshot::load(&store, &id)?;
            let r = drift::detect(&root, &m, full)?;
            println!("drift vs {}:", respawned::short(&id));
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
            actor,
            keep_extra,
            force,
        } => {
            let (store, root) = open_store()?;
            let _lock = store.try_lock()?;
            if let Some(actor_name) = actor {
                // Surgical undo: virtual manifest where the actor's
                // snapshots never ran. keep_extra stays on — the bulk
                // removal pass can't tell actor files from user files,
                // so actor-only paths are removed explicitly below.
                let (vm, touched) = revert::surgical_manifest(&store, &actor_name)?;
                let vm_paths: std::collections::HashSet<&str> =
                    vm.files.iter().map(|f| f.path.as_str()).collect();
                let (drift_r, applied) = revert::check_then_apply(&store, &root, &vm, true, force)?;
                let r = match applied {
                    None => {
                        eprintln!("worktree has un-snapshotted changes:");
                        print_drift(&drift_r);
                        eprintln!("use --force to revert anyway");
                        return Err(Error::Corrupt("revert refused".into()));
                    }
                    Some(r) => r,
                };
                // Paths the actor created (touched but absent from the
                // virtual manifest) still sit on disk — remove them.
                // resolve_dest keeps the same ancestor-symlink defense
                // the main revert path uses.
                let mut removed_actor = 0u64;
                for p in &touched {
                    if !vm_paths.contains(p.as_str()) {
                        let dest = revert::resolve_dest(&root, p)?;
                        match std::fs::symlink_metadata(&dest) {
                            Ok(m) if m.is_file() || m.file_type().is_symlink() => {
                                std::fs::remove_file(&dest)?;
                                removed_actor += 1;
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(Error::Io(e)),
                        }
                    }
                }
                // Snapshot the result so HEAD tracks the undone tree.
                let nid = snapshot::create_from_actor(
                    &store,
                    &root,
                    &format!("surgical undo of actor '{actor_name}'"),
                    None,
                )?;
                audit::record(
                    &store,
                    "revert-actor",
                    &format!("{actor_name} {} paths", touched.len()),
                )?;
                println!(
                    "undid {} path(s) by '{actor_name}': {} restored, {} removed (snapshot {})",
                    touched.len(),
                    r.restored.len(),
                    removed_actor,
                    respawned::short(&nid)
                );
                return Ok(0);
            }
            let id =
                id.ok_or_else(|| Error::Corrupt("revert needs a snapshot ref or --actor".into()))?;
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
                            respawned::short(&id),
                            r.restored.len(),
                            r.removed.len()
                        ),
                    )?;
                    println!(
                        "reverted to {}: {} restored, {} removed, {} extra kept",
                        respawned::short(&id),
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
                    if !fan.file_type()?.is_dir() {
                        continue;
                    }
                    let fan_hex = fan.file_name().to_string_lossy().to_string();
                    for e in std::fs::read_dir(fan.path())? {
                        let e = e?;
                        let full = format!("{}{}", fan_hex, e.file_name().to_string_lossy());
                        if !respawned::is_hash_name(&full) {
                            continue; // foreign file, not an object
                        }
                        let h = respawned::parse_hash(&full)?;
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
        Cmd::Serve {
            addr,
            announce,
            psk,
        } => {
            let (store, _) = open_store()?;
            if !is_loopback(&addr) && psk.is_none() {
                eprintln!(
                    "warning: plaintext serve on {addr} — anyone who can reach it \
                     can read snapshotted content (use --psk for encrypted sync)"
                );
            } else if !is_loopback(&addr) && psk.is_some() {
                eprintln!("serving secured on {addr} (Noise NNpsk0)");
            }
            println!(
                "serving on {addr}{}{}",
                if psk.is_some() { " (secured)" } else { "" },
                if announce { " (announcing)" } else { "" }
            );
            sync::serve(store, &addr, announce, psk)?;
        }
        Cmd::Peers { secs } => {
            println!("listening {secs}s for beacons…");
            for p in sync::discover(secs)? {
                println!("  {}{}", p.addr, if p.secured { " (secured)" } else { "" });
            }
        }
        Cmd::Pull { addr, psk } => {
            let (store, _) = open_store()?;
            let _lock = store.try_lock()?;
            let r = sync::pull(&store, &addr, psk.as_deref())?;
            match r.remote_head {
                Some(h) => {
                    audit::record(
                        &store,
                        "pull",
                        &format!(
                            "{addr} head {} objects {}",
                            respawned::short(&h),
                            r.objects_fetched
                        ),
                    )?;
                    println!(
                        "pulled {} manifests, {} objects ({} skipped) from {addr}",
                        r.manifests_fetched, r.objects_fetched, r.objects_skipped
                    );
                    println!("remote head: {}", respawned::hash_hex(&h));
                }
                None => println!("remote has no snapshots"),
            }
        }
        Cmd::Guard { revert, full, cmd } => {
            let (store, root) = open_store()?;
            let policy = match revert {
                RevertArg::Never => guard::RevertPolicy::Never,
                RevertArg::OnFail => guard::RevertPolicy::OnFail,
                RevertArg::Always => guard::RevertPolicy::Always,
            };
            let report = guard::run(&store, &root, &cmd, policy, full)?;
            println!("guard snapshot {}", respawned::hash_hex(&report.snapshot));
            match (report.exit_code, report.signal) {
                (Some(c), _) => println!("command exited {c}"),
                (None, Some(sig)) => println!("command killed by signal {sig}"),
                (None, None) => println!("command status unknown"),
            }
            println!("drift vs guard snapshot:");
            print_drift(&report.drift);
            if report.reverted {
                println!("worktree restored to guard snapshot");
            } else if !report.drift.clean() {
                println!(
                    "undo with: respawn revert {} --force",
                    respawned::hash_hex(&report.snapshot)
                );
            }
            return Ok(report.process_exit_code());
        }
        Cmd::Purge {
            path,
            verify,
            pubkey,
        } => {
            let (store, root) = open_store()?;
            if let Some(cert) = verify {
                let out = purge::verify_cert(&store, &cert, pubkey.as_deref())?;
                println!("{out}");
                return Ok(0);
            }
            let path = path.ok_or_else(|| {
                Error::Corrupt("purge needs a worktree-relative path (or --verify)".into())
            })?;
            let _lock = store.try_lock()?;
            let r = purge::run(&store, &root, &path)?;
            println!(
                "purged {path}: {} chunks removed, {} shared-retained, cert {}",
                r.chunks_removed,
                r.chunks_retained_shared,
                r.cert_path.display()
            );
            if r.live_removed {
                println!("live file removed");
            }
            if let Some(n) = r.note {
                println!("note: {n}");
            }
        }
        Cmd::Fleet { sub } => {
            let (store, root) = open_store()?;
            match sub {
                FleetCmd::Trust { pubkey } => {
                    let _lock = store.try_lock()?;
                    fleet::trust(&store, &pubkey)?;
                    println!("fleet key pinned: {pubkey}");
                }
                FleetCmd::Order { to, out } => {
                    let _lock = store.try_lock()?;
                    let path = fleet::order(&store, &to, &out)?;
                    audit::record(&store, "fleet-order", &out.to_string_lossy())?;
                    println!("fleet order written to {}", path.display());
                }
                FleetCmd::Apply {
                    file,
                    from,
                    psk,
                    force,
                } => {
                    let _lock = store.try_lock()?;
                    let target =
                        fleet::apply(&store, &root, &file, from.as_deref(), psk.as_deref(), force)?;
                    println!("fleet revert applied: {}", respawned::hash_hex(&target));
                }
            }
        }
        Cmd::Anchor { sub } => {
            let (store, root) = open_store()?;
            match sub {
                AnchorCmd::Keygen => {
                    let _lock = store.try_lock()?;
                    let (pk, note) = anchor::keygen(&store)?;
                    audit::record(&store, "anchor-keygen", &pk)?;
                    println!("anchor pubkey: {pk}");
                    if let Some(n) = note {
                        println!("note: {n}");
                    }
                    println!("record it off-fabric — `anchor verify --pubkey` pins against it");
                }
                AnchorCmd::Pubkey => {
                    println!("{}", anchor::pubkey(&store)?);
                }
                AnchorCmd::Create { file } => {
                    let _lock = store.try_lock()?;
                    let out = anchor::create(&store, &file)?;
                    audit::record(&store, "anchor", &file.to_string_lossy())?;
                    println!(
                        "anchor written to {} (audit entries: {})",
                        file.display(),
                        out.audit_len
                    );
                    if let Some(n) = out.note {
                        println!("note: {n}");
                    }
                    println!("keep it outside .respawn/ — an anchor inside the thing it anchors proves nothing");
                }
                AnchorCmd::Next { dir } => {
                    let _lock = store.try_lock()?;
                    let dir = match dir {
                        Some(d) => d,
                        None => schedule::default_anchor_dir(&anchor::fabric_id(&store)?)?,
                    };
                    let (path, out) = anchor::next(&store, &dir)?;
                    audit::record(&store, "anchor", &path.to_string_lossy())?;
                    println!(
                        "anchor written to {} (audit entries: {})",
                        path.display(),
                        out.audit_len
                    );
                    if let Some(n) = out.note {
                        println!("note: {n}");
                    }
                }
                AnchorCmd::Schedule {
                    every,
                    dir,
                    uninstall,
                } => {
                    if uninstall {
                        let p = schedule::uninstall(&store)?;
                        println!("removed scheduled anchor ({})", p.display());
                    } else {
                        let spec = schedule::plan(&store, &root, dir, every)?;
                        schedule::install(&spec)?;
                        println!(
                            "scheduled {}: anchor every {}s → {}",
                            spec.label,
                            spec.every,
                            spec.anchor_dir.display()
                        );
                        println!("agent log: {}", spec.log.display());
                    }
                }
                AnchorCmd::Verify { file, pubkey, prev } => {
                    let out = anchor::verify(&store, &file, pubkey.as_deref())?;
                    println!("anchor valid — signed by {}", out.signer_pubkey);
                    println!("anchored audit prefix: {} entries intact", out.audit_len);
                    match (out.anchored_head, out.current_head) {
                        (a, c) if a == c => println!("HEAD unchanged since anchor"),
                        (a, c) => println!(
                            "HEAD moved (normal — new snapshots): {} -> {}",
                            a.unwrap_or_else(|| "none".into()),
                            c.unwrap_or_else(|| "none".into())
                        ),
                    }
                    match (&out.prev_anchor, &prev) {
                        (None, None) => println!("chain link: none (first anchor)"),
                        (Some(h), None) => println!(
                            "chain link: anchors to {} (pass --prev <file> to check it)",
                            &h[..12]
                        ),
                        (None, Some(_)) => {
                            return Err(Error::Corrupt(
                                "--prev given but anchor has no chain link".into(),
                            ));
                        }
                        (Some(_), Some(p)) => {
                            anchor::verify_link(&file, p)?;
                            println!("chain link verified against {}", p.display());
                        }
                    }
                }
            }
        }
    }
    Ok(0)
}

fn is_loopback(addr: &str) -> bool {
    addr.split(':')
        .next()
        .map(|h| h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]")
        .unwrap_or(false)
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
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
