//! LAN sync: replicate objects and manifests between peers.
//!
//! Wire protocol (TCP, little-endian):
//!   frame = u32 len + payload
//!   payload[0] = opcode
//!     0x01 GET_HEAD      → [has:u8][hash:32]
//!     0x02 GET_MANIFEST  + hash → u64 len + bytes (0 = missing)
//!     0x03 HAVE          + u32 n + n hashes → n bytes (0/1)
//!     0x04 GET_OBJECT    + hash → u64 len + bytes (0 = missing)
//!
//! Receivers verify every object's BLAKE3 before storing — a hostile or
//! corrupted peer cannot poison the store. `serve --announce` also
//! broadcasts a UDP beacon so `peers` can discover listeners without
//! knowing addresses.

use crate::{Error, Hash, Result, Store};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 4789;
pub const BEACON_PORT: u16 = 47810;
const MAGIC: &[u8; 5] = b"SFAB1";

const OP_GET_HEAD: u8 = 0x01;
const OP_GET_MANIFEST: u8 = 0x02;
const OP_HAVE: u8 = 0x03;
const OP_GET_OBJECT: u8 = 0x04;

const MAX_FRAME: usize = 64 * 1024 * 1024;
const MAX_MANIFESTS_PER_PULL: usize = 100_000;
const MAX_OBJECTS_PER_PULL: usize = 8_000_000;
/// Hashes per HAVE request — keeps request frames well under MAX_FRAME.
const HAVE_BATCH: usize = 500_000;
const MAX_CONNECTIONS: usize = 64;

fn read_u64(frame: &[u8]) -> Result<u64> {
    if frame.len() < 8 {
        return Err(Error::Sync("short frame".into()));
    }
    Ok(u64::from_le_bytes(frame[..8].try_into().unwrap()))
}

fn frame_payload(frame: &[u8]) -> Result<&[u8]> {
    let len = read_u64(frame)? as usize;
    if len == 0 {
        return Ok(&[]);
    }
    if frame.len() < 8 + len {
        return Err(Error::Sync("truncated frame payload".into()));
    }
    Ok(&frame[8..8 + len])
}

fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::Sync("frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame(s: &mut TcpStream, payload: &[u8]) -> Result<()> {
    s.write_all(&(payload.len() as u32).to_le_bytes())?;
    s.write_all(payload)?;
    Ok(())
}

fn respond(s: &mut TcpStream, store: &Store, frame: &[u8]) -> Result<()> {
    match frame.first().copied() {
        Some(OP_GET_HEAD) => {
            let head = store.head()?;
            let mut out = vec![if head.is_some() { 1u8 } else { 0u8 }];
            if let Some(h) = head {
                out.extend_from_slice(&h);
            }
            write_frame(s, &out)?;
        }
        Some(OP_GET_MANIFEST) if frame.len() == 33 => {
            let h: Hash = frame[1..].try_into().unwrap();
            let data = if store.has_manifest(&h) {
                store.get_manifest_bytes(&h)?
            } else {
                Vec::new()
            };
            let mut out = (data.len() as u64).to_le_bytes().to_vec();
            out.extend_from_slice(&data);
            write_frame(s, &out)?;
        }
        Some(OP_HAVE) if frame.len() >= 5 => {
            let n = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
            if frame.len() != 5 + n * 32 {
                return Err(Error::Sync("malformed HAVE".into()));
            }
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let h: Hash = frame[5 + i * 32..5 + (i + 1) * 32].try_into().unwrap();
                out.push(if store.has_object(&h) { 1u8 } else { 0u8 });
            }
            write_frame(s, &out)?;
        }
        Some(OP_GET_OBJECT) if frame.len() == 33 => {
            let h: Hash = frame[1..].try_into().unwrap();
            let data = store.get_object(&h).unwrap_or_default();
            let mut out = (data.len() as u64).to_le_bytes().to_vec();
            out.extend_from_slice(&data);
            write_frame(s, &out)?;
        }
        _ => return Err(Error::Sync("unknown opcode".into())),
    }
    Ok(())
}

/// Serve object requests on `addr` until killed. `--announce` spawns a
/// UDP beacon thread. Connections are capped — each costs a thread, so
/// an unbounded accept loop would be a one-line DoS.
pub fn serve(store: Store, addr: &str, announce: bool) -> Result<()> {
    let listener = TcpListener::bind(addr)?;
    let store = Arc::new(store);
    let conns = Arc::new(AtomicUsize::new(0));

    if announce {
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || loop {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = sock.set_broadcast(true);
                let mut msg = MAGIC.to_vec();
                msg.extend_from_slice(&port.to_le_bytes());
                let _ = sock.send_to(&msg, format!("255.255.255.255:{BEACON_PORT}"));
            }
            std::thread::sleep(Duration::from_secs(3));
        });
    }

    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(_) => continue,
        };
        if conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue; // over capacity — drop on the floor
        }
        conns.fetch_add(1, Ordering::Relaxed);
        let st = Arc::clone(&store);
        let count = Arc::clone(&conns);
        std::thread::spawn(move || {
            let mut s = conn;
            while let Ok(frame) = read_frame(&mut s) {
                if frame.is_empty() || respond(&mut s, &st, &frame).is_err() {
                    break;
                }
            }
            count.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

/// Listen ~`secs` for beacon announcements; returns (addr, head-port)
/// pairs found. Excludes our own beacon only by chance — callers filter.
pub fn discover(secs: u64) -> Result<Vec<String>> {
    let sock = UdpSocket::bind(("0.0.0.0", BEACON_PORT))?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut found = std::collections::HashSet::new();
    let mut buf = [0u8; 16];
    while std::time::Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if n == 7 && &buf[..5] == MAGIC => {
                let port = u16::from_le_bytes([buf[5], buf[6]]);
                found.insert(format!("{}:{}", from.ip(), port));
            }
            _ => continue,
        }
    }
    Ok(found.into_iter().collect())
}

#[derive(Debug, Default)]
pub struct PullReport {
    pub remote_head: Option<Hash>,
    pub manifests_fetched: u64,
    pub objects_fetched: u64,
    pub objects_skipped: u64,
}

/// Pull the remote's HEAD chain + all missing objects into the local
/// store. Does not touch the worktree or local HEAD — `revert` after.
///
/// Everything the remote sends is attacker-controlled: every slice is
/// bounds-checked, every object and manifest is hash-verified and
/// validated before it is accepted, the parent walk is cycle-guarded
/// and capped, and nothing from the wire ever reaches the worktree.
pub fn pull(store: &Store, addr: &str) -> Result<PullReport> {
    let mut report = PullReport::default();
    let mut s =
        TcpStream::connect(addr).map_err(|e| Error::Sync(format!("connect {addr}: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;

    write_frame(&mut s, &[OP_GET_HEAD])?;
    let resp = read_frame(&mut s)?;
    if resp.len() != 33 || resp[0] != 1 {
        if resp.first().copied() == Some(0) {
            return Ok(report); // remote has no head
        }
        return Err(Error::Sync("malformed HEAD response".into()));
    }
    let remote_head: Hash = resp[1..33].try_into().unwrap();
    report.remote_head = Some(remote_head);

    // Walk the remote manifest chain until we reach one we already have.
    // visited guards cycles; the cap bounds a hostile infinite chain.
    let mut needed_objects: Vec<Hash> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut cur = remote_head;
    loop {
        if store.has_manifest(&cur) {
            break;
        }
        if !visited.insert(cur) {
            return Err(Error::Sync("manifest chain cycle".into()));
        }
        if visited.len() > MAX_MANIFESTS_PER_PULL {
            return Err(Error::Sync("manifest chain too long".into()));
        }
        let mut req = vec![OP_GET_MANIFEST];
        req.extend_from_slice(&cur);
        write_frame(&mut s, &req)?;
        let resp = read_frame(&mut s)?;
        let data = frame_payload(&resp)?;
        if data.is_empty() {
            return Err(Error::Sync(format!(
                "remote missing manifest {}",
                crate::short(&cur)
            )));
        }
        store.put_manifest_as(&cur, data)?;
        report.manifests_fetched += 1;

        let m = crate::snapshot::Manifest::deserialize(data)?;
        m.validate()?;
        for fe in &m.files {
            for ch in &fe.chunks {
                needed_objects.push(*ch);
            }
        }
        if needed_objects.len() > MAX_OBJECTS_PER_PULL {
            return Err(Error::Sync("pull exceeds object cap".into()));
        }
        match m.parent {
            Some(p) => cur = p,
            None => break,
        }
    }

    // Deduplicate, then filter through HAVE (batched so the request
    // stays under the frame cap) to fetch only what's missing.
    needed_objects.sort();
    needed_objects.dedup();
    for batch in needed_objects.chunks(HAVE_BATCH) {
        let mut req = vec![OP_HAVE];
        req.extend_from_slice(&(batch.len() as u32).to_le_bytes());
        for h in batch {
            req.extend_from_slice(h);
        }
        write_frame(&mut s, &req)?;
        let have = read_frame(&mut s)?;
        if have.len() != batch.len() {
            return Err(Error::Sync("HAVE response truncated".into()));
        }
        for (i, h) in batch.iter().enumerate() {
            if have[i] == 1 && !store.has_object(h) {
                let mut req = vec![OP_GET_OBJECT];
                req.extend_from_slice(h);
                write_frame(&mut s, &req)?;
                let resp = read_frame(&mut s)?;
                let data = frame_payload(&resp)?;
                if data.is_empty() {
                    return Err(Error::Sync(format!(
                        "remote missing object {}",
                        crate::short(h)
                    )));
                }
                store.put_object_as(h, data)?;
                report.objects_fetched += 1;
            } else {
                report.objects_skipped += 1;
            }
        }
    }

    // Remote head file, for `status`/`revert` convenience.
    let remotes = store.fabric_dir().join("remotes");
    std::fs::create_dir_all(&remotes)?;
    std::fs::write(remotes.join(sanitize(addr)), crate::hash_hex(&remote_head))?;
    Ok(report)
}

/// Peer addresses become filenames under `.respawn/remotes/` — keep
/// only characters that can never traverse or surprise a filesystem.
fn sanitize(addr: &str) -> String {
    addr.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Ensure a fabric exists at `root` for tests / embedding.
pub fn ensure_init(root: &Path) -> Result<Store> {
    match Store::open(root) {
        Ok(s) => Ok(s),
        Err(Error::NotInitialized) => Store::init(root),
        Err(e) => Err(e),
    }
}
