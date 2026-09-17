# respawn

> **Status: beta.** Format and CLI may change between minor versions. The
> integrity guarantees below are implemented and tested; there has been no
> external security audit.

**Undo as infrastructure.** respawn versions the state of a directory
tree as a content-addressed snapshot graph — every file's content lives in
the store (content-defined chunks via FastCDC), so any snapshot can be
materialized back exactly. Reverting is a HEAD pointer swap plus atomic
per-file writes. Drift is a manifest diff. Machines replicate snapshots
over the LAN — plaintext or Noise-encrypted — with no server.

Built for the agent era: snapshot the world before an autonomous process
touches it, revert when it goes wrong, and prove afterward what changed.

```
respawn init            # create .respawn/ in the worktree
respawn snap -m "v1"    # content-addressed snapshot
respawn snap --apfs     # true point-in-time cut via APFS (macOS, root)
respawn status          # drift vs HEAD (added/modified/deleted)
respawn status --full   # rehash every file — don't trust metadata
respawn diff v1 head    # compare two snapshots
respawn revert <id>     # materialize a snapshot (atomic per file)
respawn log             # snapshot history
respawn verify          # audit chain + object integrity

respawn guard -- <cmd>          # snap → run cmd → report drift
respawn guard --revert on-fail -- <cmd>   # undo the command's writes if it failed
respawn anchor keygen           # mint the checkpoint signing key (once)
respawn anchor create <file>    # sign HEAD+audit state → file outside .respawn/
respawn anchor verify <file>    # prove the anchored history is intact

respawn serve --psk <secret>            # encrypted, authenticated LAN serve
respawn serve --announce                # plaintext serve + UDP beacon
respawn peers                           # discover announcing peers
respawn pull host:4789 --psk <secret>   # replicate a peer's history
```

## What it actually guarantees

- **Content integrity.** Every object is BLAKE3-addressed and verified on
  read, on reconstruction during revert, and on receipt during sync. A
  corrupted or tampered object is detected, never silently used.
- **Atomic per-file revert.** Files are written to a temp file and renamed
  over the destination. A crash mid-revert can leave a partially-applied
  snapshot (some files new, some old) but never a half-written file.
- **Tamper-evident audit — plus provable history.** Every mutation
  appends to a hash-chained `audit.jsonl`. `anchor create` signs a
  checkpoint (fabric id, HEAD, audit length + tip) with an ed25519 key
  and writes it *outside* `.respawn/`; `anchor verify` proves the
  anchored prefix of the log is still intact — so wholesale log
  replacement, which an internal chain cannot see, is caught. Entries
  appended after anchoring are legitimate continuation, not tampering.
- **Guarded execution.** `respawn guard -- <cmd>` snapshots, runs the
  command with the worktree as cwd, then reports exactly what it changed
  and propagates its exit code. `--revert on-fail|always` restores the
  pre-state. This is the agent-era primitive: wrap anything that writes.
- **Encrypted, authenticated sync (opt-in).** `serve --psk` runs Noise
  NNpsk0 (X25519 + ChaChaPoly): the passphrase authenticates both ends,
  ephemeral DH gives forward secrecy, and frame lengths ride inside the
  ciphertext. A `--psk` listener refuses plaintext outright — no silent
  downgrade. Without `--psk` the legacy plaintext protocol still works
  and still verifies every object's hash.
- **Single-writer enforcement.** Mutating commands hold an `flock` on
  `.respawn/lock`; a second writer fails fast instead of forking the
  audit chain. The lock is released by the OS on exit or crash — no
  stale-PID problem.
- **Replication without trust.** Peers serve raw objects; the receiver
  re-hashes before storing, validates manifest structure before use, and
  never lets wire data reach the worktree. A malicious peer cannot
  poison your store or write outside it — worst case, it wastes your
  bandwidth (chain length, object count, and frame size are all capped).
- **Revert cannot escape the worktree.** Manifest paths are validated
  on load and re-validated at the write boundary; absolute paths and
  `..` components are rejected, symlinked ancestors block the write, and
  modes are masked to `0o777` so setuid bits never propagate.

## What it does not guarantee (honest limits)

- **Filesystem state only.** Processes, memory, app state, and file
  permissions beyond POSIX mode bits are not captured. "Machine state" is
  a v0.2+ question, not a v0.1 claim.
- **Revert is O(changed files), not O(1).** The HEAD swap is constant-time;
  materializing content is proportional to what differs. For large trees
  the honest cost model is "pay for what changed."
- **Anchors bind history, not the future.** An anchor proves the audit
  prefix it signed is still present and unaltered. It cannot prove
  entries *after* the anchor are honest, and it only travels as far as
  you take the file — an anchor nobody copies off the machine protects
  nothing. The signing key lives at `.respawn/anchor.secret`; an attacker
  with that file can forge anchors, which is why `verify --pubkey` pins
  the signer you recorded at `keygen`.
- **Plaintext sync remains for compatibility.** Without `--psk` the wire
  is unencrypted and unauthenticated — integrity is still guaranteed by
  content hashes, confidentiality is not, and any reachable host can
  read snapshotted content. `serve` binds to `127.0.0.1` by default and
  warns on wider binds; use `--psk` on any network you do not fully
  trust. The PSK is a bearer credential — anyone holding it can join.
- **Drift's fast path trusts metadata.** `status` skips hashing files
  whose size and mtime match the manifest — an attacker able to write
  your files can also restore mtime. Use `status --full` to rehash
  everything when it matters. The `revert` safety gate always does.
- **Snapshot is per-file quiesced, not tree-atomic (without --apfs).**
  Each file is stamped, read, and re-stamped — a file that changed
  mid-read is re-captured up to 3 times, then recorded in the manifest's
  `unstable` list rather than silently trusted. That shrinks the window
  to a single file read; it is not a whole-tree cut. `snap --apfs`
  freezes the volume at the filesystem layer for a true point-in-time
  capture, but needs macOS + APFS + root for `mount_apfs`, and only
  covers the boot volume. On anything else, snapshot quiesced trees.
- **Content-defined chunking is not alignment-stable.** CDC dedups
  inserts well, but chunk boundaries are content-derived — byte-identical
  files always chunk identically, near-identical ones mostly do. No
  promise of a specific dedup ratio.
- **No `watch` auto-snapshotting.** `watch` reports drift events;
  `guard` is the policy-driven pre-write snapshot. A watch-triggered
  auto-snapshot mode is not implemented.

## Layout

```
worktree/
  .respawn/
    objects/<2hex>/<62hex>    zstd-compressed chunks, BLAKE3-addressed
    manifests/<2hex>/<62hex>  JSON manifests; id = BLAKE3 of bytes
    HEAD                      hex id of current snapshot
    audit.jsonl               hash-chained event log
    lock                      flock'd during mutations — single writer
    fabric_id                 random fabric identity, bound into anchors
    anchor.secret             ed25519 anchor key (0600) — sign checkpoints
    remotes/<peer>            last-pulled remote heads
```

## Install

```sh
brew tap savageAZfck/tap
brew install respawn    # 0.1.0-beta, universal macOS binary
```

## Consolidation note

Absorbs the concepts of the retired stubs `git_fabric`, `blade_subsystem`,
`wire_gate`, `air_bridge`, `sovereign_edge(-rzr_cut)`, and `kingsman`:
the snapshot graph, the append-only store, the transport gate, atomic
state/rollback, and drift-watch — unified into one product instead of
seven sketches.

## License

Functional Source License 1.1 (FSL-1.1-ALv2) — (c) 2026 Adam Clark.
Source is open to read, use, and build on for any non-competing purpose;
converts to Apache-2.0 automatically two years after release.
Contact savagetism@icloud.com for licensing or partnership.
