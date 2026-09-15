# respawn

> **Status: beta.** Format and CLI may change between minor versions. The
> integrity guarantees below are implemented and tested; there has been no
> external security audit.

**Undo as infrastructure.** respawn versions the state of a directory
tree as a content-addressed snapshot graph — every file's content lives in
the store, so any snapshot can be materialized back exactly. Reverting is a
HEAD pointer swap plus atomic per-file writes. Drift is a manifest diff.
Machines replicate snapshots over the LAN with no server.

Built for the agent era: snapshot the world before an autonomous process
touches it, revert when it goes wrong, and prove afterward what changed.

```
respawn init            # create .respawn/ in the worktree
respawn snap -m "v1"    # content-addressed snapshot
respawn status          # drift vs HEAD (added/modified/deleted)
respawn status --full   # rehash every file — don't trust metadata
respawn diff v1 head    # compare two snapshots
respawn revert <id>     # materialize a snapshot (atomic per file)
respawn log             # snapshot history
respawn verify          # audit chain + object integrity
respawn serve --announce# serve objects to LAN peers (loopback default)
respawn peers           # discover announcing peers
respawn pull host:4789  # replicate a peer's history locally
```

## What it actually guarantees

- **Content integrity.** Every object is BLAKE3-addressed and verified on
  read, on reconstruction during revert, and on receipt during sync. A
  corrupted or tampered object is detected, never silently used.
- **Atomic per-file revert.** Files are written to a temp file and renamed
  over the destination. A crash mid-revert can leave a partially-applied
  snapshot (some files new, some old) but never a half-written file.
- **Tamper-evident audit.** Every mutation appends to a hash-chained
  `audit.jsonl`. `verify` detects edited, deleted, or reordered entries.
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
- **Fixed 64 KiB chunks.** Dedup is per-chunk, so a 1-byte edit to a file
  rewrites one chunk — fine — but content-defined chunking (better dedup
  on inserts) is not implemented yet.
- **Audit detects tampering, not history rewriting.** An attacker with
  write access to `.respawn/` can replace the whole log; the chain
  only proves the log you have is internally consistent. External anchors
  (signed checkpoints) are future work — see sovereign_ledger for the
  model.
- **LAN sync is plaintext and unauthenticated.** Objects are
  self-verifying, so integrity is safe on a hostile network, but
  *confidentiality* is not — anyone who can reach the listener can read
  snapshotted content. `serve` binds to `127.0.0.1` by default and warns
  on any other address; only bind wider on a network you trust.
  Encrypted, authenticated transport is planned.
- **Drift's fast path trusts metadata.** `status` skips hashing files
  whose size and mtime match the manifest — an attacker able to write
  your files can also restore mtime. Use `status --full` to rehash
  everything when it matters. The `revert` safety gate always does.
- **Single writer.** Concurrent `snap`/`pull`/`revert` against the same
  worktree is last-writer-wins (the audit chain can fork). A lockfile is
  planned; for now, one process per fabric.
- **Snapshot is not a point-in-time cut.** Files are read serially; a
  file mutating mid-`snap` is captured as whatever was read. Snapshot
  quiesced trees, or accept per-file (not whole-tree) atomicity.
- **No `watch` auto-snapshotting yet.** `watch` reports drift events;
  policy-driven auto-snapshots (before-agent snapshots) are the next step.

## Layout

```
worktree/
  .respawn/
    objects/<2hex>/<62hex>    zstd-compressed chunks, BLAKE3-addressed
    manifests/<2hex>/<62hex>  JSON manifests; id = BLAKE3 of bytes
    HEAD                      hex id of current snapshot
    audit.jsonl               hash-chained event log
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
