# state_fabric

> **Status: beta.** Format and CLI may change between minor versions. The
> integrity guarantees below are implemented and tested; there has been no
> external security audit.

**Undo as infrastructure.** state_fabric versions the state of a directory
tree as a content-addressed snapshot graph — every file's content lives in
the store, so any snapshot can be materialized back exactly. Reverting is a
HEAD pointer swap plus atomic per-file writes. Drift is a manifest diff.
Machines replicate snapshots over the LAN with no server.

Built for the agent era: snapshot the world before an autonomous process
touches it, revert when it goes wrong, and prove afterward what changed.

```
state_fabric init            # create .state_fabric/ in the worktree
state_fabric snap -m "v1"    # content-addressed snapshot
state_fabric status          # drift vs HEAD (added/modified/deleted)
state_fabric diff v1 head    # compare two snapshots
state_fabric revert <id>     # materialize a snapshot (atomic per file)
state_fabric log             # snapshot history
state_fabric verify          # audit chain + object integrity
state_fabric serve --announce# serve objects to LAN peers
state_fabric peers           # discover announcing peers
state_fabric pull host:4789  # replicate a peer's history locally
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
  re-hashes before storing. A malicious peer cannot poison your store —
  worst case, it wastes your bandwidth.

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
  write access to `.state_fabric/` can replace the whole log; the chain
  only proves the log you have is internally consistent. External anchors
  (signed checkpoints) are future work — see sovereign_ledger for the
  model.
- **LAN sync is plaintext.** Objects are self-verifying, so integrity is
  safe on a hostile network, but *confidentiality* is not — snapshot
  contents are visible to anyone on the wire. Encrypted transport is
  planned; do not sync secrets over untrusted LANs.
- **No `watch` auto-snapshotting yet.** `watch` reports drift events;
  policy-driven auto-snapshots (before-agent snapshots) are the next step.

## Layout

```
worktree/
  .state_fabric/
    objects/<2hex>/<62hex>    zstd-compressed chunks, BLAKE3-addressed
    manifests/<2hex>/<62hex>  bincode manifests; id = BLAKE3 of bytes
    HEAD                      hex id of current snapshot
    audit.jsonl               hash-chained event log
    remotes/<peer>            last-pulled remote heads
```

## Install

```sh
brew tap savageAZfck/tap
brew install state-fabric    # 0.1.0-beta, universal macOS binary
```

## Consolidation note

Absorbs the concepts of the retired stubs `git_fabric`, `blade_subsystem`,
`wire_gate`, `air_bridge`, `sovereign_edge(-rzr_cut)`, and `kingsman`:
the snapshot graph, the append-only store, the transport gate, atomic
state/rollback, and drift-watch — unified into one product instead of
seven sketches.
