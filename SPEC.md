# SPEC — respawn (undo as infrastructure)

## Object store

`.respawn/objects/<2-hex>/<62-hex>` — BLAKE3-keyed blobs, zstd-compressed
on disk, hashed on the *uncompressed* bytes. Writes are tmp+rename
atomic; reads re-verify the hash, so corruption is detected on access.

## Manifests and snapshots

A manifest (bincode) records every file under the root: path, mode,
size, mtime, content hash, ordered chunk hashes. Content is split by
FastCDC content-defined chunking (v3; v2 fixed-64 KiB manifests remain
readable). The snapshot id is the BLAKE3 of the manifest bytes — ids are
tamper-evident by construction. `HEAD` is a pointer file; `revert`
swaps HEAD then materializes files atomically per path.

## Audit chain

`.respawn/audit.jsonl` — append-only, hash-chained:

```json
{"seq":0,"ts":0,"event":"...","detail":"...","prev":"...","hash":"..."}
```

`hash = blake3(canonical(seq, ts, event, detail, prev))`. Editing,
deleting, or reordering any line breaks the chain; `respawn verify`
recomputes linkage plus every object's hash.

## Anchors

A hash chain over `.respawn/` alone cannot survive wholesale replacement
— an attacker with write access can substitute a fresh self-consistent
log. Anchors close that: an ed25519-signed statement of
`(fabric_id, HEAD, audit length, audit tip, last_anchor_hash)` written
to a path *outside* the fabric. Verification checks the signature and
that the anchored tip is still a prefix of the live log — truncation,
splicing, and replacement all fail. Anchors chain: each signs the
BLAKE3 of the previous anchor file. Signing key lives in the login
Keychain (macOS) or `.respawn/anchor.secret` (0600) elsewhere.

## Tombstones and purge certs

`purged.jsonl` — path+content-hash pairs the fabric must never snapshot
or restore again. `purge` tombstones by path *and* content hash (a
rename cannot resurrect), sweeps objects referenced only by the purged
content (shared objects are retained and reported — a cert claiming
total destruction while dedup'd data lived would be a lie), then issues
an ed25519-signed certificate: fabric id, path, content hash, chunk
counts, audit tip. `purge --verify` proves erasure without the content.

## Fleet orders

`fleet order` mints an ed25519-signed payload `(fabric_id, target
snapshot, ts, nonce)`. `fleet apply` verifies the signer against the
pinned `.respawn/fleet.pub` (set once by `fleet trust`), refuses orders
for another fabric, dedupes on `fleet_seen`, pulls the target if
needed, and reverts. One signed order, every peer lands on the same
anchored state.

## Sync wire protocol

TCP, little-endian. `frame = u32 len + payload`, `payload[0]` = opcode:

- `0x01 GET_HEAD` → `[has:u8][hash:32]`
- `0x02 GET_MANIFEST` + hash → `u64 len + bytes` (0 = missing)
- `0x03 HAVE` + u32 n + n hashes → n bytes (0/1)
- `0x04 GET_OBJECT` + hash → `u64 len + bytes` (0 = missing)

Receivers verify every object's BLAKE3 before storing — a hostile or
corrupt peer cannot poison the store.

Transport: plaintext (legacy) or Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s`
when `--psk` is given. Mutual authentication from the passphrase (mixed
at position 0 — a wrong-PSK peer cannot handshake) plus forward secrecy
from ephemeral DH. Prologue: a secured client sends `SFAB` + version +
mode; a secured *server* rejects non-selector connections, so security
cannot silently downgrade — the serving operator decides the floor.
Frame sizes are encrypted; the wire shows only ciphertext.

## APFS snapshots

`snap --apfs` (macOS ≤15) takes a point-in-time cut via an APFS local
snapshot, mounts it read-only, and snapshots the frozen view — consistent
history without quiescing the writer. Drop of the handle unmounts,
removes the temp dir, and deletes the APFS snapshot so Time Machine
space is not held.
