# Threat model — respawn

**Attacker rewrites the audit log.** A fresh self-consistent chain
verifies internally — so audit integrity alone is not continuity. The
anchor layer exists for exactly this: signed tips held outside the
fabric, chained to each other. Whole-log replacement fails
`anchor verify` because the anchored tip is no longer a prefix.

**Attacker truncates or splices history.** The anchor records audit
length and tip; a shortened or rejoined log diverges from the anchored
statement. Deleted anchor files break the anchor chain pairwise.

**Attacker tampers with stored objects.** Every object read re-verifies
its BLAKE3. Corrupt or substituted content fails on access, not later.

**Malicious sync peer floods or poisons.** Receivers verify object
hashes before storing; bad bytes never reach the store. A peer can
withhold objects — availability, not integrity.

**Downgrade attack on transport.** A `--psk` server rejects
non-selector connections outright; a plaintext client cannot silently
downgrade a hardened peer. The selector prologue (`SFAB`) exists
precisely so the server learns intent before bytes that matter.

**PSK compromise.** Noise NNpsk0 gives mutual auth plus forward secrecy;
a stolen passphrase admits future handshakes but does not decrypt
recorded sessions. Rotating the PSK closes the door going forward —
there is no PKI to revoke because the passphrase is the credential.

**Fleet order replay.** Orders carry `(fabric_id, target, ts, nonce)`
and peers dedupe on `fleet_seen`; a replayed order is a no-op. Orders
for a foreign fabric refuse outright — the fabric id is inside the
signed body, so cross-fabric confusion cannot be smuggled.

**Purge theatre.** The cert reports objects retained when content was
dedup'd — a certificate claiming erasure while shared data lived on
would be a lie, so the sweep reports retention instead. Tombstones key
on content hash as well as path so a rename cannot resurrect the datum.

**Snapshot-time races.** `--apfs` freezes the tree before hashing; the
live filesystem cannot move under the manifest mid-snapshot.

## What this crate guarantees

- Any single-line edit, deletion, or reorder in `audit.jsonl` fails
  `verify`.
- Whole-fabric replacement is caught by anchors, provided at least one
  anchor was written outside `.respawn/` before compromise.
- Object corruption or substitution is detected on every read and on
  every sync receive.
- A purge cert proves erasure honestly — including reporting what could
  not be destroyed due to sharing.
- A `--psk` sync session cannot be silently downgraded or eavesdropped.

## What it does not guarantee

- Anchors written *after* compromise prove nothing — anchor early,
  anchor outside, chain them.
- A compromised host can delete `.respawn/` entirely; detectability is
  not recoverability. Anchors prove it happened; replication brings the
  data back.
- `fleet trust` is trust-on-first-pin: the operator must verify the
  pinned key out of band.
- The audit chain proves *what was recorded*, not that recording was
  complete — a fully compromised process can stop writing entirely.
