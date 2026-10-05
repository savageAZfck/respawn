# Security

Report vulnerabilities privately to savagetism@icloud.com — do not open
public issues for exploitable weaknesses.

Scope: object store integrity, audit chain verification, anchor and
fleet signature verification, purge tombstone enforcement, Noise
transport handshake and downgrade resistance, LAN sync object
validation.

Out of scope: host filesystem compromise (see THREAT_MODEL.md — anchors
detect, they do not resurrect), APFS platform behavior, and the physical
security of the machine holding `.respawn/`.
