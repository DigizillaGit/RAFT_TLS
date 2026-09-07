## Changelog: Secure Transport, Replay Protection, and Attack CLI

### Overview
This changelog documents functional changes introduced to add secure transport (AEAD, replay protection), remove timestamp-based checks, expose attack/testing commands, and enhance logging/observability. It also clarifies mixed-mode behavior when some nodes run with secure ON while others run with secure OFF.

### Configuration and Bootstrapping
- Added `address_book.json` fields:
  - `secure_transport` (bool): default transport mode at startup for all nodes.
  - `secure_key_id` (string): logical key identifier for PSK selection/rotation.
  - `secure_psk` (string): pre-shared key material (hex/base64/utf-8).
  - `demo_logs` (bool): enable detailed file logs like `event=...` and secure drops.
  - `demo_stdout_simple` (bool): concise stdout for demos.

Files: `address_book.json`, `raft/raft.py` (config loader)

### Secure Transport Integration
- Outbound path wraps Raft JSON into an envelope when secure is enabled; inbound path unwraps, authenticates, and replay-checks.
  - Envelope fields: `key_id`, `nonce`, `tx_id`, `payload`, `tag`.
  - Broadcast derives keys with empty `peer_id` and is verified independently by each receiver.

Files: `raft/raft.py` (send/receive), `raft/secure_transport.py` (encode/decode, keystore, replay cache)

### Replay Protection
- Introduced `ReplayCache` with per-peer de-duplication by `tx_id` and TTL/size bounding.
- On duplicate: inbound path raises and logs drop line.

Files: `raft/secure_transport.py`

### Removal of Timestamp Validation
- Removed all uses of message timestamps for replay/acceptance decisions.
- Raft role logic no longer branches on time difference checks; correctness relies on terms and Raft rules only.

Files: `raft/protocol.py`, `raft/raft.py` (legacy checks removed)

### Hardening Behavior (Mixed Modes)
- With secure ON: drop raw (non-secure) messages; log `non-secure message received while secure enabled (dropped)`.
- With secure OFF: drop secure envelopes to avoid parse errors; log `secure message received while secure disabled (dropped)`.
- When only a single node toggled (e.g., node3 OFF while node1/node2 ON), expect leadership churn/conflicts due to asymmetric acceptance/drops.

Files: `raft/raft.py` (receive path policy), `SECURE_TRANSPORT.md` (policy described)

### CLI and Command Server (Attack/Demo)
- Added interactive sender `start_attack_process.py` with commands:
  - `secure on | secure off`
  - `entryattack "..."`
  - `replaylast`, `replaylast to <receiver>`, `replaylast received`
  - `attack higher-term to <target> <delta>` (secure/insider)
  - `attack raw higher-term to <target> <delta>` (outsider/raw)
  - `attack oldvote to <target> <delta>`
- Node3 command server parses and executes above commands, mapping to `RaftNode` helpers.

Files: `start_attack_process.py`, `start_server3.py`, `raft/raft.py` (helpers: replay, entry attack, vote attack, toggle secure)

### Logging and Observability
- File logs (`nodeX_logs.txt`) include structured lines:
  - Raft events: elections, votes, heartbeats, append entries, role changes.
  - Secure transport: `secure accepted tx_id [...]`, `secure drop tx_id [...] (auth/replay)`, `non-secure message received while secure enabled (dropped)`, `secure message received while secure disabled (dropped)`.
- Stdout throttling to reduce demo noise; file logs remain full-fidelity.

Files: `raft/raft.py`, `SECURE_TRANSPORT.md`

### Toggle Semantics
- `set_secure(true/false)` updates runtime state and resets replay cache upon enabling.
- Emits `event=secure_toggle enabled=<bool>` to the node's log file.

Files: `raft/raft.py`

### Backward Compatibility and Migration
- With `secure_transport=false`, nodes interoperate using raw JSON; secure envelopes are dropped rather than misparsed.
- Migration path documented in `SECURE_TRANSPORT.md`.

### Known User-Facing Effects
- Mixed-mode clusters can produce perceived "mixed" logs when only one node differs in secure state.
- Outsider raw injections are ineffective with secure ON; with secure OFF they may impact elections.

### Testing Notes
- See `docs/ATTACK_AND_TESTING_GUIDE.md` for step-by-step demos (secure OFF vs secure ON).


