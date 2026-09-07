## Secure Transport for Raft

### 1) Introduction
- Purpose: Replace timestamp-based replay checks with a cryptographic transport layer that provides confidentiality, integrity, authenticity, and replay protection without changing Raft’s protocol or state transitions.
- Scope: This document is the authoritative reference for configuration, design, logging, demos/attacks, operations, and security guidance.
- Non-goals: Modifying Raft log semantics, election rules, or protocol data structures. The transport upgrade must be transparent to Raft roles and message formats.
- Quick outcomes:
  - Timestamps removed from `RequestVotesMessage` and all Raft role checks.
  - Secure envelope integrated on send/receive with minimal code surface changes.
  - Human-friendly stdout with throttling plus detailed file logs for auditability.

### 2) Architecture Overview
- Data plane:
  - Raft messages remain JSON (e.g., RequestVotes, AppendEntries). No secure fields are added to protocol classes.
  - When secure transport is enabled, messages are wrapped in an envelope containing `key_id`, `nonce`, `tx_id`, `payload`, and `tag`.
  - The envelope is the only structure exposed on the wire; the inner JSON is confidential when `confidential=True`.
- Control plane:
  - Configuration is centralized in `address_book.json` with `secure_transport`, `secure_key_id`, and `secure_psk`.
  - A simple command server (in `start_server3.py`) exposes toggles and demo attack endpoints.
- Integration points:
  - `_send_message` (outbound) and `_get_message` (inbound) in `raft/raft.py` implement the wrapper/unwrapper.
  - `SecureKeystore`, `encode_secure_message`, `decode_secure_message`, and `ReplayCache` live in `raft/secure_transport.py`.
- Compatibility:
  - With `secure_transport=false`, nodes send/receive raw JSON; secure envelopes arriving are dropped, avoiding parse errors.

### 3) Threat Model
- In-scope threats (addressed):
  - Replay: An attacker re-sends previously observed Raft messages. The replay cache detects duplicate `tx_id` per-peer and drops the message.
  - Tampering: An attacker alters message fields. AES-GCM authentication fails; the message is dropped.
  - Outsider injection: An attacker injects raw (unenveloped) JSON. With secure ON, non-secure messages are dropped by policy.
- Partially-in-scope: Insider with PSK can send valid messages, including higher-term vote requests. Raft handles higher-term demotion per spec; this is by design.
- Out-of-scope:
  - Node compromise and PSK exfiltration defense (use operational controls and rotation).
  - DoS resistance beyond best-effort drops (e.g., flooding the listener).
  - Secure boot / measured attestation.

### 4) Design Goals
- Preserve Raft semantics and message schema.
- Provide confidentiality (optional) and mandatory integrity/authenticity (via AEAD).
- Enforce replay protection with low false positive/negative rates (no clock skew issues).
- Support PSK rotation through `key_id` indirection.
- Deliver operational observability with two-tier logging (stdout vs files) for demos and debugging.

### 5) Cryptographic Design
- Keys:
  - `K_master` (PSK) is loaded from `address_book.json` and keyed by `secure_key_id`.
  - The keystore is a simple in-memory map `{ key_id: key_bytes }` via `SecureKeystore`.
- Derivation:
  - `K_tx = HKDF_SHA256(ikm=K_master, salt=nonce(12B), info=peer_id, length=32)`, unique per message and receiver context.
  - `peer_id` is the receiver address for unicast or an empty string for broadcast, preventing cross-context reuse.
- AEAD:
  - AES-256-GCM encrypts the serialized Raft JSON. Associated Authenticated Data (AAD) binds `key_id|nonce|tx_id|peer_id`.
  - Authentication failure (tag mismatch) aborts decoding; message is dropped and logged.
- Replay:
  - 16-byte `tx_id` uniquely identifies a message. The `ReplayCache` stores recent `tx_id`s per peer (LRU+TTL). A duplicate triggers an immediate drop.
  - TTL determines how long a `tx_id` remains invalid if replayed; default is tuned for demo/heartbeat cadence.

### 6) Envelope Specification
Produced by `encode_secure_message` and consumed by `decode_secure_message` in `raft/secure_transport.py`:
```json
{
  "key_id": "default",
  "nonce": "base64(12B)",
  "tx_id": "base64(16B)",
  "payload": "base64(ciphertext)",
  "tag": "base64(16B GCM tag)"
}
```
- The inner Raft JSON is encrypted and authenticated.
- AAD authenticates context and prevents envelope tampering.
 - `broadcast` messages set `peer_id`="" during derivation. Receivers still verify using their own context.
 - For integrity-only mode (not used in demos), `payload` equals plaintext and `tag` is HMAC over (AAD, payload).

### 7) Integration Points (Code Map)
- `raft/secure_transport.py`: HKDF, AES-GCM, encode/decode, replay cache.
- `raft/protocol.py`: Raft message classes; timestamp fields removed; no secure fields added.
- `raft/raft.py`:
  - `_send_message`: wraps JSON into a secure envelope (when enabled), caches last envelope per receiver.
  - `_get_message`: unwraps, verifies AEAD, checks replay, enforces hardening rules, and returns a parsed Raft message.
  - Additional demo utilities: toggling secure, replay helpers, attack senders, stdout throttling.
  - Important behavior:
    - When `secure_enabled` and a non-secure message arrives, it is dropped with: `non-secure message received while secure enabled (dropped)`.
    - When secure is disabled and a secure envelope arrives, it is dropped to avoid parse errors and logged accordingly.
    - Self-originated received events are suppressed on stdout to avoid noise.

### 8) Removal of Timestamp Validation
- All references to `msg_timestamp` and timestamp-based checks were removed from protocol and Raft role handlers (follower, candidate, leader).
- Replay protection is solely enforced by `tx_id` + replay cache inside the secure transport layer.
- This avoids clock synchronization dependencies and false positives.
 - Impact on Raft correctness: None. Raft’s safety/liveness rely on terms and majority voting; timestamps were an add-on and are no longer used.
 - Code references:
   - `raft/protocol.py`: `RequestVotesMessage` no longer includes `msg_timestamp` in ctor, properties, `to_dict`, `jsonify`, or `un_jsonify`.
   - `raft/raft.py`: any legacy `difference <= 10` checks were removed; follower/candidate/leader paths no longer branch on timestamps.

### 9) Hardening Rules
- If `secure_enabled == true`:
  - Secure envelopes are required; non-secure (raw) messages are dropped and file-logged as: `non-secure message received while secure enabled (dropped)`.
  - Replayed secure messages are dropped and file-logged as: `secure drop tx_id [...] (auth/replay)`.
- If `secure_enabled == false`:
  - Secure envelopes arriving are dropped and logged as a safety measure.
 - Rationale: Mixed-mode networks can occur during transition. Strict dropping avoids accidental acceptance of unverified inputs and preserves deterministic behavior.

### 10) Configuration
`address_book.json` example:
```json
{
  "node1": {"ip": "192.46.237.85", "port": "2380"},
  "node2": {"ip": "172.105.85.119", "port": "2380"},
  "node3": {"ip": "172.104.149.60", "port": "2380"},
  "secure_transport": true,
  "secure_key_id": "default",
  "secure_psk": "dev-psk-not-for-production",
  "demo_logs": true,
  "demo_stdout_simple": true
}
```
- `secure_psk` accepts hex, base64, or utf-8 text. All nodes must share the same PSK and `secure_key_id`.
 - Operational recommendation:
   - Keep `address_book.json` under configuration management. Avoid script-side overwrites.
   - For production, source `secure_psk` from environment or secret store; do not check real secrets into version control.

### 11) Runtime Behavior
- Send path (`_send_message`):
  - Serialize → derive key → AEAD encrypt → emit envelope → cache for demo replay.
- Receive path (`_get_message`):
  - Enforce hardening → verify envelope → replay-check → parse inner JSON → deliver to role handlers.
- Toggling secure: `set_secure(true/false)` on a node resets the replay cache when enabling.
 - Broadcast vs unicast:
   - For broadcast heartbeats, `peer_id` in KDF is empty to derive a context-common key. Each receiver still validates AEAD and manages its own replay cache.
 - Attack surface:
   - With secure ON: outsider raw injections are rejected; only valid envelopes from PSK holders are processed.
   - With secure OFF: raw JSON is accepted for backward compatibility; secure envelopes are dropped to avoid misparse.

### 12) Logging and Observability
- File logs (`nodeX_logs.txt`, detailed):
  - `event=sent_vote_request term=...`
  - `event=received_vote_request ...`
  - `event=sent_heartbeat term=...`
  - `event=received_append_entries term=... count=...`
  - `event=role_change old=... new=... term=...`
  - `secure accepted tx_id [...]`
  - `secure drop tx_id [...] (auth/replay)`
  - `non-secure message received while secure enabled (dropped)`
- Stdout (simplified, human-friendly):
  - `nodeX: Starting as follower (term N)`
  - `nodeX: Asked for votes (term N)`
  - `nodeX: Vote YES/NO from nodeY (term N)`
  - `nodeX: Heartbeat sent/from nodeY (term N)`
  - `nodeX: Replicating K entries / AppendEntries K entries (term N)`
 - Examples from real runs:
   - File: `2025-09-10 09:14:23 : event=role_change old=candidate new=leader term=14`
   - File: `2025-09-10 09:14:20 : secure accepted tx_id [JpLjyLWBXLO0Md2qsHhZjw==]`
   - File: `2025-09-10 09:10:47 : secure drop tx_id [h/NJEWy2YFmTxoZu05xDWQ==] (auth/replay)`
   - File: `non-secure message received while secure enabled (dropped)`
   - Stdout: `node1: Asked for votes (term 14)` / `node2: Heartbeat from node1 (term 14)`

### 13) Stdout Throttling Policy
- To avoid noisy demos, stdout lines for heartbeats and append entries are rate-limited to once every ~2 seconds per category (sent/received).
- File logs remain unthrottled to preserve full fidelity.
 - Implementation:
   - `raft/raft.py` tracks last printed timestamps per category: sent/received heartbeats and append-entries.
   - Threshold (`_stdout_throttle_secs`) defaults to 2.0 seconds.
 - Tuning:
   - For very slow demos, you can increase to 3–5s; for verbose debugging, set to 0 (not recommended for presentations).

### 14) Demo and Attack Guide
See also: `docs/ATTACK_AND_TESTING_GUIDE.md` for step-by-step instructions and expected logs.
Run the CLI:
```bash
source venv/bin/activate
python start_attack_process.py
```
Commands and expected outcomes:
- `secure on` / `secure off`: enable/disable secure transport on node3 host. On enable, replay cache resets.
- `entryattack "Your message here"`: leader replicates; followers log received append entries.
- `replaylast` / `replaylast to <target>` / `replaylast received`: re-send cached secure envelope; receivers drop with `secure drop` when secure ON.
- `attack higher-term to <target> <delta>`: insider secure vote with term = current + delta; leader demotes when delta ≥ 1; election follows.
- `attack raw higher-term to <target> <delta>`: outsider raw vote; with secure ON it is dropped by hardening; with secure OFF it may demote leader.
- `attack oldvote to <target> <delta>`: old-term vote; ignored by Raft.
 - Recommended sequences:
   1) Replay demo (secure ON):
      - Run `entryattack "demo"` to seed and then `replaylast received` → peers log `secure drop tx_id [...] (auth/replay)`.
   2) Demotion demo (insider):
      - `attack higher-term to <leader> 1` → leader demotes, new election occurs (observe role changes and vote responses).
   3) Outsider vs secure:
      - `attack raw higher-term to <leader> 1` with secure ON → dropped; toggle `secure off` → same command can demote leader.

### 15) Key Management and Rotation
- Use `secure_key_id` to reference PSKs in a keystore; current implementation loads one PSK from config.
- Rotation strategy:
  1) Deploy new PSK under a new `secure_key_id` to all nodes (in config or a secret store).
  2) Switch `secure_key_id` across the cluster.
  3) Remove old PSK after a grace period.
- For production, store PSKs outside the repo (env vars, vault).
 - Considerations:
   - Ensure all nodes load both old and new keys during rotation overlap.
   - Monitor logs for mixed `key_id` usage during transition.
   - Rotate periodically based on policy; immediately rotate upon suspected compromise.

### 16) Troubleshooting
- Replay commands say “not available”: seed by letting a normal send occur (heartbeat/append) or run `entryattack` first; then retry.
- Command server port busy: the server now skips starting a duplicate binder; ensure a single `start_server3.py` runs.
- Seeing self messages in “received”: the code suppresses self-originated received stdout; file logs still include events as appropriate.
 - `KeyError: 'type'` on secure-off with secure envelopes: guarded by dropping secure envelopes when secure is disabled.
 - `Address already in use` on node3 command server: code sets `SO_REUSEADDR` and gracefully skips duplicate bind; ensure only one instance is launched.
 - Leader repeatedly re-elected:
   - Election timeouts and heartbeat frequency are widened for stability; tune in `raft/raft.py` if needed.

### 17) Security Considerations
- With secure ON, outsider raw injections are dropped; insiders with PSK can still send valid envelopes.
- Protect PSKs in transit and at rest; rotate periodically.
- AEAD with strong KDF and per-message nonce prevents tampering and provides confidentiality.
 - Replay cache sizing/TTL:
   - Ensure TTL exceeds maximum network reordering and delivery delays expected in your environment.
   - Memory usage is bounded via LRU; tune cache size for cluster scale.

### 18) Backward Compatibility
See also: `docs/CHANGELOG_SECURE_TRANSPORT.md` for a consolidated list of changes.
- When `secure_transport=false`, nodes send/receive raw JSON, preserving legacy behavior (secure envelopes received in this mode are dropped to avoid parse errors).
- No changes to the Raft protocol schema; other Raft implementations can interoperate at the message layer if they share the same serialization.
 - Migration path:
   - Phase 1: Deploy code with `secure_transport=false` everywhere (no behavior change).
   - Phase 2: Enable `secure_transport=true` cluster-wide; verify operations and logs.
   - Phase 3: Remove legacy timestamp references from any dependent tooling or dashboards (if any).

### 19) Limitations and Future Work
- Current keystore is in-memory per process; consider HSM or secure secret providers.
- Add mutual authentication at node identity level (e.g., per-node keys or certificates) for stronger insider controls.
- Consider sequence numbers or windowed nonces in addition to replay cache for deterministic ordering if needed.
 - Persist replay cache across restarts (optional) if replay windows span node restarts (trade-off against memory and false positives).
 - Replace PSK with per-node key pairs and mutual TLS for production-grade identity and revocation.

### 20) Glossary
Related operational guidance: `docs/PRODUCTION_RUNBOOK.md`.
- `PSK (K_master)`: Pre-shared master key for the cluster.
- `key_id`: Logical identifier for a PSK for rotation.
- `nonce`: Random 12-byte value for AES-GCM and HKDF salt.
- `tx_id`: Random 16-byte transaction identifier for replay detection.
- `AAD`: Associated Authenticated Data included in AEAD authentication.
- `HKDF`: HMAC-based Key Derivation Function (SHA-256).
- `AES-GCM`: Authenticated encryption cipher mode providing confidentiality and integrity.
 - `Broadcast context`: Messages sent to all peers with empty `peer_id` context for KDF.
 - `LRU`: Least Recently Used eviction policy.
 - `TTL`: Time to live; window for which a `tx_id` remains invalid if replayed.



