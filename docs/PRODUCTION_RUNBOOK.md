## Production Runbook: Secure Transport and Raft Operations

This runbook covers configuration, secrets management, startup/shutdown, health checks, incident response, and key rotation for clusters using secure transport with replay protection.

### Configuration Management
- Manage `address_book.json` under your CM tool; avoid ad-hoc edits on hosts.
- Parameters:
  - `secure_transport`: must be the same across all nodes at steady state.
  - `secure_key_id`: current PSK identifier.
  - `secure_psk`: DO NOT commit real secrets. Source from env or secret store at deploy time.
  - `demo_logs`, `demo_stdout_simple`: keep `demo_stdout_simple=false` in prod to reduce console noise; file logs remain detailed.

### Secrets Management
- Source `secure_psk` from environment variables or a secret store (Vault, AWS Secrets Manager, etc.).
- Ensure all nodes share identical `secure_psk` for a given `secure_key_id`.
- Limit exposure of logs where PSK values might inadvertently appear (they should not, but defense-in-depth).

### Startup
- Prereq: Python venv prepared and dependencies installed.
- Start each node under the venv:
  - `/opt/raft/venv/bin/python /opt/raft/start_server1.py`
  - `/opt/raft/venv/bin/python /opt/raft/start_server2.py`
  - `/opt/raft/venv/bin/python /opt/raft/start_server3.py`
- Expect one leader election; verify via logs `event=role_change` and heartbeats.

### Shutdown
- Gracefully stop processes via your process manager (systemd, supervisor, etc.).
- Avoid mid-rotation shutdowns; complete key rotations (below) first if in progress.

### Health Checks
- Liveness: process up and accepting connections.
- Raft: regular heartbeats (`event=sent_heartbeat`/`received_append_entries`) and stable leader.
- Secure transport:
  - No recurring `non-secure message received while secure enabled (dropped)` when cluster is fully secure.
  - No spikes of `secure drop tx_id [...] (auth/replay)` unless replay testing is ongoing.

### Observability and Logs
- Per-node file logs `nodeX_logs.txt` contain detailed events suitable for audit:
  - Elections and role changes
  - Vote requests/responses
  - AppendEntries send/receive counts
  - Secure envelope acceptance and drops
- Ship logs to your centralized system (e.g., via filebeat). Keep retention to cover audit needs.

### Incident Response
- Mixed-mode anomalies: If some nodes log non-secure or secure-dropped lines, verify `secure_transport` consistency and recent toggles.
- Leader churn: Check for outsider raw injections (should be dropped with secure ON) or insider higher-term tests.
- Replay storms: Investigate sender behavior; ensure `replaylast` or similar tools are not active in prod.

### Key Rotation Procedure
1) Prepare new PSK stored securely and choose a new `secure_key_id` (e.g., `rot-2025-09`).
2) Deploy config allowing BOTH old and new keys (implementation currently loads a single PSK keyed by `secure_key_id`; extend keystore or deploy coordinated switch):
   - Staged approach:
     - Update `secure_psk` under new `secure_key_id` on all nodes, but keep `secure_key_id` pointing to the old one. Validate stability.
     - Switch `secure_key_id` to the new value across the cluster near-simultaneously.
3) Monitor logs for any `Unknown key_id` or authentication errors.
4) After a grace period, retire the old key material.

### Running Validations in Production
- Non-disruptive checks:
  - Observe heartbeats and append entries cadence.
  - Verify absence of non-secure inputs while secure is ON.
  - Spot-check for replay drops (should be zero during normal ops).
- NEVER run `attack raw higher-term` or `replaylast` in production.

### Change Management
- For config flips (secure ON/OFF) perform during a maintenance window and as a cluster-wide change.
- Document: time, nodes, `secure_key_id` changes, expected impacts, and validation steps.

### Known Pitfalls
- Mixed secure states cause message drops and can induce elections.
- Using demo CLI in prod can cause unintended state transitions; disable or restrict access to the command server in production.

### Appendix: Quick Commands
- Check last secure toggles:
  - `grep 'event=secure_toggle' node*_logs.txt | tail`
- Clear old demo logs before staging tests (not in prod):
  - `rm -f /opt/raft/node{1,2,3}_logs.txt`


