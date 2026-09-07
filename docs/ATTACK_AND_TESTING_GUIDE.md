## Attack and Testing Guide

This guide explains how to run clean, reproducible demos for secure transport OFF vs ON, why logs may look "mixed" when only some nodes toggle, and how to validate replay protection and raw-injection resistance.

### Prerequisites
- Ensure the Python virtual environment is active:
  - `/opt/raft/venv/bin/python` per your environment, or `source venv/bin/activate` if running locally.
- All commands below assume running the three nodes via the provided startup scripts and using the interactive CLI `start_attack_process.py`.

### Clean Start
1. Stop all running nodes.
2. Clear previous logs for a clean run:
   - `rm -f /opt/raft/node{1,2,3}_logs.txt` (or project-root `node{1,2,3}_logs.txt` depending on your setup)
3. Verify/adjust `address_book.json`:
   - Set `secure_transport` to desired default (true for secure, false for non-secure).
4. Start nodes in venv:
   - `/opt/raft/venv/bin/python /opt/raft/start_server1.py`
   - `/opt/raft/venv/bin/python /opt/raft/start_server2.py`
   - `/opt/raft/venv/bin/python /opt/raft/start_server3.py`

### Why node3 logs can look "mixed"
- If only node3 is toggled to secure OFF while node1/node2 remain secure ON:
  - When node3 receives secure envelopes, it logs: `secure message received while secure disabled (dropped)`.
  - When node3 sends raw messages to secure-ON peers, peers drop them; leadership may churn. Logs may show `sent_heartbeat leader=node3` while also `received_heartbeat leader=node1` on different nodes.
  - If you toggled node3 ON/OFF around the same time, both behaviors appear across time, creating the impression of mixed policy.

To avoid confusion, run demos with consistent secure state across all nodes as below.

### Demo A: Secure OFF (no replay protection)
Goal: Show that identical requests are accepted without `secure drop`.

1) Configure secure OFF globally
- Edit `address_book.json`: set `"secure_transport": false`.
- Start all nodes (see Clean Start).

2) Run CLI
- `source venv/bin/activate` (if not using absolute venv path)
- `python start_attack_process.py`

3) Verify absence of secure lines
- In logs, confirm you do NOT see:
  - `secure accepted tx_id [...]`
  - `secure message received while secure disabled (dropped)`
  - `non-secure message received while secure enabled (dropped)`

4) Replay-like demo
- Send the same command twice:
  - `entryattack "Replay test"`
  - `entryattack "Replay test"`
- Or two identical raw votes to a follower:
  - `attack raw higher-term to 127.0.0.1:2382 1`
  - `attack raw higher-term to 127.0.0.1:2382 1`
- Expected: Target logs show both requests processed. No `secure drop` lines.

### Demo B: Secure ON with replay protection and raw-drop
Goal: Demonstrate cryptographic validation, replay protection, and outsider raw rejection.

1) Configure secure ON globally
- Edit `address_book.json`: set `"secure_transport": true`.
- Start all nodes (see Clean Start).

2) Ensure runtime secure ON everywhere
- On node3 host CLI you can still toggle, but for this demo keep all nodes ON:
  - In CLI: `secure on` (optional if already ON)

3) Seed a secure message
- Normal heartbeats will occur naturally. To be explicit:
  - `entryattack "demo"`

4) Replay last secure envelope
- Replay to a specific receiver (replace with actual follower address or name):
  - `replaylast to 127.0.0.1:2382`
- Expected on that receiver's logs:
  - `secure drop tx_id [...] (auth/replay)`

5) Outsider raw injection blocked
- Attempt a raw higher-term vote:
  - `attack raw higher-term to 127.0.0.1:2382 1`
- Expected: With secure ON, target drops as non-secure input and does NOT demote leader.

6) Insider secure higher-term effect
- Send insider (secure) higher-term:
  - `attack higher-term to <leader_or_follower_addr> 1`
- Expected: Leader demotes if delta ≥ 1; observe election and role changes. This is Raft-correct behavior and not a security failure.

### Quick Checks
- Confirm each node’s secure toggles over time:
  - `grep 'event=secure_toggle' node*_logs.txt | tail`
- Clear old noise before tests:
  - `rm -f /opt/raft/node{1,2,3}_logs.txt`

### Expected Log Lines Reference
- Replay drop (secure ON): `secure drop tx_id [...] (auth/replay)`
- Accepted secure: `secure accepted tx_id [...]`
- Non-secure blocked (secure ON): `non-secure message received while secure enabled (dropped)`
- Secure blocked (secure OFF): `secure message received while secure disabled (dropped)`

### Troubleshooting
- `replaylast` says not available: allow a message to be sent first (heartbeat or `entryattack`).
- Leadership churn in mixed mode: align secure state across all nodes for the demo.
- Duplicate command server: ensure only one `start_server3.py` instance binds on the host.


