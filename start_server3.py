#!/usr/bin/env python
from raft import RaftNode
import json
import socket
import threading

address_book_fname = 'address_book.json'

def handle_commands(s0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('localhost', 9999))
        except OSError as e:
            if getattr(e, 'errno', None) == 98:
                print("Command server already running; skipping")
                return
            raise
        server_socket.listen(5)

        while True:
            conn, addr = server_socket.accept()
            with conn:
                data = conn.recv(1024)
                if not data:
                    continue
                command = data.decode('utf-8').strip()

                try:
                    if command.startswith("replayattack bypass "):
                        _, _, bypass_value = command.split(maxsplit=2)
                        bypass = bypass_value.lower() == "true"
                        #print(f"Executing replay attack with bypass_timestamp={bypass}")
                        s0.replay_attack(bypass_timestamp=bypass)
                        #conn.sendall(b"replayattack executed successfully")

                    elif command.strip() == "replaylast":
                        ok = s0.replay_last_envelope(None)
                        conn.sendall(b"ok: replaylast executed" if ok else b"error: replaylast not available")

                    elif command.startswith("replaylast to "):
                        _, _, target = command.partition("replaylast to ")
                        target = target.strip() or None
                        ok = s0.replay_last_envelope(target)
                        conn.sendall(f"ok: replaylast to {target}".encode() if ok else f"error: replaylast to {target} not available".encode())

                    elif command.strip() == "replaylast received":
                        ok = s0.replay_last_received_envelope()
                        conn.sendall(b"ok: replaylast received executed" if ok else b"error: replaylast received not available")

                    elif command.startswith("entryattack "):
                        _, message = command.split(maxsplit=1)
                        #print(f"Executing log replication attack with message: {message}")
                        s0.send_entry_attack(message)
                        conn.sendall(b"ok: entryattack executed")

                    elif command.startswith("attack higher-term to "):
                        # attack higher-term to <target> <delta>
                        try:
                            _, _, rest = command.partition("attack higher-term to ")
                            parts = rest.strip().split()
                            target = parts[0]
                            delta = int(parts[1]) if len(parts) > 1 else 1
                            ok = s0.send_vote_attack(target=target, delta_term=delta, raw=False, old_term=False)
                            conn.sendall(f"ok: higher-term to {target} delta={delta}".encode() if ok else b"error: higher-term attack failed")
                        except Exception as e:
                            print(f"attack higher-term parse error: {e}")
                            conn.sendall(b"error: invalid higher-term command")

                    elif command.startswith("attack raw higher-term to "):
                        # attack raw higher-term to <target> <delta>
                        try:
                            _, _, rest = command.partition("attack raw higher-term to ")
                            parts = rest.strip().split()
                            target = parts[0]
                            delta = int(parts[1]) if len(parts) > 1 else 1
                            ok = s0.send_vote_attack(target=target, delta_term=delta, raw=True, old_term=False)
                            conn.sendall(f"ok: raw higher-term to {target} delta={delta}".encode() if ok else b"error: raw higher-term attack failed")
                        except Exception as e:
                            print(f"attack raw higher-term parse error: {e}")
                            conn.sendall(b"error: invalid raw higher-term command")

                    elif command.startswith("attack oldvote to "):
                        # attack oldvote to <target> <delta>
                        try:
                            _, _, rest = command.partition("attack oldvote to ")
                            parts = rest.strip().split()
                            target = parts[0]
                            delta = int(parts[1]) if len(parts) > 1 else 1
                            ok = s0.send_vote_attack(target=target, delta_term=delta, raw=False, old_term=True)
                            conn.sendall(f"ok: oldvote to {target} delta={delta}".encode() if ok else b"error: oldvote attack failed")
                        except Exception as e:
                            print(f"attack oldvote parse error: {e}")
                            conn.sendall(b"error: invalid oldvote command")

                    else:
                        if command.strip() == "set secure true":
                            s0.set_secure(True)
                            conn.sendall(b"ok: secure enabled")
                        elif command.strip() == "set secure false":
                            s0.set_secure(False)
                            conn.sendall(b"ok: secure disabled")
                        else:
                            conn.sendall(b"error: invalid command")
                except Exception as e:
                    print(f"Error handling command '{command}': {e}")
                    #conn.sendall(b"error: failed to execute command")

if __name__ == '__main__':
    s0 = RaftNode(address_book_fname, 'node3', 'follower')

    s0.start()

    # Start a thread to handle external commands
    threading.Thread(target=handle_commands, args=(s0,), daemon=True).start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        s0.stop()
