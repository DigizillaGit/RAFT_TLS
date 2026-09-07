import socket

def send_command(command):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect(('172.104.149.60', 9999))  # Connect to node3
            client_socket.sendall(command.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            return response
        except ConnectionRefusedError:
            return "error: unable to connect to the main script"

if __name__ == '__main__':
    HELP = """
Available commands:
  secure on | secure off

  replaylast
  replaylast to <receiver>
  replaylast received

  entryattack "Your message here"

  attack higher-term to <target> <delta>
  attack raw higher-term to <target> <delta>
  attack oldvote to <target> <delta>

Targets can be node names (node1/node2/node3) or addresses (192.46.237.85:2380).
"""
    print(HELP)
    print()

    while True:
        user_input = input("Enter command: ").strip()
        if user_input.lower() == "exit":
            print("Exiting command sender.")
            break
        if not user_input:
            continue

        # Map convenience commands for secure toggle
        if user_input.lower() in ("secure on", "secure off"):
            cmd = "set secure true" if user_input.lower().endswith("on") else "set secure false"
        else:
            cmd = user_input

        response = send_command(cmd)
        print("Response:", response)