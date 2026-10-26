import json
import socket as s
import threading

import protocol as p
from aes import check_key
from common import KDC_PORT, PROMPT, PROTOCOL_ERRORS, log, send

HELP = """Commands:
  /set <id> <key>  register or change the master key shared with a user
  /del <id>        remove a user
  /list            show registered users and their master keys
  /help            show this help
  /quit            stop the KDC"""

keys = {}

def handle(conn: s.socket, addr: tuple) -> None:
    with conn:
        line = conn.makefile("r").readline()
        try:
            request = json.loads(line)
            log(f"[STEP 1] {addr[0]} -> KDC : IDA={request['id_a']} IDB={request['id_b']} N1={request['n1']}")
            ks = p.new_session_key()
            reply = p.step2(request, dict(keys), ks)
            log(f"[STEP 2] KDC -> {request['id_a']} : Ks={ks}\n"
                f"E(Ka, [Ks||IDA||IDB||N1]) = {reply['for_a']}\n"
                f"E(Kb, [Ks||IDA])          = {reply['ticket']}")
        except PROTOCOL_ERRORS as e:
            reply = {"type": "error", "reason": str(e)}
            log(f"Rejected request from {addr[0]}: {e}")
        send(conn, reply)

def serve():
    server = s.socket(s.AF_INET, s.SOCK_STREAM)
    server.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", KDC_PORT))
    server.listen()
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

def command(line: str) -> bool:
    parts = line.split(maxsplit=2)
    if not parts:
        return True
    if parts[0] == "/set" and len(parts) == 3:
        try:
            check_key(parts[2])
            keys[parts[1]] = parts[2]
            print(f"Master key of '{parts[1]}' set")
        except ValueError as e:
            print(f"Error: {e}")
    elif parts[0] == "/del" and len(parts) == 2:
        print(f"'{parts[1]}' removed" if keys.pop(parts[1], None) else "Error: Unknown user")
    elif parts[0] == "/list":
        for user, key in keys.items():
            print(f"    {user:<10} {key}")
        print(f"{len(keys)} user(s) registered")
    elif parts[0] == "/quit":
        return False
    else:
        print(HELP)
    return True

def main():
    threading.Thread(target=serve, daemon=True).start()
    print(f"KDC listening on port {KDC_PORT}")
    print(HELP + "\n")
    while True:
        try:
            if not command(input(PROMPT)):
                break
        except (EOFError, KeyboardInterrupt):
            break

if __name__ == "__main__":
    main()