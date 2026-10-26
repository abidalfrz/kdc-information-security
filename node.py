import argparse
import json
import os
import socket as s
import threading

import protocol as p
from aes import check_key, decrypt, encrypt
from common import KDC_PORT, PEER_PORT, PROMPT, PROTOCOL_ERRORS, ask_key, log, send

HELP = """Commands:
  <text>          send an encrypted message (needs a session key)
  /rekey          run the key distribution again (new session key from the KDC)
  /master <key>   change my master key (shared with the KDC)
  /key <key>      set the session key manually (e.g. to test a wrong key)
  /keys           show my current keys
  /help           show this help
  /quit           exit"""

class Node:
    def __init__(self, my_id: str, kdc_ip: str, master_key: str):
        self.id = my_id
        self.kdc_ip = kdc_ip
        self.master_key = master_key
        self.session_key = None
        self.pending = None  
        self.peer_id = None
        self.sock = None

    # Role A
    def start_key_distribution(self):
        n1 = p.nonce()
        request = p.step1(self.id, self.peer_id, n1)
        print(f"[STEP 1] {self.id} -> KDC : IDA={self.id} IDB={self.peer_id} N1={n1}")
        try:
            reply = self.ask_kdc(request)
            ks, ticket = p.open_step2(reply, self.master_key, self.id, self.peer_id, n1)
        except (OSError, *PROTOCOL_ERRORS) as e:
            print(f"Error: Step 2 failed: {e}")
            return
        print(f"[STEP 2] KDC -> {self.id} : decrypted with Ka, N1 matches, Ks={ks}")
        self.pending = {"ks": ks}
        send(self.sock, p.step3(ticket))
        print(f"[STEP 3] {self.id} -> {self.peer_id} : E(Kb, [Ks||IDA]) = {ticket}")

    def ask_kdc(self, request: dict) -> dict:
        with s.create_connection((self.kdc_ip, KDC_PORT), timeout=5) as sock:
            send(sock, request)
            reply = json.loads(sock.makefile("r").readline())
        if reply["type"] == "error":
            raise ValueError(f"KDC: {reply['reason']}")
        return reply

    # Role B
    def on_step3(self, message: dict) -> None:
        ks, id_a = p.open_step3(message, self.master_key)
        if id_a != self.peer_id:
            raise ValueError(f"ticket is for '{id_a}', but I am connected to '{self.peer_id}'")
        log(f"[STEP 3] {id_a} -> {self.id} : decrypted with Kb, Ks={ks}")
        n2 = p.nonce()
        self.pending = {"ks": ks, "n2": n2}
        reply = p.step4(ks, n2)
        send(self.sock, reply)
        log(f"[STEP 4] {self.id} -> {id_a} : N2={n2}, E(Ks, N2) = {reply['data']}")

    # Role A
    def on_step4(self, message: dict) -> None:
        if not self.pending:
            raise ValueError("unexpected step 4")
        ks = self.pending["ks"]
        n2 = p.open_step4(message, ks)
        reply = p.step5(ks, n2)
        send(self.sock, reply)
        log(f"[STEP 4] {self.peer_id} -> {self.id} : decrypted with Ks, N2={n2}")
        log(f"[STEP 5] {self.id} -> {self.peer_id} : f(N2)={p.f(n2)}, E(Ks, f(N2)) = {reply['data']}")
        self.activate(ks)

    # Role B
    def on_step5(self, message: dict) -> None:
        if not self.pending or "n2" not in self.pending:
            raise ValueError("unexpected step 5")
        p.check_step5(message, self.pending["ks"], self.pending["n2"])
        log(f"[STEP 5] f(N2) verified, {self.peer_id} holds the same Ks")
        self.activate(self.pending["ks"])

    def activate(self, ks: str) -> None:
        self.session_key, self.pending = ks, None
        log(f"Session key established: {ks}  (AES chat is ready)\n")

    def on_message(self, message: dict) -> None:
        cipher = message["cipher"]
        log(f"[IN] ciphertext : {cipher}")
        if not self.session_key:
            log("[IN] no session key yet\n")
            return
        try:
            log(f"[IN] message    : {decrypt(cipher, self.session_key)}\n")
        except ValueError:
            log("[IN] failed to decrypt (different session key?)\n")

    def on_error(self, message: dict) -> None:
        self.pending = None
        log(f"Error: {self.peer_id}: {message['reason']}")

    def receive(self, reader) -> None:
        handlers = {"step3": self.on_step3, "step4": self.on_step4, "step5": self.on_step5,
                    "msg": self.on_message, "error": self.on_error}
        for line in reader:
            try:
                message = json.loads(line)
                handlers[message["type"]](message)
            except PROTOCOL_ERRORS as e:
                self.pending = None
                log(f"Error: Key distribution failed: {e}")
                send(self.sock, {"type": "error", "reason": f"key distribution failed: {e}"})
        print(f"\nError: {self.peer_id} disconnected.")
        os._exit(0)

    def command(self, line: str) -> bool:
        cmd, _, arg = line.partition(" ")
        if cmd == "/quit":
            return False
        if cmd == "/rekey":
            self.start_key_distribution()
        elif cmd in ("/master", "/key"):
            self.change_key(cmd, arg)
        elif cmd == "/keys":
            print(f"master  : {self.master_key}\nsession : {self.session_key}")
        elif cmd.startswith("/"):
            print(HELP)
        elif line:
            self.send_message(line)
        return True

    def change_key(self, cmd: str, key: str) -> None:
        try:
            check_key(key)
        except ValueError as e:
            print(f"Error: {e}")
            return
        if cmd == "/master":
            self.master_key = key
            print("Master key changed (must match the KDC, then /rekey)")
        else:
            self.session_key = key
            print("Session key changed")

    def send_message(self, text: str) -> None:
        if not self.session_key:
            print("Error: No session key yet, run /rekey")
            return
        try:
            cipher = encrypt(text, self.session_key)
        except ValueError as e:
            print(f"Error: {e}")
            return
        send(self.sock, {"type": "msg", "cipher": cipher})
        print(f"[OUT] ciphertext : {cipher}\n")

    def connect(self, peer_ip: str | None) -> s.socket:
        if peer_ip:
            sock = s.create_connection((peer_ip, PEER_PORT))
        else:
            server = s.socket(s.AF_INET, s.SOCK_STREAM)
            server.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", PEER_PORT))
            server.listen(1)
            print(f"Waiting for a peer on port {PEER_PORT}")
            sock, _ = server.accept()
            server.close()
        self.sock = sock
        send(sock, {"type": "hello", "id": self.id})
        return sock

    def run(self, peer_ip: str | None) -> None:
        reader = self.connect(peer_ip).makefile("r")
        self.peer_id = json.loads(reader.readline())["id"]
        print(f"Connected with '{self.peer_id}' ({self.sock.getpeername()[0]})\n")
        print(HELP + "\n")
        threading.Thread(target=self.receive, args=(reader,), daemon=True).start()
        if peer_ip:
            self.start_key_distribution()
        while True:
            try:
                if not self.command(input(PROMPT).strip()):
                    break
            except (EOFError, KeyboardInterrupt):
                break
        self.sock.close()

def main():
    parser = argparse.ArgumentParser(description="Alice / Bob node")
    parser.add_argument("id", help="my user id, e.g. alice or bob")
    parser.add_argument("--kdc", required=True, help="IP address of the KDC")
    parser.add_argument("--connect", metavar="PEER_IP", help="connect to a peer (otherwise wait for one)")
    args = parser.parse_args()

    master_key = ask_key(f"Master key of '{args.id}' (shared with the KDC)")
    Node(args.id, args.kdc, master_key).run(args.connect)

if __name__ == "__main__":
    main()