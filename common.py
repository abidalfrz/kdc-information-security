import json
import readline

from aes import check_key

KDC_PORT = 6000
PEER_PORT = 5000
PROMPT = "> "

PROTOCOL_ERRORS = (ValueError, KeyError, TypeError)

def send(sock, message: dict) -> None:
    sock.sendall((json.dumps(message) + "\n").encode())

def log(text: str = "") -> None:
    print(f"\r\033[K{text}")
    print(PROMPT + readline.get_line_buffer(), end="", flush=True)

def ask_key(label: str) -> str:
    while True:
        key = input(f"{label} (16/24/32 ASCII chars): ")
        try:
            check_key(key)
            return key
        except ValueError as e:
            print(f"[!] {e}")
