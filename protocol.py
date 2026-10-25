import json
import secrets
import string

from aes import decrypt, encrypt

SESSION_KEY_LENGTH = 16  # AES-128
SESSION_KEY_CHARS = string.ascii_letters + string.digits

def nonce() -> int:
    return secrets.randbits(32)

def f(n: int) -> int:
    return n + 1

def new_session_key() -> str:
    return "".join(secrets.choice(SESSION_KEY_CHARS) for _ in range(SESSION_KEY_LENGTH))

def seal(fields: dict, key: str) -> str:
    return encrypt(json.dumps(fields), key)

def unseal(cipher_hex: str, key: str) -> dict:
    return json.loads(decrypt(cipher_hex, key))

def step1(id_a: str, id_b: str, n1: int) -> dict:
    return {"type": "step1", "id_a": id_a, "id_b": id_b, "n1": n1}

# KDC side
def step2(request: dict, keys: dict, ks: str) -> dict:
    if request.get("type") != "step1":
        raise ValueError("expected a step 1 request")
    id_a, id_b, n1 = request["id_a"], request["id_b"], request["n1"]
    for user in (id_a, id_b):
        if user not in keys:
            raise ValueError(f"unknown user '{user}'")
    return {
        "type": "step2",
        "for_a": seal({"ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1}, keys[id_a]),
        "ticket": seal({"ks": ks, "id_a": id_a}, keys[id_b]),
    }

# A side
def open_step2(reply: dict, ka: str, id_a: str, id_b: str, n1: int) -> tuple:
    fields = unseal(reply["for_a"], ka)
    if (fields["id_a"], fields["id_b"], fields["n1"]) != (id_a, id_b, n1):
        raise ValueError("reply does not match the request (wrong N1 / IDs, replay?)")
    return fields["ks"], reply["ticket"]

def step3(ticket: str) -> dict:
    return {"type": "step3", "ticket": ticket}

# B side
def open_step3(message: dict, kb: str) -> tuple:
    fields = unseal(message["ticket"], kb)
    return fields["ks"], fields["id_a"]

def step4(ks: str, n2: int) -> dict:
    return {"type": "step4", "data": seal({"n2": n2}, ks)}

def open_step4(message: dict, ks: str) -> int:
    return unseal(message["data"], ks)["n2"]

def step5(ks: str, n2: int) -> dict:
    return {"type": "step5", "data": seal({"f_n2": f(n2)}, ks)}

def check_step5(message: dict, ks: str, n2: int) -> None:
    if unseal(message["data"], ks)["f_n2"] != f(n2):
        raise ValueError("f(N2) does not match")