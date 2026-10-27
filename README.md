# Key Distribution (KDC) + Two-Way AES Chat

| Name | NRP |
|---|---|
| Muhammad Abid Baihaqi Al Faridzi | 5025241133 |
| Yoseph Kevin Hendrata | 5025241146 |

## Files

| File | Contents |
|---|---|
| `aes.py` | Manual AES-128/192/256, CBC mode, PKCS#7 padding |
| `protocol.py` | The 5 key distribution steps |
| `kdc.py` | KDC server (port 6000) |
| `node.py` | Alice / Bob chat program (Bob listens on port 5000) |
| `common.py` | Shared helpers |

## Key Distribution Scenario

```
1. A   -> KDC : IDA || IDB || N1
2. KDC -> A   : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
3. A   -> B   : E(Kb, [Ks || IDA])
4. B   -> A   : E(Ks, N2)
5. A   -> B   : E(Ks, f(N2))      f(N2) = N2 + 1
```

## Run

**KDC**
```bash
python3 kdc.py
> /set alice KeyAliceKDC12345
> /set bob KeyBobKDC1234567
```

**Bob**
```bash
python3 node.py bob --kdc <KDC_IP>
```

**Alice**
```bash
python3 node.py alice --kdc <KDC_IP> --connect <BOB_IP>
```

Type a message and press Enter to send. Other commands: `/rekey`, `/master <key>`, `/key <key>`, `/keys`, `/help`, `/quit`.

## License

Copyright (c) 2026 Muhammad Abid Baihaqi Al Faridzi and Yoseph Kevin Hendrata. All rights reserved.
