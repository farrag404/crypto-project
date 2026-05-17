# CryptoMsg — Secure Messaging System

A cryptographic software tool implementing symmetric and asymmetric encryption
from scratch, with a fully integrated secure messaging application.

---

## Project Structure

cryptoProject/
├── asymmetric/
│   ├── __init__.py
│   ├── ntru.py          # NTRU core (post-quantum)
│   ├── kem.py           # Key Encapsulation Mechanism
│   ├── poly.py          # Polynomial arithmetic
│   ├── inverse.py       # Polynomial Extended Euclidean Algorithm
│   └── kdf.py           # SHA-256 Key Derivation Function
├── symmetric/
│   ├── __init__.py
│   ├── vigenere.py      # Vigenere cipher (encryption at rest)
│   └── hill.py          # Hill cipher (encryption in transit)
├── system/
│   ├── __init__.py
│   ├── ca.py            # Certificate Authority
│   ├── server.py        # Secure messaging server
│   ├── client.py        # Secure messaging client
│   └── gui.py           # Tkinter GUI
├── utils/
│   ├── __init__.py
│   └── math_utils.py    # GCD, mod inverse, mod exp, matrix ops
├── benchmark.py         # NTRU performance analysis
├── bench.py             # Vigenere vs Hill performance comparison
├── test_ntru.py         # NTRU correctness test
└── README.md

---

## Requirements

- Python 3.10 or higher
- No external cryptographic libraries used
- Standard library only (hashlib, random, tkinter, time)

---

## How to Run

### 1. GUI Application (Recommended)

```bash
python -m system.gui
```

Opens the full graphical interface where you can:
- Send encrypted messages as abdelrahman or ahmed
- View Hill-encrypted messages in transit
- View Vigenere-encrypted messages stored at rest
- Rotate session keys
- Revoke certificates
- Rotate CA keys
- View server inbox

### 2. Run NTRU Test

```bash
python -m test_ntru
```

Verifies that the NTRU Key Encapsulation Mechanism works correctly.
Expected output:

CLIENT KEY: <hex>
SERVER KEY: <hex>
MATCH: True

### 3. Run Symmetric Benchmark

```bash
cd symmetric
python bench.py
```

Compares Vigenere vs Hill cipher performance across different text sizes.

### 4. Run NTRU Benchmark

```bash
python benchmark.py
```

Measures NTRU keygen, encrypt, decrypt, encapsulate, and decapsulate times
over 100 iterations.

---

## Encryption Flow

```
Client                          Server
  |                               |
  |-- verify server cert (CA) --> |
  |<-- NTRU KEM key exchange ---> |
  |                               |
  |-- Hill cipher (transit) ----> |
  |                               |
  |                  Vigenere (at rest) --> database.txt
```

### Algorithms Used

| Layer       | Algorithm     | Purpose                        |
|-------------|---------------|--------------------------------|
| Transit     | Hill Cipher   | Encrypt messages in transit    |
| At Rest     | Vigenere      | Encrypt messages in database   |
| Key Exchange| NTRU KEM      | Derive shared session secret   |
| Auth        | CA + Certs    | Verify server/client identity  |

---

## Cryptographic Details

### Vigenere Cipher
- Formula: `C = (P + K) mod 26`
- Decryption: `P = (C - K + 26) mod 26`
- Implemented from scratch, character by character

### Hill Cipher
- Formula: `C = (K × P) mod 26`
- Key matrix: `K = [[3,3],[2,5]]`  (det=9, gcd(9,26)=1)
- Decryption uses matrix inverse mod 26
- Implemented using manual matrix multiplication

### NTRU (Post-Quantum)
- Parameters: `N=17, q=127, p=3`
- Ring: `Z[x] / (x^N - 1)`
- Key generation, encryption, decryption all implemented from scratch
- Used as a Key Encapsulation Mechanism (KEM)

### Certificate Authority
- Issues signed certificates for server and clients
- Verifies signatures using SHA-256 hash
- Supports certificate revocation (CRL)
- Supports CA key rotation (re-issues all valid certs)

---

## Key Management

| Operation        | Description                                      |
|------------------|--------------------------------------------------|
| Key Generation   | NTRU keygen on startup for each party            |
| Key Exchange     | NTRU KEM encapsulate/decapsulate                 |
| Session Rotation | New NTRU exchange replaces old shared secret     |
| CA Rotation      | New CA keys, all certs re-issued, old revoked    |
| Revocation       | Certificate serial added to CRL, messages blocked|

---

## AI Usage Declaration

AI tools (Claude) were used for:
- Code suggestions and syntax help
- Debugging error messages
- GUI layout assistance

---

## Academic Integrity

This project was developed as part of a cryptography coursework.
All submitted work reflects the team's own understanding and effort.
No encryption libraries (OpenSSL, PyCryptodome, etc.) were used.
Only Python's standard library ('hashlib' for SHA-256 in KDF, 'random' for key generation) was used alongside manual mathematical implementations.