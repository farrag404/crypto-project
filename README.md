# Cryptography Project

A comprehensive implementation of classical and modern cryptographic algorithms, including symmetric ciphers, asymmetric cryptography (NTRU), key encapsulation mechanisms, and a secure messaging system.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Modules](#modules)
4. [Installation & Setup](#installation--setup)
5. [Usage Examples](#usage-examples)
6. [Cryptographic Algorithms](#cryptographic-algorithms)
7. [Testing](#testing)
8. [Performance Analysis](#performance-analysis)

---

## 🎯 Overview

This project implements multiple cryptographic systems:

- **Symmetric Encryption**: Vigenere cipher, Hill cipher
- **Asymmetric Encryption**: NTRU (N-th Degree Truncated Polynomial Ring Units)
- **Key Encapsulation Mechanism (KEM)**: NTRU-based KEM for secure key exchange
- **Key Derivation**: SHA-256 based KDF
- **Certificate Authority**: CA system for certificate issuance and verification
- **Secure Messaging**: Client-server system with encrypted communication

---

## 📁 Project Structure

```
crypto-project/
├── asymmetric/              # Asymmetric cryptography (NTRU)
│   ├── __init__.py
│   ├── ntru.py             # NTRU cipher implementation
│   ├── kem.py              # Key Encapsulation Mechanism
│   ├── poly.py             # Polynomial arithmetic operations
│   ├── inverse.py          # Polynomial modular inverse (EEA)
│   └── kdf.py              # Key Derivation Function (SHA-256)
│
├── symmetric/              # Symmetric encryption
│   ├── __init__.py
│   ├── vigenere.py         # Vigenere cipher
│   └── hill.py             # Hill cipher (block cipher)
│
├── system/                 # Secure messaging system
│   ├── __init__.py
│   ├── ca.py              # Certificate Authority
│   ├── client.py          # Secure messaging client
│   └── server.py          # Secure messaging server
│
├── utils/                 # Utility functions
│   ├── __init__.py
│   ├── helpers.py         # General helpers
│   └── math_utils.py      # Mathematical utilities (GCD, modular inverse, etc.)
│
├── test_ntru.py          # NTRU cipher tests (key exchange, encryption/decryption)
├── benchmark.py          # Performance analysis
└── README.md            # This file
```

---

## 📦 Modules

### **asymmetric/** - NTRU Cryptosystem

#### `ntru.py` - Core NTRU Algorithm

Implements the NTRU public-key cryptosystem in polynomial ring Z_q[x]/(x^N - 1).

**Key Components:**

- `NTRU` class with parameters:
  - `N=17`: Polynomial degree
  - `q=127`: Large modulus
  - `p=3`: Small modulus

**Methods:**

- `keygen()`: Generate public key from two random sparse polynomials (f, g)
- `encrypt(message, public_key)`: Encrypt a message polynomial
- `decrypt(ciphertext)`: Decrypt using private key
- `random_sparse_poly()`: Generate random sparse polynomial
- `random_message_poly()`: Generate random message polynomial

**Key Mathematical Operations:**

- Private key: f (sparse polynomial)
- Public key: h = p _ g _ f^(-1) (mod q)
- Encryption: c = r\*h + m (mod q)
- Decryption: m = (f*c mod q) → (a mod p) → (a * f^(-1) mod p)

#### `poly.py` - Polynomial Arithmetic

Handles polynomial operations in the quotient ring Z_q[x]/(x^N - 1).

**Functions:**

- `poly_add(a, b, q)`: Polynomial addition modulo q
- `poly_sub(a, b, q)`: Polynomial subtraction modulo q
- `poly_mul(a, b, N, q)`: Cyclic convolution (multiplication in quotient ring)
- `poly_scalar_mul(poly, scalar, q)`: Scalar multiplication
- `poly_center(poly, q)`: Center coefficients to symmetric interval [-q/2, q/2]

#### `inverse.py` - Modular Inverse Computation

Implements Extended Euclidean Algorithm (EEA) for finding polynomial modular inverses.

**Key Function:**

- `poly_inverse(f, N, q)`: Compute f^(-1) mod (q, x^N - 1)
- Returns `None` if inverse doesn't exist

#### `kem.py` - Key Encapsulation Mechanism

NTRU-based KEM for secure key exchange between parties.

**Methods:**

- `encapsulate(public_key)`: Generate random seed, encrypt it, derive shared key
- `decapsulate(ciphertext)`: Decrypt ciphertext, recover seed, derive same shared key

**Purpose:** Allows two parties to independently establish a shared secret.

#### `kdf.py` - Key Derivation Function

Derives cryptographic keys from polynomial secrets.

**Function:**

- `derive_key(poly_secret)`: Convert polynomial to bytes and hash with SHA-256

---

### **symmetric/** - Symmetric Encryption

#### `vigenere.py` - Vigenere Cipher

Classic polyalphabetic substitution cipher.

**Encryption Formula:** C = (P + K) mod 26
**Decryption Formula:** P = (C - K + 26) mod 26

**Functions:**

- `vigenere_encrypt(plaintext, key)`: Encrypt plaintext with key
- `vigenere_decrypt(ciphertext, key)`: Decrypt ciphertext with key

**Features:**

- Key repeats cyclically over plaintext
- Non-alphabetic characters preserved
- Case-insensitive operation

**Example:**

```
Plaintext:  HELLO WORLD
Key:        SECRET
Ciphertext: ZMBUL ZSRYP
```

#### `hill.py` - Hill Cipher

Block cipher using matrix operations over modular arithmetic.

**Key:** 2×2 or NxN invertible matrix
**Encryption:** c = A·m mod 26
**Decryption:** m = A^(-1)·c mod 26

**Functions:**

- `hill_encrypt(plaintext, key_matrix)`: Encrypt using matrix key
- `hill_decrypt(ciphertext, key_matrix)`: Decrypt using inverse matrix

**Requirements:**

- Key matrix must be invertible mod 26
- Determinant must be coprime with 26

---

### **system/** - Secure Messaging System

#### `ca.py` - Certificate Authority

Issues, verifies, and manages digital certificates for secure communication.

**Certificate Structure:**

```python
{
    "subject": "server" | "client_<name>",
    "public_key": [...],      # NTRU public key polynomial
    "issued_at": <timestamp>,
    "expires_at": <timestamp>,
    "serial": <int>,          # Unique certificate ID
    "signature": <int>        # Hash signed by CA
}
```

**Key Methods:**

- `generate_cert(subject, public_key)`: Issue certificate
- `verify_cert(cert)`: Verify certificate authenticity
- `revoke_cert(serial)`: Add to revocation list (CRL)

**Security:** Certificates are signed using CA's NTRU private key.

#### `client.py` - Secure Messaging Client

Implements secure client for encrypted messaging.

**Connection Flow:**

1. Generate NTRU key pair
2. Register with CA and obtain certificate
3. Verify server's certificate
4. Perform NTRU-KEM key exchange
5. Establish session key
6. Encrypt messages with Hill cipher

**Key Features:**

- Certificate-based authentication
- Perfect forward secrecy via KEM
- Session key rotation support

#### `server.py` - Secure Messaging Server

Implements server for secure communication.

**Connection Flow:**

1. Register with CA and hold signed certificate
2. Accept client connections
3. Verify client certificates
4. Perform NTRU-KEM with each client
5. Decrypt incoming messages (Hill cipher)
6. Store messages at rest (Vigenere encryption)

**Security:**

- Client authentication via certificates
- Transport encryption (Hill cipher + session key)
- At-rest encryption (Vigenere cipher)

---

### **utils/** - Utility Functions

#### `math_utils.py` - Mathematical Operations

Core mathematical functions used throughout the project.

**Functions:**

- `gcd(a, b)`: Greatest Common Divisor (Euclidean algorithm)
- `extended_gcd(a, b)`: Extended Euclidean Algorithm - returns (gcd, x, y)
- `mod_inverse(a, m)`: Compute modular inverse: a·x ≡ 1 (mod m)
- `mod_exp(base, exp, mod)`: Fast modular exponentiation

**Usage Example:**

```python
# Find modular inverse of 3 mod 26
inverse = mod_inverse(3, 26)  # Returns 9 (since 3*9 = 27 ≡ 1 mod 26)
```

#### `helpers.py`

General helper functions and utilities (extend as needed).

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.7+
- No external cryptographic libraries (all implemented from scratch)

### Setup

```bash
# Clone or navigate to project directory
cd crypto-project

# No external dependencies needed
# All modules are self-contained
```

---

## 💡 Usage Examples

### Example 1: NTRU Encryption & Decryption

```python
from asymmetric.ntru import NTRU

# Initialize NTRU with parameters
ntru = NTRU(N=17, q=127, p=3)

# Generate key pair
public_key = ntru.keygen()

# Create a message
message = ntru.random_message_poly()

# Encrypt message
ciphertext = ntru.encrypt(message, public_key)

# Decrypt message
decrypted = ntru.decrypt(ciphertext)

assert message == decrypted  # Verification
```

### Example 2: NTRU Key Exchange (KEM)

```python
from asymmetric.ntru import NTRU
from asymmetric.kem import NTRUKEM

# Initialize and generate keys
ntru = NTRU(N=17, q=127, p=3)
public_key = ntru.keygen()

# Create KEM instance
kem = NTRUKEM(ntru)

# Client encapsulates (generates shared key)
ciphertext, client_key = kem.encapsulate(public_key)

# Server decapsulates (derives same key)
server_key = kem.decapsulate(ciphertext)

assert client_key == server_key  # Both parties have same key
```

### Example 3: Vigenere Cipher

```python
from symmetric.vigenere import vigenere_encrypt, vigenere_decrypt

plaintext = "HELLO WORLD"
key = "SECRET"

# Encrypt
ciphertext = vigenere_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")  # Output: ZMBUL ZSRYP

# Decrypt
recovered = vigenere_decrypt(ciphertext, key)
print(f"Recovered: {recovered}")     # Output: HELLO WORLD

assert plaintext == recovered
```

### Example 4: Hill Cipher

```python
from symmetric.hill import hill_encrypt, hill_decrypt

plaintext = "HELLO"
key_matrix = [[3, 3], [2, 5]]

# Encrypt (processes 2 chars at a time)
ciphertext = hill_encrypt(plaintext, key_matrix)
print(f"Ciphertext: {ciphertext}")

# Decrypt
recovered = hill_decrypt(ciphertext, key_matrix)
print(f"Recovered: {recovered}")

assert plaintext == recovered
```

### Example 5: Secure Messaging System

```python
from system.ca import CertificateAuthority
from system.client import Client
from system.server import Server

# Set up CA
ca = CertificateAuthority()

# Create server
server = Server("secure-server", ca)

# Create client
client = Client("alice", ca)

# Client connects to server
session_key = client.connect(server)

# Client sends encrypted message
message = "Hello, Server!"
client.send(server, message)

# Server receives and decrypts
received = server.receive_message(client.username)
print(f"Server received: {received}")
```

---

## 🔐 Cryptographic Algorithms

### NTRU - N-th Degree Truncated Polynomial Ring Units

**Overview:** Lattice-based public-key cryptosystem believed to be resistant to quantum attacks.

**Ring:** Z_q[x]/(x^N - 1) - polynomials of degree < N with coefficients mod q

**Parameters:**

- N = 17 (polynomial degree)
- q = 127 (large modulus)
- p = 3 (small modulus)

**Key Generation:**

1. Choose random sparse polynomials f, g
2. Compute f^(-1) mod q and f^(-1) mod p
3. Public key: h = (p·g·f^(-1)) mod q

**Encryption:**

- Choose random sparse polynomial r
- c = (r·h + m) mod q

**Decryption:**

- a = (f·c) mod q
- a_mod_p = a mod p
- m = (a_mod_p · f^(-1)) mod p

**Security:** Based on difficulty of finding short vectors in lattices.

---

### Vigenere Cipher

**Type:** Polyalphabetic substitution cipher

**Algorithm:**

- Repeat key cyclically over plaintext
- Each plaintext character shifted by corresponding key character
- Shift amount: (key_char - 'A')

**Security:** Vulnerable to frequency analysis and Kasiski examination. Suitable for educational purposes only.

---

### Hill Cipher

**Type:** Polygraphic block cipher

**Algorithm:**

- Block size: typically 2 or 3 characters
- Key: Invertible matrix mod 26
- Encryption: c = A·m (mod 26)
- Decryption: m = A^(-1)·c (mod 26)

**Key Requirements:**

- Matrix must be invertible mod 26
- gcd(det(A), 26) = 1

---

## 🧪 Testing

### Run All Tests

```bash
python test_ntru.py
```

**Test Cases:**

1. **KEM Key Exchange**: Verify client and server derive same shared key
2. **Encrypt/Decrypt**: Verify message recovery after encryption
3. **Multiple Cycles**: Run 3 encrypt/decrypt cycles for consistency

**Expected Output:**

```
CLIENT KEY: 28aaabc6e7f91a434fcc95044c7dd0d59edd1b4bd531214734f689bcf23fc78a
SERVER KEY: 28aaabc6e7f91a434fcc95044c7dd0d59edd1b4bd531214734f689bcf23fc78a

MATCH: True

--- Testing Encrypt/Decrypt ---
Original message: [2, 1, 0, 2, 2, 0, 0, 2, 1, 0, 0, 0, 0, 1, 2, 1, 1]
Encrypted: [94, 103, 44, 22, 23, 66, 34, 31, 38, 59, 18, 51, 111, 79, 6, 100, 25]
Decrypted: [2, 1, 0, 2, 2, 0, 0, 2, 1, 0, 0, 0, 0, 1, 2, 1, 1]
MATCH: True

--- Testing Multiple Encrypt/Decrypt Cycles ---
Test 1: True
Test 2: True
Test 3: True
All tests passed: True
```

---

## ⚡ Performance Analysis

Run performance benchmarks:

```bash
python benchmark.py
```

**Metrics Collected:**

- Key generation time
- Encryption time
- Decryption time
- KEM encapsulation time
- KEM decapsulation time
- Public key size (bytes)
- Ciphertext size (bytes)

**Benchmark Results (100 iterations):**

- Reports average times and standard deviations
- Analyzes performance scaling
- Provides insights for optimization

---

## 🎓 Educational Value

This project is designed to:

- Understand fundamental cryptographic concepts
- Study polynomial arithmetic and ring operations
- Learn about lattice-based cryptography
- Explore symmetric cipher implementation
- Understand PKI and certificate systems
- Implement secure communication protocols

---

## ⚠️ Security Notice

**This is an educational project.** Do NOT use for production environments:

- NTRU parameters (N, q, p) are toy-sized
- No protection against side-channel attacks
- Simplified signature scheme (XOR-based)
- No input validation or error handling beyond basics

For production cryptography, use well-tested libraries like OpenSSL, libsodium, or cryptography.py.

---

## 📝 License

Open source for educational purposes.

---

## 🤝 Contributing

Feel free to extend with:

- Additional cryptographic algorithms
- Improved polynomial arithmetic
- Side-channel attack resistance
- Formal security proofs
- Performance optimizations

---

## 📚 References

- **NTRU:** Hoffstein, J., Pipher, J., Silverman, J.H. (1998). "NTRU: A Ring-Based Public Key Cryptosystem"
- **Hill Cipher:** Hill, L.S. (1929). "Cryptography in an Algebraic Alphabet"
- **Vigenere Cipher:** Vigenere, B. (1586). "Traicté des Chiffres"
- **Lattice-Based Cryptography:** Peikert, C. (2016). "A Decade of Lattice Cryptography"

---

**Last Updated:** May 17, 2026
