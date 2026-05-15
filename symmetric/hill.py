import sys
import time
 
 
# ── Matrix Helper Functions ───────────────────────────────────
 
def mat_multiply(A, B, mod):
    """
    Multiply two matrices A and B, then apply mod to each element.
    Works for any NxN matrix.
    """
    n = len(A)
    # create result matrix filled with zeros
    result = [[0] * n for _ in range(n)]
 
    for i in range(n):
        for j in range(n):
            total = 0
            for k in range(n):
                total += A[i][k] * B[k][j]
            # apply mod to keep values in 0-25 range
            result[i][j] = total % mod
 
    return result
 
 
def mat_vec_multiply(A, v, mod):
    """
    Multiply matrix A by vector v, then apply mod.
    Used to encrypt/decrypt one block of letters.
    e.g. A = 2x2 key matrix, v = [7, 8] for letters H, I
    """
    n = len(A)
    result = [0] * n
 
    for i in range(n):
        total = 0
        for j in range(n):
            total += A[i][j] * v[j]
        # mod 26 keeps result within A-Z range
        result[i] = total % mod
 
    return result
 
 
def mod_inverse(a, m):
    """
    Find modular inverse of a mod m using Extended Euclidean Algorithm.
    We need this to find the inverse of the determinant.
    Returns x such that: a * x ≡ 1 (mod m)
    Returns None if inverse doesn't exist (gcd(a,m) != 1)
    """
    # try all values from 1 to m-1
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # no inverse exists
 
 
def determinant_2x2(matrix):
    """
    Calculate determinant of a 2x2 matrix.
    Formula: det = (a*d) - (b*c)
    | a  b |
    | c  d |
    """
    return (matrix[0][0] * matrix[1][1]) - (matrix[0][1] * matrix[1][0])
 
 
def determinant_3x3(matrix):
    """
    Calculate determinant of a 3x3 matrix using cofactor expansion.
    | a  b  c |
    | d  e  f |
    | g  h  i |
    det = a(ei-fh) - b(di-fg) + c(dh-eg)
    """
    a = matrix[0][0] * (matrix[1][1]*matrix[2][2] - matrix[1][2]*matrix[2][1])
    b = matrix[0][1] * (matrix[1][0]*matrix[2][2] - matrix[1][2]*matrix[2][0])
    c = matrix[0][2] * (matrix[1][0]*matrix[2][1] - matrix[1][1]*matrix[2][0])
    return a - b + c
 
 
def inverse_matrix_2x2(matrix, mod):
    """
    Find the inverse of a 2x2 matrix mod 26.
 
    Steps:
    1. Calculate determinant
    2. Find modular inverse of determinant
    3. Swap diagonal elements, negate off-diagonal
    4. Multiply everything by modular inverse of det
    5. Apply mod 26
    """
    det = determinant_2x2(matrix) % mod
 
    # check if inverse exists: gcd(det, 26) must equal 1
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        raise ValueError(f"Key matrix is not invertible mod {mod}. Choose a different key.")
 
    # adjugate matrix for 2x2:
    # | a  b |  →  |  d  -b |
    # | c  d |     | -c   a |
    adj = [
        [ matrix[1][1], -matrix[0][1]],
        [-matrix[1][0],  matrix[0][0]]
    ]
 
    # K_inv = det_inv * adjugate mod 26
    inv = [[0, 0], [0, 0]]
    for i in range(2):
        for j in range(2):
            # +mod*10 to avoid negative numbers before mod
            inv[i][j] = (det_inv * adj[i][j]) % mod
 
    return inv
 
 
def is_valid_key(matrix, mod=26):
    """
    Check if a key matrix is valid for Hill cipher.
    Condition: gcd(determinant, 26) must equal 1
    i.e. the determinant must have a modular inverse mod 26
    """
    n = len(matrix)
    if n == 2:
        det = determinant_2x2(matrix) % mod
    elif n == 3:
        det = determinant_3x3(matrix) % mod
    else:
        return False
 
    return mod_inverse(det, mod) is not None
 
 
# ── Core Encryption / Decryption ──────────────────────────────
 
def hill_encrypt(plaintext, key_matrix):
    """
    Encrypt plaintext using Hill cipher.
    Formula: C = (K x P) mod 26
 
    Process:
    1. Remove non-letters and convert to uppercase
    2. Split into blocks matching key matrix size
    3. Pad with 'X' if last block is incomplete
    4. Multiply each block by key matrix mod 26
    5. Convert numbers back to letters
    """
    n = len(key_matrix)  # block size = matrix dimension (2 or 3)
 
    # keep only letters, convert to uppercase
    plaintext = ''.join(c for c in plaintext.upper() if c.isalpha())
 
    # pad with 'X' if text length not divisible by block size
    # e.g. block size=2, text="HELLO" (5 letters) → pad to "HELLOX" (6 letters)
    while len(plaintext) % n != 0:
        plaintext += 'X'
 
    ciphertext = ""
 
    # process one block at a time
    for i in range(0, len(plaintext), n):
        block = plaintext[i:i+n]
 
        # convert block letters to numbers
        # e.g. "HI" → [7, 8]
        P = [ord(c) - ord('A') for c in block]
 
        # multiply key matrix by plaintext vector mod 26
        # C = (K x P) mod 26
        C = mat_vec_multiply(key_matrix, P, 26)
 
        # convert numbers back to letters and add to result
        ciphertext += ''.join(chr(num + ord('A')) for num in C)
 
    return ciphertext
 
 
def hill_decrypt(ciphertext, key_matrix):
    """
    Decrypt ciphertext using Hill cipher.
    Formula: P = (K_inv x C) mod 26
 
    Process:
    1. Find inverse of key matrix mod 26
    2. Split ciphertext into blocks
    3. Multiply each block by inverse key matrix mod 26
    4. Convert numbers back to letters
    """
    n = len(key_matrix)
 
    # keep only letters
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
 
    # find inverse of key matrix mod 26
    if n == 2:
        inv_matrix = inverse_matrix_2x2(key_matrix, 26)
    else:
        raise ValueError("Only 2x2 key matrix supported for decryption in this implementation")
 
    plaintext = ""
 
    # process one block at a time
    for i in range(0, len(ciphertext), n):
        block = ciphertext[i:i+n]
 
        # convert block letters to numbers
        C = [ord(c) - ord('A') for c in block]
 
        # multiply inverse key matrix by ciphertext vector mod 26
        # P = (K_inv x C) mod 26
        P = mat_vec_multiply(inv_matrix, C, 26)
 
        # convert numbers back to letters
        plaintext += ''.join(chr(num + ord('A')) for num in P)
 
    return plaintext
 
 
# ── File Encryption ───────────────────────────────────────────
 
def encrypt_file(input_path, output_path, key_matrix):
    """
    Read a text file, encrypt it using Hill cipher, save result
    """
    with open(input_path, 'r') as f:
        content = f.read()
 
    encrypted = hill_encrypt(content, key_matrix)
 
    with open(output_path, 'w') as f:
        f.write(encrypted)
 
    print(f"File encrypted → {output_path}")
 
 
def decrypt_file(input_path, output_path, key_matrix):
    """
    Read an encrypted file, decrypt it using Hill cipher, save result
    """
    with open(input_path, 'r') as f:
        content = f.read()
 
    decrypted = hill_decrypt(content, key_matrix)
 
    with open(output_path, 'w') as f:
        f.write(decrypted)
 
    print(f"File decrypted → {output_path}")
 
 
# ── Step-by-step (Handwritten Verification Helper) ────────────
 
def show_steps(plaintext, key_matrix):
    """
    Print every encryption step in detail.
    Use this as reference for your handwritten verification.
    """
    n = len(key_matrix)
    plaintext = ''.join(c for c in plaintext.upper() if c.isalpha())
    while len(plaintext) % n != 0:
        plaintext += 'X'
 
    print(f"\n{'='*55}")
    print(f"  Hill Cipher - Step by Step")
    print(f"  Plaintext  : {plaintext}")
    print(f"  Block size : {n} (matrix is {n}x{n})")
    print(f"\n  Key Matrix:")
    for row in key_matrix:
        print(f"    {row}")
    print(f"{'='*55}")
 
    result = ""
 
    for i in range(0, len(plaintext), n):
        block = plaintext[i:i+n]
        P = [ord(c) - ord('A') for c in block]
        C = mat_vec_multiply(key_matrix, P, 26)
        cipher_block = ''.join(chr(num + ord('A')) for num in C)
 
        print(f"\n  Block: {block} → numbers: {P}")
        print(f"  Matrix multiplication:")
        for row_i, row in enumerate(key_matrix):
            terms = " + ".join(f"{row[j]}x{P[j]}" for j in range(n))
            total = sum(row[j] * P[j] for j in range(n))
            print(f"    row {row_i}: {terms} = {total} → {total % 26} mod 26 = {chr(C[row_i] + ord('A'))}")
 
        print(f"  Result: {block} → {cipher_block}")
        result += cipher_block
 
    print(f"\n{'='*55}")
    print(f"  Final result: {plaintext} → {result}")
    print(f"{'='*55}\n")
    return result
 
 
# ── Performance Analysis ──────────────────────────────────────
 
def performance_analysis(text, key_matrix):
    """
    Measure and print:
    - Input size in characters and bytes
    - Encryption runtime in milliseconds
    - Ciphertext size in bytes
    - Size overhead compared to original
    """
    print(f"\n{'='*40}")
    print(f"  Performance Analysis — Hill Cipher")
    print(f"{'='*40}")
    print(f"  Input size     : {len(text)} chars  ({sys.getsizeof(text)} bytes)")
 
    start = time.perf_counter()
    encrypted = hill_encrypt(text, key_matrix)
    end = time.perf_counter()
 
    runtime_ms = (end - start) * 1000
 
    print(f"  Runtime        : {runtime_ms:.4f} ms")
    print(f"  Ciphertext size: {sys.getsizeof(encrypted)} bytes")
    print(f"  Size overhead  : {sys.getsizeof(encrypted) - sys.getsizeof(text)} bytes")
    print(f"{'='*40}\n")
 
 
# ── Main ──────────────────────────────────────────────────────
 
if __name__ == "__main__":
 
    # 2x2 key matrix — must have det with modular inverse mod 26
    key_matrix = [
        [3, 3],
        [2, 5]
    ]
 
    # check key is valid before using it
    if not is_valid_key(key_matrix):
        print("ERROR: Key matrix is not valid! det must be coprime with 26.")
        exit()
 
    message = "HI"
 
    # --- Basic encrypt / decrypt test ---
    print(">>> Basic Test")
    encrypted = hill_encrypt(message, key_matrix)
    decrypted = hill_decrypt(encrypted, key_matrix)
    print(f"  Original : {message}")
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Match    : {message == decrypted}")
 
    # --- Step by step (use as reference for handwritten verification) ---
    show_steps("HI", key_matrix)
 
    # --- Longer test ---
    message2 = "HELLO WORLD"
    encrypted2 = hill_encrypt(message2, key_matrix)
    decrypted2 = hill_decrypt(encrypted2, key_matrix)
    print(f">>> Longer Test")
    print(f"  Original : {message2}")
    print(f"  Encrypted: {encrypted2}")
    print(f"  Decrypted: {decrypted2}")
 
    # --- Performance test ---
    long_text = "HELLO WORLD " * 500
    performance_analysis(long_text, key_matrix)
