"""
Vigenere Cipher - Implemented from scratch
No encryption libraries used - only basic Python
"""

def vigenere_encrypt(plaintext, key):
    """
    Encrypt plaintext using Vigenere cipher
    Formula: C = (P + K) mod 26
    """
    key = key.upper().replace(" ", "")
    plaintext = plaintext.upper()
    
    ciphertext = ""
    key_index = 0  # tracks position in key (separate from text index)

    for char in plaintext:
        if char.isalpha():
            P = ord(char) - ord('A')           # convert letter to number (A=0, Z=25)
            K = ord(key[key_index % len(key)]) - ord('A')  # key letter as number
            C = (P + K) % 26                   # encrypt formula
            ciphertext += chr(C + ord('A'))    # convert back to letter
            key_index += 1                     # only advance key on letters
        else:
            ciphertext += char                 # spaces/symbols stay as-is

    return ciphertext


def vigenere_decrypt(ciphertext, key):
    """
    Decrypt ciphertext using Vigenere cipher
    Formula: P = (C - K + 26) mod 26
    """
    key = key.upper().replace(" ", "")
    ciphertext = ciphertext.upper()

    plaintext = ""
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            C = ord(char) - ord('A')
            K = ord(key[key_index % len(key)]) - ord('A')
            P = (C - K + 26) % 26             # +26 to avoid negative numbers
            plaintext += chr(P + ord('A'))
            key_index += 1
        else:
            plaintext += char

    return plaintext


def encrypt_file(input_path, output_path, key):
    """
    Encrypt a text file using Vigenere cipher
    """
    with open(input_path, 'r') as f:
        content = f.read()
    
    encrypted = vigenere_encrypt(content, key)

    with open(output_path, 'w') as f:
        f.write(encrypted)

    print(f"File encrypted: {output_path}")


def decrypt_file(input_path, output_path, key):
    """
    Decrypt a text file using Vigenere cipher
    """
    with open(input_path, 'r') as f:
        content = f.read()

    decrypted = vigenere_decrypt(content, key)

    with open(output_path, 'w') as f:
        f.write(decrypted)

    print(f"File decrypted: {output_path}")


def show_steps(plaintext, key):
    """
    Show step-by-step encryption for verification (handwritten example helper)
    """
    key = key.upper().replace(" ", "")
    plaintext = plaintext.upper()

    print(f"\n{'='*55}")
    print(f"  Vigenere Encryption Steps")
    print(f"  Plaintext : {plaintext}")
    print(f"  Key       : {key}")
    print(f"{'='*55}")
    print(f"{'Char':<6} {'Key':<6} {'P':<5} {'K':<5} {'(P+K)%26':<12} {'Cipher'}")
    print(f"{'-'*55}")

    key_index = 0
    result = ""

    for char in plaintext:
        if char.isalpha():
            P = ord(char) - ord('A')
            K = ord(key[key_index % len(key)]) - ord('A')
            C = (P + K) % 26
            cipher_char = chr(C + ord('A'))
            print(f"{char:<6} {key[key_index % len(key)]:<6} {P:<5} {K:<5} {C:<12} {cipher_char}")
            result += cipher_char
            key_index += 1
        else:
            print(f"{char:<6} {'-':<6} {'-':<5} {'-':<5} {'-':<12} {char}")
            result += char

    print(f"{'='*55}")
    print(f"  Result: {result}")
    print(f"{'='*55}\n")
    return result


# ── Performance Analysis ──────────────────────────────────────
import time
import sys

def performance_analysis(text, key):
    """
    Measure runtime and ciphertext size
    """
    print(f"\n--- Performance Analysis ---")
    print(f"Input size     : {len(text)} characters ({sys.getsizeof(text)} bytes)")

    start = time.perf_counter()
    encrypted = vigenere_encrypt(text, key)
    end = time.perf_counter()

    runtime_ms = (end - start) * 1000
    print(f"Runtime        : {runtime_ms:.4f} ms")
    print(f"Ciphertext size: {sys.getsizeof(encrypted)} bytes")
    print(f"Size overhead  : {sys.getsizeof(encrypted) - sys.getsizeof(text)} bytes")
    print(f"----------------------------\n")


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":

    # --- Basic test ---
    key = "KEY"
    message = "HELLO WORLD"

    print(">>> Basic Test")
    encrypted = vigenere_encrypt(message, key)
    decrypted = vigenere_decrypt(encrypted, key)
    print(f"Original : {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match    : {message.replace(' ','') == decrypted.replace(' ','')}")

    # --- Step by step (for handwritten verification) ---
    show_steps("HELLO", "KEY")

    # --- Performance ---
    long_text = "HELLO WORLD " * 500
    performance_analysis(long_text, key)

    # --- File encryption example ---
    # encrypt_file("document.txt", "document_encrypted.txt", key)
    # decrypt_file("document_encrypted.txt", "document_decrypted.txt", key)
