"""
====================================================
  Performance Benchmark
  Vigenere vs Hill Cipher
====================================================
"""

import time
import sys
import os

# import both ciphers
from vigenere import vigenere_encrypt, vigenere_decrypt
from hill import hill_encrypt, hill_decrypt


# ── Test Data ─────────────────────────────────────────────────

# different text sizes to test performance at scale
TEXT_SIZES = [100, 500, 1000, 5000, 10000]
BASE_TEXT  = "HELLOWORLD" * 2000   # big enough to slice from

# keys
VIG_KEY    = "SECRETKEY"
HILL_KEY   = [[3, 3], [2, 5]]


# ── Benchmark Function ────────────────────────────────────────

def benchmark(name, encrypt_fn, decrypt_fn, text, key, runs=5):
    """
    Run encrypt + decrypt multiple times and return average times.
    We run multiple times to get a stable average (avoid CPU spikes).

    Returns:
        enc_ms  : average encrypt time in milliseconds
        dec_ms  : average decrypt time in milliseconds
        in_size : input size in bytes
        out_size: ciphertext size in bytes
    """
    enc_times = []
    dec_times = []

    for _ in range(runs):
        # measure encryption time
        start = time.perf_counter()
        cipher = encrypt_fn(text, key)
        enc_times.append(time.perf_counter() - start)

        # measure decryption time
        start = time.perf_counter()
        decrypt_fn(cipher, key)
        dec_times.append(time.perf_counter() - start)

    # average over all runs → convert to milliseconds
    enc_ms = (sum(enc_times) / runs) * 1000
    dec_ms = (sum(dec_times) / runs) * 1000

    in_size  = sys.getsizeof(text)
    out_size = sys.getsizeof(cipher)

    return enc_ms, dec_ms, in_size, out_size


# ── Print Results ─────────────────────────────────────────────

def run_benchmark():
    print(f"\n{'='*75}")
    print(f"  Benchmark: Vigenere vs Hill Cipher")
    print(f"  Each test averaged over 5 runs")
    print(f"{'='*75}")

    # table header
    print(f"\n{'Size':<8} {'Cipher':<12} {'Encrypt(ms)':<14} {'Decrypt(ms)':<14} {'Input(B)':<12} {'Output(B)'}")
    print(f"{'-'*75}")

    for size in TEXT_SIZES:
        text = BASE_TEXT[:size]

        # --- Vigenere ---
        enc_v, dec_v, in_v, out_v = benchmark(
            "Vigenere",
            vigenere_encrypt,
            vigenere_decrypt,
            text,
            VIG_KEY
        )

        # --- Hill ---
        enc_h, dec_h, in_h, out_h = benchmark(
            "Hill",
            hill_encrypt,
            hill_decrypt,
            text,
            HILL_KEY
        )

        # print both rows for this size
        print(f"{size:<8} {'Vigenere':<12} {enc_v:<14.4f} {dec_v:<14.4f} {in_v:<12} {out_v}")
        print(f"{size:<8} {'Hill':<12} {enc_h:<14.4f} {dec_h:<14.4f} {in_h:<12} {out_h}")
        print(f"{'-'*75}")

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{'='*75}")
    print(f"  Summary — Full text (10,000 chars)")
    print(f"{'='*75}")

    text = BASE_TEXT[:10000]

    enc_v, dec_v, in_v, out_v = benchmark("Vigenere", vigenere_encrypt, vigenere_decrypt, text, VIG_KEY)
    enc_h, dec_h, in_h, out_h = benchmark("Hill",     hill_encrypt,     hill_decrypt,     text, HILL_KEY)

    print(f"\n  Vigenere:")
    print(f"    Encrypt time : {enc_v:.4f} ms")
    print(f"    Decrypt time : {dec_v:.4f} ms")
    print(f"    Ciphertext   : {out_v} bytes  (overhead: {out_v - in_v} bytes)")

    print(f"\n  Hill:")
    print(f"    Encrypt time : {enc_h:.4f} ms")
    print(f"    Decrypt time : {dec_h:.4f} ms")
    print(f"    Ciphertext   : {out_h} bytes  (overhead: {out_h - in_h} bytes)")

    print(f"\n  Faster cipher    : {'Vigenere' if enc_v < enc_h else 'Hill'}")
    print(f"  Smaller output   : {'Vigenere' if out_v < out_h else 'Hill' if out_h < out_v else 'Same'}")
    print(f"{'='*75}\n")

    # ── Security Comparison ───────────────────────────────────
    print(f"{'='*75}")
    print(f"  Security Comparison")
    print(f"{'='*75}")
    print(f"  {'Property':<30} {'Vigenere':<20} {'Hill'}")
    print(f"  {'-'*65}")
    props = [
        ("Type",                  "Stream cipher",     "Block cipher"),
        ("Key type",              "Text keyword",      "Matrix NxN"),
        ("Block size",            "1 char",            "N chars (N=matrix size)"),
        ("Vulnerable to",         "Kasiski attack",    "Known plaintext attack"),
        ("Math used",             "Addition mod 26",   "Matrix multiplication"),
        ("Key space",             "26^len(key)",       "All invertible NxN matrices"),
    ]
    for prop, v, h in props:
        print(f"  {prop:<30} {v:<20} {h}")
    print(f"{'='*75}\n")


# ── Main ──────────────────────────────────────────────────────

if __name__ == "__main__":
    run_benchmark()
