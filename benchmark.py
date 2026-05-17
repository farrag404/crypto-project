"""
Performance analysis for all cryptographic systems
Includes: NTRU KEM (asymmetric), Vigenere and Hill (symmetric)
"""

import time
import sys
import string
import random

from asymmetric.ntru import NTRU
from asymmetric.kem import NTRUKEM
from symmetric.vigenere import vigenere_encrypt, vigenere_decrypt
from symmetric.hill import hill_encrypt, hill_decrypt


def benchmark_ntru(iterations=100):

    print("=" * 60)
    print("NTRU KEM PERFORMANCE ANALYSIS")
    print("=" * 60)

    keygen_times = []
    encrypt_times = []
    decrypt_times = []
    encaps_times = []
    decaps_times = []

    total_public_key_size = 0
    total_ciphertext_size = 0

    for _ in range(iterations):

        ntru = NTRU(
            N=17,
            q=127,
            p=3
        )

        #
        # KEY GENERATION
        #
        start = time.perf_counter()

        public_key = ntru.keygen()

        end = time.perf_counter()

        keygen_times.append(end - start)

        #
        # KEM INIT
        #
        kem = NTRUKEM(ntru)

        #
        # ENCAPSULATION
        #
        start = time.perf_counter()

        ciphertext, client_key = kem.encapsulate(public_key)

        end = time.perf_counter()

        encaps_times.append(end - start)

        #
        # DECAPSULATION
        #
        start = time.perf_counter()

        server_key = kem.decapsulate(ciphertext)

        end = time.perf_counter()

        decaps_times.append(end - start)

        #
        # RAW ENCRYPTION BENCH
        #
        message = ntru.random_message_poly()

        start = time.perf_counter()

        cipher = ntru.encrypt(message, public_key)

        end = time.perf_counter()

        encrypt_times.append(end - start)

        #
        # RAW DECRYPTION BENCH
        #
        start = time.perf_counter()

        recovered = ntru.decrypt(cipher)

        end = time.perf_counter()

        decrypt_times.append(end - start)

        #
        # VERIFY CORRECTNESS
        #
        if client_key != server_key:
            print("ERROR: Shared keys do not match")
            return

        #
        # COMMUNICATION COSTS
        #
        total_public_key_size += sys.getsizeof(public_key)
        total_ciphertext_size += sys.getsizeof(ciphertext)

    #
    # AVERAGES
    #
    avg_keygen = sum(keygen_times) / iterations
    avg_encrypt = sum(encrypt_times) / iterations
    avg_decrypt = sum(decrypt_times) / iterations
    avg_encaps = sum(encaps_times) / iterations
    avg_decaps = sum(decaps_times) / iterations

    avg_pk_size = total_public_key_size / iterations
    avg_ct_size = total_ciphertext_size / iterations

    #
    # RESULTS
    #
    print("\nCOMPUTATION COSTS")
    print("-" * 60)

    print(f"Average KeyGen Time      : {avg_keygen*1000:.4f} ms")
    print(f"Average Encrypt Time     : {avg_encrypt*1000:.4f} ms")
    print(f"Average Decrypt Time     : {avg_decrypt*1000:.4f} ms")
    print(f"Average Encaps Time      : {avg_encaps*1000:.4f} ms")
    print(f"Average Decaps Time      : {avg_decaps*1000:.4f} ms")

    print("\nCOMMUNICATION COSTS")
    print("-" * 60)

    print(f"Average Public Key Size  : {avg_pk_size:.2f} bytes")
    print(f"Average Ciphertext Size  : {avg_ct_size:.2f} bytes")
    print(f"Shared Secret Size       : 32 bytes")

    print("\nVERIFICATION")
    print("-" * 60)

    print("All encapsulation/decapsulation tests passed.")
    print("Shared keys matched successfully.")

    print("=" * 60)


def benchmark_vigenere(text_sizes=[100, 500, 1000, 5000], iterations=100):
    """
    Benchmark Vigenere cipher across different text sizes
    """
    print("\n" + "=" * 60)
    print("VIGENERE CIPHER PERFORMANCE ANALYSIS")
    print("=" * 60)

    key = "SECRETKEY"

    for size in text_sizes:
        # Generate random plaintext
        plaintext = ''.join(random.choices(string.ascii_uppercase, k=size))

        encrypt_times = []
        decrypt_times = []
        total_plaintext_size = 0
        total_ciphertext_size = 0

        for _ in range(iterations):
            #
            # ENCRYPTION
            #
            start = time.perf_counter()

            ciphertext = vigenere_encrypt(plaintext, key)

            end = time.perf_counter()

            encrypt_times.append(end - start)

            #
            # DECRYPTION
            #
            start = time.perf_counter()

            recovered = vigenere_decrypt(ciphertext, key)

            end = time.perf_counter()

            decrypt_times.append(end - start)

            #
            # VERIFY CORRECTNESS
            #
            if plaintext != recovered:
                print(f"ERROR: Plaintext mismatch for size {size}")
                return

            #
            # COMMUNICATION COSTS
            #
            total_plaintext_size += sys.getsizeof(plaintext)
            total_ciphertext_size += sys.getsizeof(ciphertext)

        #
        # AVERAGES
        #
        avg_encrypt = sum(encrypt_times) / iterations
        avg_decrypt = sum(decrypt_times) / iterations
        avg_plaintext_size = total_plaintext_size / iterations
        avg_ciphertext_size = total_ciphertext_size / iterations
        throughput_encrypt = (size / 1024) / avg_encrypt if avg_encrypt > 0 else 0
        throughput_decrypt = (size / 1024) / avg_decrypt if avg_decrypt > 0 else 0

        #
        # RESULTS
        #
        print(f"\nText Size: {size} characters")
        print("-" * 60)
        print(f"Average Encrypt Time     : {avg_encrypt*1000:.4f} ms")
        print(f"Average Decrypt Time     : {avg_decrypt*1000:.4f} ms")
        print(f"Encrypt Throughput       : {throughput_encrypt:.2f} KB/s")
        print(f"Decrypt Throughput       : {throughput_decrypt:.2f} KB/s")
        print(f"Plaintext Size           : {avg_plaintext_size:.2f} bytes")
        print(f"Ciphertext Size          : {avg_ciphertext_size:.2f} bytes")

    print("\nVERIFICATION")
    print("-" * 60)
    print("All encryption/decryption tests passed.")
    print("Plaintexts recovered successfully.")
    print("=" * 60)


def benchmark_hill(text_sizes=[10, 50, 100, 500], iterations=100):
    """
    Benchmark Hill cipher across different text sizes
    """
    print("\n" + "=" * 60)
    print("HILL CIPHER PERFORMANCE ANALYSIS")
    print("=" * 60)

    # Hill cipher key matrix (2x2)
    key_matrix = [[3, 3], [2, 5]]

    for size in text_sizes:
        # Generate random plaintext (must be even length for 2x2 matrix)
        plaintext = ''.join(random.choices(string.ascii_uppercase, k=size))

        encrypt_times = []
        decrypt_times = []
        total_plaintext_size = 0
        total_ciphertext_size = 0

        for _ in range(iterations):
            #
            # ENCRYPTION
            #
            start = time.perf_counter()

            ciphertext = hill_encrypt(plaintext, key_matrix)

            end = time.perf_counter()

            encrypt_times.append(end - start)

            #
            # DECRYPTION
            #
            start = time.perf_counter()

            recovered = hill_decrypt(ciphertext, key_matrix)

            end = time.perf_counter()

            decrypt_times.append(end - start)

            #
            # VERIFY CORRECTNESS
            #
            # Hill cipher pads with 'X', so we compare without padding
            if plaintext.rstrip('X') != recovered.rstrip('X'):
                print(f"ERROR: Plaintext mismatch for size {size}")
                return

            #
            # COMMUNICATION COSTS
            #
            total_plaintext_size += sys.getsizeof(plaintext)
            total_ciphertext_size += sys.getsizeof(ciphertext)

        #
        # AVERAGES
        #
        avg_encrypt = sum(encrypt_times) / iterations
        avg_decrypt = sum(decrypt_times) / iterations
        avg_plaintext_size = total_plaintext_size / iterations
        avg_ciphertext_size = total_ciphertext_size / iterations
        throughput_encrypt = (size / 1024) / avg_encrypt if avg_encrypt > 0 else 0
        throughput_decrypt = (size / 1024) / avg_decrypt if avg_decrypt > 0 else 0

        #
        # RESULTS
        #
        print(f"\nText Size: {size} characters")
        print("-" * 60)
        print(f"Average Encrypt Time     : {avg_encrypt*1000:.4f} ms")
        print(f"Average Decrypt Time     : {avg_decrypt*1000:.4f} ms")
        print(f"Encrypt Throughput       : {throughput_encrypt:.2f} KB/s")
        print(f"Decrypt Throughput       : {throughput_decrypt:.2f} KB/s")
        print(f"Plaintext Size           : {avg_plaintext_size:.2f} bytes")
        print(f"Ciphertext Size          : {avg_ciphertext_size:.2f} bytes")

    print("\nVERIFICATION")
    print("-" * 60)
    print("All encryption/decryption tests passed.")
    print("Plaintexts recovered successfully.")
    print("=" * 60)


def benchmark_comparison():
    """
    Compare all cryptographic systems on a standard 100-byte message
    """
    print("\n" + "=" * 60)
    print("COMPREHENSIVE CIPHER COMPARISON (100-byte message, 50 iterations)")
    print("=" * 60)

    message = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3  # ~100 chars
    key = "SECRETKEY"
    hill_key = [[3, 3], [2, 5]]

    #
    # VIGENERE
    #
    vig_encrypt_times = []
    vig_decrypt_times = []

    for _ in range(50):
        start = time.perf_counter()
        vig_cipher = vigenere_encrypt(message, key)
        vig_encrypt_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        vigenere_decrypt(vig_cipher, key)
        vig_decrypt_times.append(time.perf_counter() - start)

    #
    # HILL
    #
    hill_encrypt_times = []
    hill_decrypt_times = []

    for _ in range(50):
        start = time.perf_counter()
        hill_cipher = hill_encrypt(message, hill_key)
        hill_encrypt_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        hill_decrypt(hill_cipher, hill_key)
        hill_decrypt_times.append(time.perf_counter() - start)

    #
    # NTRU
    #
    ntru = NTRU(N=17, q=127, p=3)
    ntru_pub_key = ntru.keygen()
    ntru_msg = ntru.random_message_poly()

    ntru_encrypt_times = []
    ntru_decrypt_times = []

    for _ in range(50):
        start = time.perf_counter()
        ntru_cipher = ntru.encrypt(ntru_msg, ntru_pub_key)
        ntru_encrypt_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        ntru.decrypt(ntru_cipher)
        ntru_decrypt_times.append(time.perf_counter() - start)

    #
    # COMPARISON TABLE
    #
    print("\n" + "-" * 60)
    print(f"{'Algorithm':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Type'}")
    print("-" * 60)

    avg_vig_enc = (sum(vig_encrypt_times) / len(vig_encrypt_times)) * 1000
    avg_vig_dec = (sum(vig_decrypt_times) / len(vig_decrypt_times)) * 1000
    print(f"{'Vigenere':<15} {avg_vig_enc:<15.4f} {avg_vig_dec:<15.4f} {'Symmetric'}")

    avg_hill_enc = (sum(hill_encrypt_times) / len(hill_encrypt_times)) * 1000
    avg_hill_dec = (sum(hill_decrypt_times) / len(hill_decrypt_times)) * 1000
    print(f"{'Hill':<15} {avg_hill_enc:<15.4f} {avg_hill_dec:<15.4f} {'Symmetric'}")

    avg_ntru_enc = (sum(ntru_encrypt_times) / len(ntru_encrypt_times)) * 1000
    avg_ntru_dec = (sum(ntru_decrypt_times) / len(ntru_decrypt_times)) * 1000
    print(f"{'NTRU':<15} {avg_ntru_enc:<15.4f} {avg_ntru_dec:<15.4f} {'Asymmetric'}")

    print("-" * 60)
    print(f"\nFastest Encrypt: {min([('Vigenere', avg_vig_enc), ('Hill', avg_hill_enc), ('NTRU', avg_ntru_enc)], key=lambda x: x[1])[0]}")
    print(f"Fastest Decrypt: {min([('Vigenere', avg_vig_dec), ('Hill', avg_hill_dec), ('NTRU', avg_ntru_dec)], key=lambda x: x[1])[0]}")
    print("=" * 60)


if __name__ == "__main__":
    import sys

    print("\n" + "=" * 60)
    print("CRYPTOGRAPHY PROJECT - FULL BENCHMARK SUITE")
    print("=" * 60)

    # Run all benchmarks
    benchmark_ntru(iterations=100)
    benchmark_vigenere(text_sizes=[100, 500, 1000], iterations=100)
    benchmark_hill(text_sizes=[10, 50, 100], iterations=100)
    benchmark_comparison()

    print("\n" + "=" * 60)
    print("ALL BENCHMARKS COMPLETED")
    print("=" * 60)