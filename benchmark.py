"""
Performance analysis for NTRU KEM
"""

import time
import sys

from asymmetric.ntru import NTRU
from asymmetric.kem import NTRUKEM


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


if __name__ == "__main__":
    benchmark_ntru(iterations=100)