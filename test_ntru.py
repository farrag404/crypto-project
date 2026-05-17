from asymmetric.ntru import NTRU
from asymmetric.kem import NTRUKEM

ntru = NTRU(
    N=17,
    q=127,
    p=3
)

public_key = ntru.keygen()

kem = NTRUKEM(ntru)

ciphertext, client_key = kem.encapsulate(public_key)

server_key = kem.decapsulate(ciphertext)

print("CLIENT KEY:", client_key.hex())
print("SERVER KEY:", server_key.hex())

print("\nMATCH:", client_key == server_key)


def test_encrypt_decrypt():
    """Test basic encryption and decryption of messages"""
    print("\n--- Testing Encrypt/Decrypt ---")
    
    # Create a new NTRU instance
    ntru_test = NTRU(N=17, q=127, p=3)
    pub_key = ntru_test.keygen()
    
    # Create a test message
    message = ntru_test.random_message_poly()
    print(f"Original message: {message}")
    
    # Encrypt the message
    cipher = ntru_test.encrypt(message, pub_key)
    print(f"Encrypted: {cipher}")
    
    # Decrypt the message
    decrypted = ntru_test.decrypt(cipher)
    print(f"Decrypted: {decrypted}")
    
    # Check if decryption matches original
    match = message == decrypted
    print(f"MATCH: {match}")
    
    return match


def test_multiple_encrypt_decrypt():
    """Test multiple encrypt/decrypt cycles"""
    print("\n--- Testing Multiple Encrypt/Decrypt Cycles ---")
    
    ntru_test = NTRU(N=17, q=127, p=3)
    pub_key = ntru_test.keygen()
    
    all_match = True
    for i in range(3):
        message = ntru_test.random_message_poly()
        cipher = ntru_test.encrypt(message, pub_key)
        decrypted = ntru_test.decrypt(cipher)
        match = message == decrypted
        print(f"Test {i+1}: {match}")
        all_match = all_match and match
    
    print(f"All tests passed: {all_match}")
    return all_match


# Run the encryption/decryption tests
test_encrypt_decrypt()
test_multiple_encrypt_decrypt()