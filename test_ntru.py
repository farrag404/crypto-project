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