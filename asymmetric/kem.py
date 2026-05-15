"""
Module: kem.py
NTRU Key Encapsulation Mechanism
"""

from .kdf import derive_key


class NTRUKEM:

    def __init__(self, ntru_instance):

        self.ntru = ntru_instance

    def encapsulate(self, public_key):

        session_seed = self.ntru.random_message_poly()

        ciphertext = self.ntru.encrypt(
            session_seed,
            public_key
        )

        shared_key = derive_key(session_seed)

        return ciphertext, shared_key

    def decapsulate(self, ciphertext):

        recovered_seed = self.ntru.decrypt(ciphertext)

        shared_key = derive_key(recovered_seed)

        return shared_key