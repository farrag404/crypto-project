import time
import uuid

from asymmetric.ntru import NTRU
from asymmetric.kem  import NTRUKEM
from symmetric.hill  import hill_encrypt

# Hill key matrix — must match server (shared out-of-band in this demo)
HILL_KEY = [[3, 3], [2, 5]]


def _session_key_to_vigenere(shared_bytes: bytes) -> str:
    """Derive a Vigenere-compatible key from shared secret (mirrors server logic)."""
    return "".join(chr(b % 26 + ord('A')) for b in shared_bytes[:10])


# Client

class Client:
    def __init__(self, username: str, ca):
        self.username = username
        self._ca      = ca

        # Client's own NTRU key pair (can be used for receiving encrypted msgs)
        self._ntru       = NTRU(N=17, q=127, p=3)
        self._public_key = self._ntru.keygen()

        # Register with CA
        self._certificate = ca.issue_certificate(
            f"client_{username}", self._public_key
        )

        # Session state (filled after connect())
        self._session_id   : str | None   = None
        self._shared_bytes : bytes | None = None
        self._kem_ctx      : NTRUKEM | None = None
        self._server       = None          # reference to Server object

        print(f"[CLIENT:{username}] Registered. Certificate serial: {self._certificate['serial']}")

    # Certificate 

    @property
    def certificate(self) -> dict:
        return self._certificate

    # Connect to Server

    def connect(self, server) -> bool:
        print(f"\n[CLIENT:{self.username}] Connecting to server ...")

        # Step 1 & 2 : Verify server certificate 
        server_cert = server.certificate
        print(f"[CLIENT:{self.username}] Verifying server certificate (serial={server_cert['serial']}) ...")

        if not self._ca.verify_certificate(server_cert):
            print(f"[CLIENT:{self.username}] Server certificate INVALID — connection aborted.")
            return False

        print(f"[CLIENT:{self.username}] Server certificate verified.")

        # Step 3 : KEM encapsulation using server's public key 
        # Build a temporary NTRU+KEM using the SERVER's public key
        temp_ntru = NTRU(N=17, q=127, p=3)
        temp_ntru.keygen()                          # gives temp_ntru its own f, f_p_inv
        temp_kem  = NTRUKEM(temp_ntru)

        kem_ciphertext, shared_bytes = temp_kem.encapsulate(server_cert["public_key"])
        self._shared_bytes = shared_bytes
        self._kem_ctx      = temp_kem

        # Step 4 : Agree on session ID 
        self._session_id = str(uuid.uuid4())[:8]    # short 8-char ID for readability
        self._server     = server

        # Step 5 : Send KEM ciphertext to server 
        server.complete_key_exchange(kem_ciphertext, self._session_id)

        print(f"[CLIENT:{self.username}] Session established. ID='{self._session_id}'")
        print(f"[CLIENT:{self.username}] Shared secret (first 6 bytes): {shared_bytes[:6].hex()} ...")
        return True

    # Send Message

    def send(self, message: str):
        if self._session_id is None or self._server is None:
            print(f"[CLIENT:{self.username}] Not connected. Call connect() first.")
            return

        print(f"\n[CLIENT:{self.username}] Sending: '{message}'")

        # Encrypt with Hill cipher (in transit)
        hill_ciphertext = hill_encrypt(message, HILL_KEY)
        print(f"[CLIENT:{self.username}] Hill-encrypted (transit): {hill_ciphertext}")

        # Deliver to server
        self._server.receive_message(
            sender         = self.username,
            session_id     = self._session_id,
            hill_ciphertext= hill_ciphertext,
        )

    # Key Rotation

    def rotate_session_key(self):
        if self._session_id is None or self._server is None:
            print(f"[CLIENT:{self.username}] Not connected.")
            return

        print(f"\n[CLIENT:{self.username}] Rotating session key ...")

        # Encapsulate a fresh secret using the server's public key
        temp_ntru = NTRU(N=17, q=127, p=3)
        temp_ntru.keygen()
        temp_kem  = NTRUKEM(temp_ntru)

        new_ciphertext, new_shared = temp_kem.encapsulate(
            self._server.certificate["public_key"]
        )
        self._shared_bytes = new_shared

        # Notify server
        self._server.rotate_session_key(self._session_id, new_ciphertext)

        print(f"[CLIENT:{self.username}] Session key rotated.")
        print(f"[CLIENT:{self.username}] New shared secret (first 6 bytes): {new_shared[:6].hex()} ...")