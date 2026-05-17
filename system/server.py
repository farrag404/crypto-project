import time

from asymmetric.ntru import NTRU
from asymmetric.kem  import NTRUKEM
from symmetric.hill  import hill_decrypt
from symmetric.vigenere import vigenere_encrypt, vigenere_decrypt

# Storage-at-rest master key (Vigenere)
_STORAGE_KEY = "SECUREMSG"

# Hill cipher key matrix
HILL_KEY = [[3, 3], [2, 5]]


def _session_key_to_vigenere(shared_bytes: bytes) -> str:
    return "".join(chr(b % 26 + ord('A')) for b in shared_bytes[:10])


def _timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# Server

class Server:
    def __init__(self, ca):

        self._ca = ca

        # NTRU instance for key exchange
        self._ntru       = NTRU(N=17, q=127, p=3)
        self._public_key = self._ntru.keygen()
        self._kem        = NTRUKEM(self._ntru)

        # Get a certificate from the CA
        self._certificate = ca.issue_certificate("server", self._public_key)

        # Active sessions  { session_id: { shared_key, hill_key_str, created_at } }
        self._sessions: dict[str, dict] = {}

        # Message inbox stored encrypted at rest
        # List of dicts { from, encrypted_storage, timestamp }
        self._inbox: list[dict] = []

        print("[SERVER] Server online.")
        print(f"[SERVER] Certificate serial: {self._certificate['serial']}")

    # Certificate

    @property
    def certificate(self) -> dict:
        return self._certificate

    @property
    def public_key(self) -> list:
        return self._public_key

    # Key Exchange

    def complete_key_exchange(self, kem_ciphertext: list, session_id: str) -> bool:
        shared_bytes = self._kem.decapsulate(kem_ciphertext)
        hill_key_str = _session_key_to_vigenere(shared_bytes)   # reused as Hill key label

        self._sessions[session_id] = {
            "shared_bytes" : shared_bytes,
            "hill_key_str" : hill_key_str,
            "created_at"   : time.time(),
        }

        print(f"[SERVER] Key exchange complete for session '{session_id}'.")
        print(f"[SERVER] Shared secret (first 6 bytes): {shared_bytes[:6].hex()} ...")
        return True

    def rotate_session_key(self, session_id: str, new_kem_ciphertext: list):
        if session_id not in self._sessions:
            print(f"[SERVER] Unknown session '{session_id}' — cannot rotate.")
            return
        shared_bytes = self._kem.decapsulate(new_kem_ciphertext)
        hill_key_str = _session_key_to_vigenere(shared_bytes)
        self._sessions[session_id]["shared_bytes"] = shared_bytes
        self._sessions[session_id]["hill_key_str"] = hill_key_str
        self._sessions[session_id]["rotated_at"]   = time.time()
        print(f"[SERVER] Session key rotated for session '{session_id}'.")

    # Receive Message

    def receive_message(self, sender: str, session_id: str, hill_ciphertext: str):
        print(f"\n[SERVER] Message received from '{sender}' (session '{session_id}')")

        # Lookup session
        if session_id not in self._sessions:
            print("[SERVER] No active session — message rejected.")
            return

        session = self._sessions[session_id]

        # Decrypt Hill ciphertext 
        plaintext = hill_decrypt(hill_ciphertext, HILL_KEY)
        print(f"[SERVER] Decrypted message : {plaintext}")

        # Encrypt at rest (Vigenere with storage key)
        encrypted_storage = vigenere_encrypt(plaintext, _STORAGE_KEY)
        record = {
            "from"              : sender,
            "session_id"        : session_id,
            "encrypted_storage" : encrypted_storage,
            "timestamp"         : _timestamp(),
        }
        self._inbox.append(record)

        # Append to database file 
        with open("system/database.txt", "a") as f:
            f.write(
                f"{record['timestamp']} | from={sender} | "
                f"session={session_id} | msg={encrypted_storage}\n"
            )

        print(f"[SERVER] Message stored (encrypted at rest): {encrypted_storage}")

    def read_inbox(self):
        """Decrypt and display all stored messages (server-side admin view)."""
        print(f"\n[SERVER] ── INBOX ({len(self._inbox)} message(s)) ──")
        for i, record in enumerate(self._inbox, 1):
            decrypted = vigenere_decrypt(record["encrypted_storage"], _STORAGE_KEY)
            print(f"  [{i}] {record['timestamp']}  from={record['from']}")
            print(f"       Stored (enc) : {record['encrypted_storage']}")
            print(f"       Plaintext    : {decrypted}")
        print("[SERVER] ── END INBOX ──\n")