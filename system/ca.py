"""
Module: ca.py
Certificate Authority (CA) — Secure Messaging System

Responsibilities:
  - Generate CA key pair (NTRU)
  - Issue signed certificates for clients and servers
  - Verify certificate authenticity
  - Revoke certificates (CRL)
  - Rotate CA keys periodically

Certificate structure (dict):
  {
    "subject"    : "server" | "client_<name>",
    "public_key" : [...],          # NTRU public key polynomial
    "issued_at"  : <timestamp>,
    "expires_at" : <timestamp>,
    "serial"     : <int>,
    "signature"  : <int>           # simple hash signed by CA
  }
"""

import time
import hashlib
import json

from asymmetric.ntru import NTRU


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hash_certificate_fields(subject: str, public_key: list, issued_at: float, expires_at: float, serial: int) -> int:
    """
    Produce a deterministic integer hash of the core certificate fields.
    Used as the 'message' the CA signs.
    """
    raw = json.dumps({
        "subject"   : subject,
        "public_key": public_key,
        "issued_at" : issued_at,
        "expires_at": expires_at,
        "serial"    : serial,
    }, sort_keys=True).encode()
    digest = hashlib.sha256(raw).hexdigest()
    return int(digest, 16)                          # big integer — treated as signature


def _sign(field_hash: int, ca_secret: int) -> int:
    """
    Simulate signing: XOR the field hash with a CA secret integer.
    (In a real PKI this would be RSA/ECDSA; here we stay library-free.)
    """
    return field_hash ^ ca_secret


def _verify_sig(field_hash: int, signature: int, ca_secret: int) -> bool:
    """Verify: recompute expected signature and compare."""
    return _sign(field_hash, ca_secret) == signature


# ── Certificate Authority ──────────────────────────────────────────────────────

class CertificateAuthority:
    """
    Simulated Certificate Authority for the Secure Messaging System.

    Lifecycle
    ---------
    1. CA is initialised and generates its own NTRU key pair.
    2. Server requests a certificate → CA issues and signs it.
    3. Clients request certificates → CA issues and signs them.
    4. Any party can call `verify_certificate()` to validate a cert.
    5. Revoked certs go onto the CRL; verification checks the CRL.
    6. `rotate_keys()` replaces the CA key pair and re-issues live certs.
    """

    CERT_VALIDITY_SECONDS = 3600        # 1 hour for demo purposes

    def __init__(self):
        # CA's own NTRU instance (used only to demonstrate CA has a key pair)
        self._ntru          = NTRU(N=17, q=127, p=3)
        self._ca_public_key = self._ntru.keygen()

        # Secret integer derived from CA private key — used for signing
        self._ca_secret     = self._derive_secret()

        # Certificate store  { serial: cert_dict }
        self._issued_certs: dict[int, dict] = {}

        # Certificate Revocation List  { serial }
        self._crl: set[int] = set()

        # Serial counter
        self._serial_counter = 1

        print("[CA] Certificate Authority initialised.")
        print(f"[CA] CA public key (first 5 coeffs): {self._ca_public_key[:5]} ...")

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _derive_secret(self) -> int:
        """Derive a stable integer secret from the CA's private polynomial."""
        raw = hashlib.sha256(
            "|".join(map(str, self._ntru.f)).encode()
        ).hexdigest()
        return int(raw, 16)

    def _next_serial(self) -> int:
        serial = self._serial_counter
        self._serial_counter += 1
        return serial

    # ── Public API ─────────────────────────────────────────────────────────────

    def issue_certificate(self, subject: str, public_key: list) -> dict:
        """
        Issue a signed certificate for *subject* with *public_key*.

        Parameters
        ----------
        subject    : human-readable name, e.g. "server" or "client_alice"
        public_key : NTRU public key polynomial (list of ints)

        Returns
        -------
        cert : dict  (see module docstring for structure)
        """
        now        = time.time()
        expires    = now + self.CERT_VALIDITY_SECONDS
        serial     = self._next_serial()

        field_hash = _hash_certificate_fields(subject, public_key, now, expires, serial)
        signature  = _sign(field_hash, self._ca_secret)

        cert = {
            "subject"   : subject,
            "public_key": public_key,
            "issued_at" : now,
            "expires_at": expires,
            "serial"    : serial,
            "signature" : signature,
        }

        self._issued_certs[serial] = cert

        print(f"[CA] Certificate issued → subject='{subject}'  serial={serial}")
        return cert

    def verify_certificate(self, cert: dict) -> bool:
        """
        Verify a certificate:
          1. Signature matches (CA really signed it)
          2. Not expired
          3. Not on the CRL

        Returns True only when ALL checks pass.
        """
        serial = cert.get("serial")

        # ── CRL check ──────────────────────────────────────────────────────────
        if serial in self._crl:
            print(f"[CA] ✗ Certificate serial={serial} is REVOKED.")
            return False

        # ── Expiry check ───────────────────────────────────────────────────────
        if time.time() > cert["expires_at"]:
            print(f"[CA] ✗ Certificate serial={serial} has EXPIRED.")
            return False

        # ── Signature check ────────────────────────────────────────────────────
        field_hash = _hash_certificate_fields(
            cert["subject"],
            cert["public_key"],
            cert["issued_at"],
            cert["expires_at"],
            cert["serial"],
        )
        if not _verify_sig(field_hash, cert["signature"], self._ca_secret):
            print(f"[CA] ✗ Certificate serial={serial} has INVALID signature.")
            return False

        print(f"[CA] ✓ Certificate serial={serial} subject='{cert['subject']}' is VALID.")
        return True

    def revoke_certificate(self, serial: int):
        """Add a certificate serial to the CRL."""
        self._crl.add(serial)
        print(f"[CA] Certificate serial={serial} has been REVOKED and added to CRL.")

    def rotate_keys(self):
        """
        Key rotation:
          1. Generate a new NTRU key pair for the CA.
          2. Derive a new signing secret.
          3. Re-issue all currently valid (non-revoked, non-expired) certificates
             so existing parties don't lose access.
        """
        print("\n[CA] ── KEY ROTATION STARTED ──")

        # New key pair
        self._ntru          = NTRU(N=17, q=127, p=3)
        self._ca_public_key = self._ntru.keygen()
        self._ca_secret     = self._derive_secret()

        print("[CA] New CA key pair generated.")

        # Re-issue valid certs
        reissued = 0
        now      = time.time()
        for serial, cert in list(self._issued_certs.items()):
            if serial not in self._crl and cert["expires_at"] > now:
                new_cert = self.issue_certificate(cert["subject"], cert["public_key"])
                # Revoke old serial so it can't be reused
                self._crl.add(serial)
                reissued += 1

        print(f"[CA] Key rotation complete. Re-issued {reissued} certificate(s).")
        print("[CA] ── KEY ROTATION DONE ──\n")

    @property
    def ca_public_key(self) -> list:
        return self._ca_public_key

    def get_crl(self) -> set:
        """Return a copy of the current Certificate Revocation List."""
        return set(self._crl)