import time
import hashlib
import json

from asymmetric.ntru import NTRU


def _hash_certificate_fields(subject: str, public_key: list, issued_at: float, expires_at: float, serial: int) -> int:
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
    return field_hash ^ ca_secret


def _verify_sig(field_hash: int, signature: int, ca_secret: int) -> bool:
    return _sign(field_hash, ca_secret) == signature


#Certificate Authority

class CertificateAuthority:
    CERT_VALIDITY_SECONDS = 3600        # 1 hour

    def __init__(self):
        self._ntru          = NTRU(N=17, q=127, p=3)
        self._ca_public_key = self._ntru.keygen()

        self._ca_secret     = self._derive_secret()

        self._issued_certs: dict[int, dict] = {}

        self._crl: set[int] = set()

        self._serial_counter = 1

        print("[CA] Certificate Authority initialised.")
        print(f"[CA] CA public key (first 5 coeffs): {self._ca_public_key[:5]} ...")

    def _derive_secret(self) -> int:
        raw = hashlib.sha256(
            "|".join(map(str, self._ntru.f)).encode()
        ).hexdigest()
        return int(raw, 16)

    def _next_serial(self) -> int:
        serial = self._serial_counter
        self._serial_counter += 1
        return serial

    def issue_certificate(self, subject: str, public_key: list) -> dict:
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
        serial = cert.get("serial")

        #CRL check
        if serial in self._crl:
            print(f"[CA] Certificate serial={serial} is REVOKED.")
            return False

        #Expiry check
        if time.time() > cert["expires_at"]:
            print(f"[CA] Certificate serial={serial} has EXPIRED.")
            return False

        #Signature check
        field_hash = _hash_certificate_fields(
            cert["subject"],
            cert["public_key"],
            cert["issued_at"],
            cert["expires_at"],
            cert["serial"],
        )
        if not _verify_sig(field_hash, cert["signature"], self._ca_secret):
            print(f"[CA] Certificate serial={serial} has INVALID signature.")
            return False

        print(f"[CA] Certificate serial={serial} subject='{cert['subject']}' is VALID.")
        return True

    def revoke_certificate(self, serial: int):
        self._crl.add(serial)
        print(f"[CA] Certificate serial={serial} has been REVOKED and added to CRL.")

    def rotate_keys(self):
        print("\n[CA] KEY ROTATION STARTED")

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
        print("[CA] KEY ROTATION DONE \n")

    @property
    def ca_public_key(self) -> list:
        return self._ca_public_key

    def get_crl(self) -> set:
        return set(self._crl)