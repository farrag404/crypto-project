"""
Module: kdf.py
SHA-256 KDF
"""

import hashlib
from .poly import poly_to_bytes


def derive_key(poly_secret):
    data = poly_to_bytes(poly_secret)

    return hashlib.sha256(data).digest()