"""
Module: ntru.py
Core NTRU logic
"""

import random

from .poly import (
    poly_add,
    poly_mul,
    poly_center
)

from .inverse import poly_inverse


class NTRU:

    def __init__(self, N=17, q=127, p=3):

        self.N = N
        self.q = q
        self.p = p

        self.f = None
        self.f_p_inv = None
        self.h = None

    def random_sparse_poly(self, weight=3):

        poly = [0] * self.N

        positions = random.sample(range(self.N), weight * 2)

        for i in positions[:weight]:
            poly[i] = 1

        for i in positions[weight:]:
            poly[i] = -1

        return poly

    def random_message_poly(self):

        return [random.randint(0, self.p - 1)
                for _ in range(self.N)]

    def keygen(self):

        while True:

            f = self.random_sparse_poly()

            f[0] += 1

            f_q_inv = poly_inverse(f, self.N, self.q)
            f_p_inv = poly_inverse(f, self.N, self.p)

            if f_q_inv is None or f_p_inv is None:
                continue

            g = self.random_sparse_poly()

            h = poly_mul(f_q_inv, g, self.N, self.q)

            h = [(self.p * x) % self.q for x in h]

            self.f = f
            self.f_p_inv = f_p_inv
            self.h = h

            return h

    def encrypt(self, message_poly, public_key):

        r = self.random_sparse_poly()

        rh = poly_mul(r, public_key, self.N, self.q)

        ciphertext = poly_add(rh, message_poly, self.q)

        return ciphertext

    def decrypt(self, ciphertext):

        a = poly_mul(self.f, ciphertext, self.N, self.q)

        a = poly_center(a, self.q)

        a_mod_p = [x % self.p for x in a]

        m = poly_mul(
            self.f_p_inv,
            a_mod_p,
            self.N,
            self.p
        )

        return [x % self.p for x in m]