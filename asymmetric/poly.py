"""
Module: poly.py
Description:
Manual polynomial arithmetic for NTRU.
Ring: Z_q[x] / (x^N - 1)
"""

def poly_add(a, b, q):
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a, b, q):
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul(a, b, N, q):
    """
    Cyclic convolution modulo (x^N - 1)
    """
    result = [0] * N

    for i in range(N):
        for j in range(N):
            result[(i + j) % N] += a[i] * b[j]

    return [x % q for x in result]


def poly_scalar_mul(poly, scalar, q):
    return [(scalar * x) % q for x in poly]


def poly_center(poly, q):
    """
    Map coefficients from [0,q)
    into symmetric interval [-q/2, q/2]
    """
    half = q // 2

    centered = []

    for x in poly:
        x %= q

        if x > half:
            x -= q

        centered.append(x)

    return centered


def poly_mod(poly, q):
    return [x % q for x in poly]


def poly_trim(poly):
    """
    Remove trailing zeros.
    """
    p = poly[:]

    while len(p) > 1 and p[-1] == 0:
        p.pop()

    return p


def poly_degree(poly):
    poly = poly_trim(poly)

    if poly == [0]:
        return -1

    return len(poly) - 1


def poly_to_bytes(poly):
    return "|".join(map(str, poly)).encode()