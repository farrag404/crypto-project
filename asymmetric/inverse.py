"""
Module: inverse.py
Robust Polynomial EEA
"""

from .poly import poly_trim, poly_degree


def poly_add_raw(a, b, q):
    size = max(len(a), len(b))

    result = [0] * size

    for i in range(size):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0

        result[i] = (av + bv) % q

    return poly_trim(result)


def poly_sub_raw(a, b, q):
    size = max(len(a), len(b))

    result = [0] * size

    for i in range(size):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0

        result[i] = (av - bv) % q

    return poly_trim(result)


def poly_mul_raw(a, b, q):
    result = [0] * (len(a) + len(b) - 1)

    for i in range(len(a)):
        for j in range(len(b)):
            result[i + j] += a[i] * b[j]
            result[i + j] %= q

    return poly_trim(result)


def poly_divmod(a, b, q):
    """
    Polynomial long division over Z_q
    """

    a = a[:]

    deg_b = poly_degree(b)

    if deg_b == -1:
        raise ZeroDivisionError()

    inv_lead = pow(b[-1], -1, q)

    quotient = [0] * max(1, len(a))

    while poly_degree(a) >= deg_b and poly_degree(a) != -1:

        deg_a = poly_degree(a)

        shift = deg_a - deg_b

        coeff = (a[-1] * inv_lead) % q

        quotient[shift] = coeff

        subtract_poly = [0] * shift + [
            (coeff * x) % q for x in b
        ]

        a = poly_sub_raw(a, subtract_poly, q)

    return poly_trim(quotient), poly_trim(a)


def poly_inverse(f, N, q, max_iter=500):
    """
    Compute inverse of f modulo (x^N - 1, q)

    Returns:
        inverse polynomial OR None
    """

    mod_poly = [-1] + [0] * (N - 1) + [1]

    r0 = mod_poly
    r1 = poly_trim([x % q for x in f])

    t0 = [0]
    t1 = [1]

    iterations = 0

    while poly_degree(r1) > 0 and iterations < max_iter:

        iterations += 1

        try:
            q_poly, r_poly = poly_divmod(r0, r1, q)
        except:
            return None

        r0, r1 = r1, r_poly

        temp = poly_sub_raw(
            t0,
            poly_mul_raw(q_poly, t1, q),
            q
        )

        t0, t1 = t1, temp

    if poly_degree(r1) != 0:
        return None

    try:
        inv_const = pow(r1[0], -1, q)
    except:
        return None

    inverse = [(x * inv_const) % q for x in t1]

    result = [0] * N

    for i, coeff in enumerate(inverse):
        result[i % N] = (result[i % N] + coeff) % q

    return result