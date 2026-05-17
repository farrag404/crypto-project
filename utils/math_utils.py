# utils/math_utils.py

# =============================
# 1. GCD (Greatest Common Divisor)
# =============================
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# =============================
# 2. Extended Euclidean Algorithm
# =============================
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1

    gcd_val, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd_val, x, y


# =============================
# 3. Modular Inverse
# =============================
def mod_inverse(a, m):
    gcd_val, x, y = extended_gcd(a, m)

    if gcd_val != 1:
        raise Exception("Modular inverse does not exist")

    return x % m


# =============================
# 4. Fast Modular Exponentiation
# =============================
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod

    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod

        exp = exp // 2
        base = (base * base) % mod

    return result


# =============================
# 5. Matrix Multiplication (mod m)
# =============================
def matrix_multiply(A, B, mod):
    result = [[0 for _ in range(len(B[0]))] for _ in range(len(A))]

    for i in range(len(A)):
        for j in range(len(B[0])):
            for k in range(len(B)):
                result[i][j] += A[i][k] * B[k][j]

            result[i][j] %= mod

    return result


# =============================
# 6. Matrix Determinant (2x2 only)
# =============================
def matrix_det_2x2(matrix):
    return matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0]


# =============================
# 7. Matrix Inverse (2x2 mod m)
# =============================
def matrix_inverse_2x2(matrix, mod):
    det = matrix_det_2x2(matrix)
    det_inv = mod_inverse(det % mod, mod)

    inv_matrix = [
        [ matrix[1][1], -matrix[0][1]],
        [-matrix[1][0],  matrix[0][0]]
    ]

    # Apply mod and multiply by determinant inverse
    for i in range(2):
        for j in range(2):
            inv_matrix[i][j] = (inv_matrix[i][j] * det_inv) % mod

    return inv_matrix