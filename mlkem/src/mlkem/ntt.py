"""Number-Theoretic Transform and NTT-domain arithmetic.

FIPS 203, Section 4.3 (Algorithms 9-12) and Appendix A.

q - 1 = 2^8 * 13, so Z_q has a primitive 256-th root of unity (zeta = 17)
but no 512-th one. The NTT is therefore "incomplete": X^256 + 1 splits into
128 quadratic factors X^2 - zeta^(2*BitRev7(i)+1), and NTT-domain
multiplication works on pairs of coefficients (BaseCaseMultiply).
"""
from .params import N, Q, ZETA

Poly = list[int]


def bitrev7(i: int) -> int:
    """Reverse the 7 low bits of i (0 <= i < 128)."""
    return int(f"{i:07b}"[::-1], 2)


# Appendix A: zeta^BitRev7(i) for NTT / NTT^-1, zeta^(2*BitRev7(i)+1) for Alg 11.
ZETAS = [pow(ZETA, bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(ZETA, 2 * bitrev7(i) + 1, Q) for i in range(128)]

N_INV = pow(128, -1, Q)  # 3303: NTT^-1 scales by 128^-1 (7 layers, not 8)


def ntt(f: Poly) -> Poly:
    """Algorithm 9: NTT. Cooley-Tukey butterflies, len = 128, 64, ..., 2."""
    f_hat = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f_hat[j + length] % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length //= 2
    return f_hat


def ntt_inv(f_hat: Poly) -> Poly:
    """Algorithm 10: NTT^-1. Gentleman-Sande butterflies, len = 2, 4, ..., 128."""
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * N_INV % Q for x in f]


def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """Algorithm 12: (a0 + a1 X)(b0 + b1 X) in Z_q[X] / (X^2 - gamma)."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f_hat: Poly, g_hat: Poly) -> Poly:
    """Algorithm 11: MultiplyNTTs. 128 base-case products, one per quadratic factor."""
    h_hat = [0] * N
    for i in range(128):
        h_hat[2 * i], h_hat[2 * i + 1] = base_case_multiply(
            f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], GAMMAS[i]
        )
    return h_hat


# ---------------------------------------------------------------------------
# Polynomial / vector / matrix helpers used by K-PKE
# ---------------------------------------------------------------------------

def poly_add(a: Poly, b: Poly) -> Poly:
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a: Poly, b: Poly) -> Poly:
    return [(x - y) % Q for x, y in zip(a, b)]


def vec_ntt(v: list[Poly]) -> list[Poly]:
    return [ntt(p) for p in v]


def vec_intt(v: list[Poly]) -> list[Poly]:
    return [ntt_inv(p) for p in v]


def vec_add(u: list[Poly], v: list[Poly]) -> list[Poly]:
    return [poly_add(a, b) for a, b in zip(u, v)]


def inner_ntt(a_hat: list[Poly], b_hat: list[Poly]) -> Poly:
    """sum_j a_hat[j] * b_hat[j] in the NTT domain (a^T . b)."""
    acc = [0] * N
    for x, y in zip(a_hat, b_hat):
        acc = poly_add(acc, multiply_ntts(x, y))
    return acc


def mat_vec_mul_ntt(A_hat: list[list[Poly]], v_hat: list[Poly]) -> list[Poly]:
    """A_hat . v_hat: result[i] = sum_j A_hat[i][j] * v_hat[j]."""
    return [inner_ntt(row, v_hat) for row in A_hat]


def mat_T_vec_mul_ntt(A_hat: list[list[Poly]], v_hat: list[Poly]) -> list[Poly]:
    """A_hat^T . v_hat: result[i] = sum_j A_hat[j][i] * v_hat[j] (used in Encrypt)."""
    k = len(A_hat)
    return [inner_ntt([A_hat[j][i] for j in range(k)], v_hat) for i in range(k)]
