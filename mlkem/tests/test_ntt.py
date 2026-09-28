"""Step 05: NTT, NTT^-1, MultiplyNTTs and the vector/matrix helpers."""
import random

import pytest

from mlkem.ntt import (
    GAMMAS, N_INV, ZETAS, bitrev7, inner_ntt, mat_T_vec_mul_ntt, mat_vec_mul_ntt,
    multiply_ntts, ntt, ntt_inv, poly_add, poly_sub, vec_intt, vec_ntt,
)
from mlkem.params import N, Q

# FIPS 203 Appendix A, copied from the PDF.
APPENDIX_A_ZETAS = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
]

# Appendix A lists the gammas signed (17, -17, 2761, -2761, ...): each pair is +-g.
_GAMMA_BASE = [
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
]
APPENDIX_A_GAMMAS = [s * g for g in _GAMMA_BASE for s in (1, -1)]


def rand_poly(rng: random.Random) -> list[int]:
    return [rng.randrange(Q) for _ in range(N)]


def schoolbook_mul(a, b):
    """Slow reference: multiplication in Z_q[X] / (X^256 + 1)."""
    c = [0] * 512
    for i in range(256):
        for j in range(256):
            c[i + j] += a[i] * b[j]
    return [(c[i] - c[i + 256]) % Q for i in range(256)]  # X^256 = -1


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def test_bitrev7():
    assert bitrev7(0) == 0
    assert bitrev7(1) == 64
    assert bitrev7(127) == 127
    assert sorted(bitrev7(i) for i in range(128)) == list(range(128))


def test_table_spot_checks():
    assert ZETAS[1] == 1729
    assert GAMMAS[0] == 17
    assert N_INV == 3303 and 128 * N_INV % Q == 1


def test_zetas_match_appendix_a():
    assert ZETAS == APPENDIX_A_ZETAS


def test_gammas_match_appendix_a():
    assert GAMMAS == [g % Q for g in APPENDIX_A_GAMMAS]


# ---------------------------------------------------------------------------
# NTT
# ---------------------------------------------------------------------------

def test_round_trip():
    rng = random.Random(5)
    for _ in range(100):
        f = rand_poly(rng)
        assert ntt_inv(ntt(f)) == f
        assert ntt(ntt_inv(f)) == f


def test_output_range():
    f_hat = ntt(rand_poly(random.Random(6)))
    assert len(f_hat) == N and all(0 <= x < Q for x in f_hat)


def test_linearity():
    rng = random.Random(7)
    for _ in range(20):
        a, b = rand_poly(rng), rand_poly(rng)
        assert ntt(poly_add(a, b)) == poly_add(ntt(a), ntt(b))
        assert ntt(poly_sub(a, b)) == poly_sub(ntt(a), ntt(b))


def test_multiply_matches_schoolbook():
    rng = random.Random(8)
    for _ in range(5):
        a, b = rand_poly(rng), rand_poly(rng)
        assert ntt_inv(multiply_ntts(ntt(a), ntt(b))) == schoolbook_mul(a, b)


def test_multiply_small_cases():
    one = [1] + [0] * (N - 1)
    x = [0, 1] + [0] * (N - 2)
    x255 = [0] * (N - 1) + [1]
    a = rand_poly(random.Random(9))
    # 1 * a == a
    assert ntt_inv(multiply_ntts(ntt(one), ntt(a))) == a
    # X * X^255 = X^256 = -1
    assert ntt_inv(multiply_ntts(ntt(x), ntt(x255))) == [Q - 1] + [0] * (N - 1)


# ---------------------------------------------------------------------------
# Vector / matrix helpers (checked against schoolbook arithmetic)
# ---------------------------------------------------------------------------

def _poly_sum(polys):
    acc = [0] * N
    for p in polys:
        acc = poly_add(acc, p)
    return acc


@pytest.mark.parametrize("k", [2, 3])
def test_matrix_helpers_match_schoolbook(k):
    rng = random.Random(10 + k)
    A = [[rand_poly(rng) for _ in range(k)] for _ in range(k)]
    v = [rand_poly(rng) for _ in range(k)]
    A_hat = [vec_ntt(row) for row in A]
    v_hat = vec_ntt(v)

    assert vec_intt(v_hat) == v

    Av = [_poly_sum(schoolbook_mul(A[i][j], v[j]) for j in range(k)) for i in range(k)]
    assert vec_intt(mat_vec_mul_ntt(A_hat, v_hat)) == Av

    ATv = [_poly_sum(schoolbook_mul(A[j][i], v[j]) for j in range(k)) for i in range(k)]
    assert vec_intt(mat_T_vec_mul_ntt(A_hat, v_hat)) == ATv

    dot = _poly_sum(schoolbook_mul(A[0][j], v[j]) for j in range(k))
    assert ntt_inv(inner_ntt(A_hat[0], v_hat)) == dot
