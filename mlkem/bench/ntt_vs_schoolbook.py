"""Step 05 teaser: schoolbook vs NTT polynomial multiplication in R_q (pure Python).

Run from mlkem/:  .venv/Scripts/python bench/ntt_vs_schoolbook.py
"""
import random
import timeit

from mlkem.ntt import multiply_ntts, ntt, ntt_inv
from mlkem.params import N, Q


def schoolbook_mul(a, b):
    """Multiplication in Z_q[X] / (X^256 + 1), O(n^2)."""
    c = [0] * (2 * N)
    for i in range(N):
        for j in range(N):
            c[i + j] += a[i] * b[j]
    return [(c[i] - c[i + N]) % Q for i in range(N)]


def ntt_mul(a, b):
    """Full NTT-based product: 2 forward NTTs, pointwise multiply, 1 inverse."""
    return ntt_inv(multiply_ntts(ntt(a), ntt(b)))


def main():
    rng = random.Random(0)
    a = [rng.randrange(Q) for _ in range(N)]
    b = [rng.randrange(Q) for _ in range(N)]
    assert schoolbook_mul(a, b) == ntt_mul(a, b)

    runs = 50
    t_school = min(timeit.repeat(lambda: schoolbook_mul(a, b), number=runs, repeat=5)) / runs
    t_ntt = min(timeit.repeat(lambda: ntt_mul(a, b), number=runs, repeat=5)) / runs
    a_hat, b_hat = ntt(a), ntt(b)
    t_pointwise = min(timeit.repeat(lambda: multiply_ntts(a_hat, b_hat), number=runs, repeat=5)) / runs

    print(f"schoolbook multiply        : {t_school * 1e3:8.3f} ms")
    print(f"NTT multiply (NTT+mul+INTT): {t_ntt * 1e3:8.3f} ms   speedup x{t_school / t_ntt:.1f}")
    print(f"MultiplyNTTs only          : {t_pointwise * 1e3:8.3f} ms   speedup x{t_school / t_pointwise:.1f}")


if __name__ == "__main__":
    main()
