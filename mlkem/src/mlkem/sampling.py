"""Sampling: SampleNTT and SamplePolyCBD (FIPS 203, Section 4.2.2, Algorithms 7 and 8)."""
from .encoding import bytes_to_bits
from .hashes import XOF
from .params import N, Q

# 504 bytes = 168 * 3 (one SHAKE128 rate block is 168 bytes) gives 336
# candidates; 256 are needed and each is accepted with p = 3329/4096, so a
# retry is rare.
_XOF_BYTES = 504


def sample_ntt(B: bytes) -> list[int]:
    """Algorithm 7: SampleNTT. 34-byte seed rho || j || i -> polynomial in NTT domain.

    Rejection-samples 12-bit candidates from SHAKE128(B) and keeps those < q.
    Note the index order: K-PKE builds A_hat[i][j] from SampleNTT(rho || j || i).
    """
    if len(B) != 34:
        raise ValueError(f"SampleNTT input must be 34 bytes, got {len(B)}")
    rho, j, i = B[:32], B[32], B[33]
    n = _XOF_BYTES
    while True:
        C = XOF(rho, j, i, n)
        a = []
        pos = 0
        while len(a) < N and pos + 3 <= n:
            c0, c1, c2 = C[pos], C[pos + 1], C[pos + 2]
            d1 = c0 + 256 * (c1 % 16)
            d2 = c1 // 16 + 16 * c2
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < N:
                a.append(d2)
            pos += 3
        if len(a) == N:
            return a
        # Ran out of XOF output: ask for more. The shorter output is a prefix
        # of the longer one, so this matches a streaming XOF exactly.
        n += 168


def sample_poly_cbd(B: bytes, eta: int) -> list[int]:
    """Algorithm 8: SamplePolyCBD_eta. 64*eta bytes -> 256 coefficients in [-eta, eta] mod q.

    Each coefficient is x - y where x and y are sums of eta random bits
    (centered binomial distribution).
    """
    if eta not in (2, 3):
        raise ValueError(f"eta must be 2 or 3, got {eta}")
    if len(B) != 64 * eta:
        raise ValueError(f"SamplePolyCBD_{eta} input must be {64 * eta} bytes, got {len(B)}")
    b = bytes_to_bits(B)
    f = []
    for i in range(N):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f
