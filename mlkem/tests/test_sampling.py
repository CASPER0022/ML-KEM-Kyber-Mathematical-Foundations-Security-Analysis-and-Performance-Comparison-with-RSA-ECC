"""Step 04: SampleNTT (Alg 7) and SamplePolyCBD (Alg 8)."""
import hashlib
import random
from collections import Counter
from math import comb

import pytest

from mlkem.hashes import PRF
from mlkem.params import N, Q
from mlkem.sampling import sample_ntt, sample_poly_cbd

RHO = bytes(range(32))


def centered(v: int) -> int:
    return v if v <= Q // 2 else v - Q


def sample_ntt_ref(B: bytes) -> list[int]:
    """Alg 7 straight from the spec, reading SHAKE128 through a big buffer."""
    C = hashlib.shake_128(B).digest(4096)
    a, pos = [], 0
    while len(a) < N:
        d1 = C[pos] + 256 * (C[pos + 1] % 16)
        d2 = C[pos + 1] // 16 + 16 * C[pos + 2]
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
        pos += 3
    return a


# ---------------------------------------------------------------------------
# SampleNTT
# ---------------------------------------------------------------------------

def test_sample_ntt_shape_and_range():
    a = sample_ntt(RHO + bytes([0, 1]))
    assert len(a) == N
    assert all(0 <= x < Q for x in a)


def test_sample_ntt_deterministic():
    B = RHO + bytes([2, 1])
    assert sample_ntt(B) == sample_ntt(B)


def test_sample_ntt_index_order_matters():
    assert sample_ntt(RHO + bytes([0, 1])) != sample_ntt(RHO + bytes([1, 0]))


def test_sample_ntt_matches_reference():
    rng = random.Random(4)
    for _ in range(20):
        B = rng.randbytes(34)
        assert sample_ntt(B) == sample_ntt_ref(B)


def test_sample_ntt_rejects_bad_length():
    with pytest.raises(ValueError):
        sample_ntt(RHO)


# ---------------------------------------------------------------------------
# SamplePolyCBD
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("eta", [2, 3])
def test_cbd_range(eta):
    f = sample_poly_cbd(PRF(eta, RHO, 0), eta)
    assert len(f) == N
    assert all(0 <= v < Q for v in f)
    assert all(-eta <= centered(v) <= eta for v in f)


@pytest.mark.parametrize("eta", [2, 3])
def test_cbd_distribution(eta):
    """Histogram of centered values ~ binomial C(2*eta, k) / 4^eta."""
    rng = random.Random(eta)
    counts = Counter()
    polys = 10_000 // N + 40  # > 10,000 coefficients
    for _ in range(polys):
        counts.update(centered(v) for v in sample_poly_cbd(rng.randbytes(64 * eta), eta))
    total = polys * N
    for v in range(-eta, eta + 1):
        expected = comb(2 * eta, v + eta) / 4 ** eta
        assert abs(counts[v] / total - expected) < 0.01, (v, counts[v] / total, expected)


@pytest.mark.parametrize("eta,length", [(2, 127), (2, 192), (3, 128), (3, 193)])
def test_cbd_rejects_bad_length(eta, length):
    with pytest.raises(ValueError):
        sample_poly_cbd(bytes(length), eta)


def test_cbd_rejects_bad_eta():
    with pytest.raises(ValueError):
        sample_poly_cbd(bytes(256), 4)


def test_sample_ntt_retry_path(monkeypatch):
    """Force the 'ran out of XOF bytes' branch; result must not change."""
    import mlkem.sampling as sampling
    B = RHO + bytes([3, 0])
    expected = sample_ntt(B)
    monkeypatch.setattr(sampling, "_XOF_BYTES", 3)
    assert sampling.sample_ntt(B) == expected
