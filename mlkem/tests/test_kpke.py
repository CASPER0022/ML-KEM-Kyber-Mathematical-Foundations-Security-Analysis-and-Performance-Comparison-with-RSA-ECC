"""Step 06: K-PKE KeyGen / Encrypt / Decrypt (Alg 13-15)."""
import random

import pytest

from mlkem.encoding import byte_decode, decompress_poly
from mlkem.kpke import decrypt, decrypt_noisy, encrypt, gen_matrix, keygen
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, Q
from mlkem.sampling import sample_ntt

ALL = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
IDS = [p.name for p in ALL]


def centered(v: int) -> int:
    v %= Q
    return v if v <= Q // 2 else v - Q


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_sizes(p):
    rng = random.Random(1)
    ek, dk = keygen(rng.randbytes(32), p)
    assert len(ek) == 384 * p.k + 32 == p.ek_size
    assert len(dk) == 384 * p.k
    c = encrypt(ek, rng.randbytes(32), rng.randbytes(32), p)
    assert len(c) == 32 * (p.du * p.k + p.dv) == p.ct_size


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_round_trip(p):
    rng = random.Random(2 + p.k)
    for _ in range(200 // len(ALL) + 1):  # ~200 round trips in total
        ek, dk = keygen(rng.randbytes(32), p)
        m = rng.randbytes(32)
        assert decrypt(dk, encrypt(ek, m, rng.randbytes(32), p), p) == m


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_round_trip_edge_messages(p):
    ek, dk = keygen(bytes(32), p)
    for m in (bytes(32), b"\xff" * 32, b"\x55" * 32):
        assert decrypt(dk, encrypt(ek, m, bytes(range(32)), p), p) == m


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_deterministic(p):
    d, m, r = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    assert keygen(d, p) == keygen(d, p)
    ek, _ = keygen(d, p)
    assert encrypt(ek, m, r, p) == encrypt(ek, m, r, p)
    assert encrypt(ek, m, r, p) != encrypt(ek, m, b"\x04" * 32, p)


def test_keygen_domain_separates_k():
    """Same seed d gives unrelated rho for different k (d || byte(k) in G)."""
    d = bytes(32)
    rho512 = keygen(d, ML_KEM_512)[0][-32:]
    rho768 = keygen(d, ML_KEM_768)[0][-32:]
    assert rho512 != rho768


def test_gen_matrix_index_order():
    rho = bytes(range(32))
    A = gen_matrix(rho, 2)
    assert A[0][1] == sample_ntt(rho + bytes([1, 0]))  # rho || j || i
    assert A[1][0] == sample_ntt(rho + bytes([0, 1]))


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_noise_below_q_over_4(p):
    """w - mu is the decryption noise; it must stay well under q/4 = 832."""
    rng = random.Random(9)
    ek, dk = keygen(rng.randbytes(32), p)
    for _ in range(10):
        m = rng.randbytes(32)
        w = decrypt_noisy(dk, encrypt(ek, m, rng.randbytes(32), p), p)
        mu = decompress_poly(byte_decode(m, 1), 1)
        assert max(abs(centered(a - b)) for a, b in zip(w, mu)) < Q // 4


def test_rejects_bad_lengths():
    p = ML_KEM_512
    ek, dk = keygen(bytes(32), p)
    with pytest.raises(ValueError):
        keygen(bytes(31), p)
    with pytest.raises(ValueError):
        encrypt(ek[:-1], bytes(32), bytes(32), p)
    with pytest.raises(ValueError):
        encrypt(ek, bytes(31), bytes(32), p)
    with pytest.raises(ValueError):
        decrypt(dk, bytes(p.ct_size - 1), p)
