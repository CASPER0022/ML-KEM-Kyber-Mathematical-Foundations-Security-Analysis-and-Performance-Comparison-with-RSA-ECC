"""Parameter sets match FIPS 203 Tables 2-3, and the constants support the NTT."""
import pytest

from mlkem.params import N, PARAMS, Q, ZETA, ML_KEM_512, ML_KEM_768, ML_KEM_1024

# FIPS 203 Table 3: (ek, dk, ct, K) sizes in bytes
TABLE_3 = {
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
    "ML-KEM-1024": (1568, 3168, 1568, 32),
}


@pytest.mark.parametrize("name", TABLE_3)
def test_sizes_match_table_3(name):
    p = PARAMS[name]
    assert (p.ek_size, p.dk_size, p.ct_size, p.shared_secret_size) == TABLE_3[name]


def test_table_2_values():
    assert (ML_KEM_512.k, ML_KEM_512.eta1, ML_KEM_512.eta2, ML_KEM_512.du, ML_KEM_512.dv) == (2, 3, 2, 10, 4)
    assert (ML_KEM_768.k, ML_KEM_768.eta1, ML_KEM_768.eta2, ML_KEM_768.du, ML_KEM_768.dv) == (3, 2, 2, 10, 4)
    assert (ML_KEM_1024.k, ML_KEM_1024.eta1, ML_KEM_1024.eta2, ML_KEM_1024.du, ML_KEM_1024.dv) == (4, 2, 2, 11, 5)


def test_q_is_prime():
    assert all(Q % d for d in range(2, int(Q**0.5) + 1))


def test_ntt_friendly_modulus():
    # 256 | q - 1, so Z_q has a 256-th root of unity; 512 does not divide q - 1,
    # which is why ML-KEM's NTT stops at degree-2 factors (Section 4.3).
    assert (Q - 1) % 256 == 0
    assert (Q - 1) % 512 != 0


def test_zeta_is_primitive_256th_root():
    assert pow(ZETA, 256, Q) == 1
    assert pow(ZETA, 128, Q) == Q - 1   # zeta^128 = -1, so the order is exactly 256


def test_n():
    assert N == 256


def test_pyca_sizes_agree():
    """An independent implementation (pyca/cryptography) agrees with Table 3."""
    from cryptography.hazmat.primitives.asymmetric import mlkem

    for cls, p in ((mlkem.MLKEM768PrivateKey, ML_KEM_768), (mlkem.MLKEM1024PrivateKey, ML_KEM_1024)):
        sk = cls.generate()
        key, ct = sk.public_key().encapsulate()
        assert len(sk.public_key().public_bytes_raw()) == p.ek_size
        assert len(ct) == p.ct_size
        assert len(key) == p.shared_secret_size
