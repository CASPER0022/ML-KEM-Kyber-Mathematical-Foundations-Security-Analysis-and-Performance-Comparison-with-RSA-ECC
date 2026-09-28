"""Step 09: interoperability with independent ML-KEM implementations.

- liboqs (C, Open Quantum Safe) via liboqs-python: 512 / 768 / 1024
- pyca/cryptography (OpenSSL / AWS-LC backend): 768 / 1024 only

Each backend is skipped automatically if it is not installed.
"""
import os

import pytest

from mlkem.hashes import J
from mlkem.mlkem import decaps, encaps, keygen, keygen_internal
from mlkem.oqs_backend import load_oqs
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

ALL = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
IDS = [p.name for p in ALL]

oqs = load_oqs()
needs_oqs = pytest.mark.skipif(oqs is None, reason="liboqs / liboqs-python not available")


def flip_bit(b: bytes, bit: int) -> bytes:
    out = bytearray(b)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


# ---------------------------------------------------------------------------
# liboqs
# ---------------------------------------------------------------------------

@needs_oqs
@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_oqs_seeded_keygen_matches_byte_for_byte(p):
    for _ in range(5):
        d, z = os.urandom(32), os.urandom(32)
        with oqs.KeyEncapsulation(p.name) as kem:
            ek_oqs = kem.generate_keypair_seed(d + z)
            dk_oqs = kem.export_secret_key()
        assert keygen_internal(p, d, z) == (ek_oqs, dk_oqs)


@needs_oqs
@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_oqs_keys_our_encaps(p):
    """liboqs KeyGen -> our Encaps -> liboqs Decaps."""
    with oqs.KeyEncapsulation(p.name) as kem:
        ek = kem.generate_keypair()
        for _ in range(5):
            K, c = encaps(p, ek)
            assert kem.decap_secret(c) == K


@needs_oqs
@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_our_keys_oqs_encaps(p):
    """our KeyGen -> liboqs Encaps -> our Decaps."""
    ek, dk = keygen(p)
    with oqs.KeyEncapsulation(p.name) as kem:
        for _ in range(5):
            c, K = kem.encap_secret(ek)
            assert decaps(p, dk, c) == K


@needs_oqs
@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_oqs_implicit_rejection_matches(p):
    """Both implementations derive the same J(z || c) key for a tampered c."""
    ek, dk = keygen(p)
    _, c = encaps(p, ek)
    bad = flip_bit(c, 100)
    with oqs.KeyEncapsulation(p.name, secret_key=dk) as kem:
        K_oqs = kem.decap_secret(bad)
    assert K_oqs == decaps(p, dk, bad) == J(dk[-32:] + bad)


# ---------------------------------------------------------------------------
# pyca/cryptography
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as pyca_mlkem
    PYCA = {
        "ML-KEM-768": (pyca_mlkem.MLKEM768PrivateKey, pyca_mlkem.MLKEM768PublicKey),
        "ML-KEM-1024": (pyca_mlkem.MLKEM1024PrivateKey, pyca_mlkem.MLKEM1024PublicKey),
    }
except ImportError:
    PYCA = {}

PYCA_PARAMS = [p for p in ALL if p.name in PYCA] or [pytest.param(None, marks=pytest.mark.skip)]


@pytest.mark.skipif(not PYCA, reason="cryptography has no ML-KEM support")
@pytest.mark.parametrize("p", PYCA_PARAMS, ids=lambda p: p.name if p else "none")
def test_pyca_seeded_ek_matches(p):
    priv_cls, _ = PYCA[p.name]
    d, z = os.urandom(32), os.urandom(32)
    ek_pyca = priv_cls.from_seed_bytes(d + z).public_key().public_bytes_raw()
    assert keygen_internal(p, d, z)[0] == ek_pyca


@pytest.mark.skipif(not PYCA, reason="cryptography has no ML-KEM support")
@pytest.mark.parametrize("p", PYCA_PARAMS, ids=lambda p: p.name if p else "none")
def test_pyca_both_directions(p):
    priv_cls, pub_cls = PYCA[p.name]
    # pyca keys -> our Encaps -> pyca Decaps
    sk = priv_cls.generate()
    K, c = encaps(p, sk.public_key().public_bytes_raw())
    assert sk.decapsulate(c) == K
    # our keys -> pyca Encaps -> our Decaps
    ek, dk = keygen(p)
    K2, c2 = pub_cls.from_public_bytes(ek).encapsulate()
    assert decaps(p, dk, c2) == K2
