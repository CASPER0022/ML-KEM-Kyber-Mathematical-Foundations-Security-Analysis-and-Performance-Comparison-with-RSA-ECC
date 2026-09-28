"""Step 07: ML-KEM FO transform, public API and input checks (Alg 16-21)."""
import pytest

from mlkem.encoding import byte_decode, byte_encode
from mlkem.hashes import H, J
from mlkem.mlkem import (
    decaps, decaps_internal, encaps, encaps_internal, keygen, keygen_internal,
)
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

ALL = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
IDS = [p.name for p in ALL]

# Table 3 of FIPS 203 (hard-coded, not derived from Params).
TABLE_3 = {
    "ML-KEM-512": (800, 1632, 768),
    "ML-KEM-768": (1184, 2400, 1088),
    "ML-KEM-1024": (1568, 3168, 1568),
}


def flip_bit(b: bytes, bit: int) -> bytes:
    out = bytearray(b)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


@pytest.fixture(scope="module", params=ALL, ids=IDS)
def keys(request):
    p = request.param
    ek, dk = keygen(p)
    return p, ek, dk


# ---------------------------------------------------------------------------
# Correctness and sizes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_shared_secret_agrees(p):
    for _ in range(100):
        ek, dk = keygen(p)
        K1, c = encaps(p, ek)
        K2 = decaps(p, dk, c)
        assert len(K1) == 32
        assert K1 == K2


def test_sizes_match_table_3(keys):
    p, ek, dk = keys
    _, c = encaps(p, ek)
    assert (len(ek), len(dk), len(c)) == TABLE_3[p.name]


def test_dk_layout(keys):
    p, ek, dk = keys
    k = p.k
    assert dk[384 * k:768 * k + 32] == ek
    assert dk[768 * k + 32:768 * k + 64] == H(ek)


@pytest.mark.parametrize("p", ALL, ids=IDS)
def test_internal_functions_deterministic(p):
    d, z, m = b"\x11" * 32, b"\x22" * 32, b"\x33" * 32
    ek, dk = keygen_internal(p, d, z)
    assert (ek, dk) == keygen_internal(p, d, z)
    assert dk[-32:] == z
    K, c = encaps_internal(p, ek, m)
    assert (K, c) == encaps_internal(p, ek, m)
    assert decaps_internal(p, dk, c) == K


def test_public_api_is_randomized(keys):
    p, ek, _ = keys
    assert keygen(p) != keygen(p)
    assert encaps(p, ek) != encaps(p, ek)


# ---------------------------------------------------------------------------
# Implicit rejection (FO transform)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bit", [0, 1000, -1])
def test_implicit_rejection(keys, bit):
    p, ek, dk = keys
    K1, c = encaps(p, ek)
    bad = flip_bit(c, bit % (8 * len(c)))
    K_bad = decaps(p, dk, bad)  # must not raise
    z = dk[-32:]
    assert K_bad != K1
    assert K_bad == J(z + bad)


def test_implicit_rejection_depends_on_z(keys):
    """Same (dk_PKE, ek, c) with a different z gives a different rejection key."""
    p, ek, dk = keys
    _, c = encaps(p, ek)
    bad = flip_bit(c, 5)
    dk2 = dk[:-32] + bytes(32)
    assert decaps(p, dk, bad) != decaps(p, dk2, bad)


# ---------------------------------------------------------------------------
# Input checks (Sections 7.2 and 7.3)
# ---------------------------------------------------------------------------

def test_ek_modulus_check(keys):
    p, ek, _ = keys
    coeffs = byte_decode(ek[:384], 12)
    coeffs[0] = 0
    chunk = bytearray(byte_encode(coeffs, 12))
    chunk[0] = 0xFF
    chunk[1] |= 0x0F  # coefficient 0 = 4095 >= q
    bad_ek = bytes(chunk) + ek[384:]
    with pytest.raises(ValueError, match="modulus"):
        encaps(p, bad_ek)


def test_ek_modulus_check_last_poly(keys):
    """A bad coefficient in the last polynomial of t_hat is caught too."""
    p, ek, _ = keys
    start = 384 * (p.k - 1)
    bad_ek = ek[:start + 382] + b"\xff\xff" + ek[start + 384:]  # last coeff = 4095
    with pytest.raises(ValueError, match="modulus"):
        encaps(p, bad_ek)


def test_dk_hash_check(keys):
    p, _, dk = keys
    k = p.k
    _, c = encaps(p, keys[1])
    bad_dk = flip_bit(dk, 8 * (768 * k + 32))  # first byte of stored H(ek)
    with pytest.raises(ValueError, match="hash"):
        decaps(p, bad_dk, c)


def test_dk_hash_check_catches_modified_ek(keys):
    p, ek, dk = keys
    _, c = encaps(p, ek)
    bad_dk = flip_bit(dk, 8 * (384 * p.k))  # first byte of embedded ek
    with pytest.raises(ValueError, match="hash"):
        decaps(p, bad_dk, c)


def test_wrong_lengths(keys):
    p, ek, dk = keys
    _, c = encaps(p, ek)
    with pytest.raises(ValueError):
        encaps(p, ek[:-1])
    with pytest.raises(ValueError):
        encaps(p, ek + b"\x00")
    with pytest.raises(ValueError):
        decaps(p, dk, c[:-1])
    with pytest.raises(ValueError):
        decaps(p, dk, c + b"\x00")
    with pytest.raises(ValueError):
        decaps(p, dk[:-1], c)
    with pytest.raises(ValueError):
        decaps(p, dk + b"\x00", c)


def test_wrong_parameter_set(keys):
    """Keys from one parameter set are rejected by another (size mismatch)."""
    p, ek, dk = keys
    other = ALL[(ALL.index(p) + 1) % len(ALL)]
    with pytest.raises(ValueError):
        encaps(other, ek)
