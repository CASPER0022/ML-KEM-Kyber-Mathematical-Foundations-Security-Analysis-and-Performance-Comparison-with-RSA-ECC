"""Step 03: H, J, G, PRF, XOF are wired to the right SHA-3 functions."""
import hashlib

import pytest

from mlkem.hashes import G, H, J, PRF, XOF

SEED = bytes(range(32))


def test_H_is_sha3_256():
    assert H(b"") == hashlib.sha3_256(b"").digest()
    assert H(b"abc") == hashlib.sha3_256(b"abc").digest()


def test_J_is_shake256_32():
    out = J(b"abc")
    assert len(out) == 32
    assert out == hashlib.shake_256(b"abc").digest(32)


def test_G_splits_sha3_512():
    a, b = G(b"abc")
    assert len(a) == len(b) == 32
    assert a + b == hashlib.sha3_512(b"abc").digest()


@pytest.mark.parametrize("eta", [2, 3])
def test_PRF_length_and_input(eta):
    out = PRF(eta, SEED, 7)
    assert len(out) == 64 * eta
    assert out == hashlib.shake_256(SEED + b"\x07").digest(64 * eta)
    assert PRF(eta, SEED, 7) != PRF(eta, SEED, 8)


def test_PRF_rejects_bad_inputs():
    with pytest.raises(ValueError):
        PRF(4, SEED, 0)
    with pytest.raises(ValueError):
        PRF(2, b"short", 0)


def test_XOF_input_order_and_prefix():
    out = XOF(SEED, 1, 2, 504)
    assert out == hashlib.shake_128(SEED + b"\x01\x02").digest(504)
    assert XOF(SEED, 2, 1, 504) != out
    # Asking for more bytes extends the stream without changing the start.
    assert XOF(SEED, 1, 2, 1008)[:504] == out
