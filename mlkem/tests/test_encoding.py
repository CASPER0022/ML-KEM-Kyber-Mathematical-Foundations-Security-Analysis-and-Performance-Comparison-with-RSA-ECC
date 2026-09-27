"""Step 03: BitsToBytes/BytesToBits, ByteEncode/ByteDecode, Compress/Decompress."""
import random
from fractions import Fraction
from math import floor

import pytest

from mlkem.encoding import (
    bits_to_bytes,
    byte_decode,
    byte_decode_ref,
    byte_encode,
    byte_encode_ref,
    bytes_to_bits,
    compress,
    decompress,
)
from mlkem.params import N, Q

rng = random.Random(203)


def random_poly(d):
    m = Q if d == 12 else 1 << d
    return [rng.randrange(m) for _ in range(N)]


def round_half_up(x: Fraction) -> int:
    return floor(x + Fraction(1, 2))


def centered(x):
    """x mod+- q, in [-(q-1)/2, (q-1)/2]."""
    x %= Q
    return x - Q if x > Q // 2 else x


# --- Algorithms 3 and 4 ---------------------------------------------------

def test_bytes_to_bits_lsb_first():
    assert bytes_to_bits(b"\x01") == [1, 0, 0, 0, 0, 0, 0, 0]
    assert bytes_to_bits(b"\x80") == [0, 0, 0, 0, 0, 0, 0, 1]
    assert bits_to_bytes([1, 0, 1, 0, 0, 0, 0, 0]) == b"\x05"


@pytest.mark.parametrize("nbytes", [1, 2, 32, 384])
def test_bits_bytes_roundtrip(nbytes):
    bits = [rng.randrange(2) for _ in range(8 * nbytes)]
    assert bytes_to_bits(bits_to_bytes(bits)) == bits


def test_bits_to_bytes_rejects_partial_byte():
    with pytest.raises(ValueError):
        bits_to_bytes([1, 0, 1])


# --- Algorithms 5 and 6 ---------------------------------------------------

@pytest.mark.parametrize("d", range(1, 13))
def test_byte_encode_decode_roundtrip(d):
    F = random_poly(d)
    B = byte_encode(F, d)
    assert len(B) == 32 * d
    assert byte_decode(B, d) == F


@pytest.mark.parametrize("d", range(1, 13))
def test_fast_matches_reference(d):
    F = random_poly(d)
    assert byte_encode(F, d) == byte_encode_ref(F, d)
    B = bytes(rng.randrange(256) for _ in range(32 * d))
    assert byte_decode(B, d) == byte_decode_ref(B, d)


def test_byte_decode_12_reduces_mod_q():
    # All-ones bytes = every 12-bit value is 4095, which is >= q.
    B = b"\xff" * (32 * 12)
    assert byte_decode(B, 12) == [4095 % Q] * N
    assert byte_decode_ref(B, 12) == [4095 % Q] * N
    # So decode-then-encode does NOT give back the input: this is the
    # modulus check ML-KEM.Encaps performs on ek (FIPS 203, Section 7.2).
    assert byte_encode(byte_decode(B, 12), 12) != B


def test_byte_encode_rejects_out_of_range():
    with pytest.raises(ValueError):
        byte_encode([Q] + [0] * (N - 1), 12)
    with pytest.raises(ValueError):
        byte_encode([16] + [0] * (N - 1), 4)


def test_byte_decode_rejects_wrong_length():
    with pytest.raises(ValueError):
        byte_decode(b"\x00" * 31, 1)


# --- Compress / Decompress --------------------------------------------------

@pytest.mark.parametrize("d", range(1, 12))
def test_compress_matches_exact_rounding(d):
    for x in range(Q):
        exact = round_half_up(Fraction(2**d * x, Q)) % 2**d
        assert compress(x, d) == exact


@pytest.mark.parametrize("d", range(1, 12))
def test_decompress_matches_exact_rounding(d):
    for y in range(2**d):
        assert decompress(y, d) == round_half_up(Fraction(Q * y, 2**d))


@pytest.mark.parametrize("d", range(1, 12))
def test_compression_error_bound(d):
    """|Decompress(Compress(x)) - x| mod+- q <= round(q / 2^(d+1)) for all x."""
    bound = round_half_up(Fraction(Q, 2 ** (d + 1)))
    worst = max(abs(centered(decompress(compress(x, d), d) - x)) for x in range(Q))
    assert worst <= bound


@pytest.mark.parametrize("d", range(1, 12))
def test_decompress_then_compress_is_identity(d):
    assert all(compress(decompress(y, d), d) == y for y in range(2**d))


def test_compress_hand_worked_edges():
    # d = 1: Compress_1(x) = round(2x / q) mod 2 is 1 exactly for x in [833, 2496].
    # 2*832/3329 = 0.4998 -> 0;  2*833/3329 = 0.5004 -> 1
    # 2*2496/3329 = 1.4995 -> 1; 2*2497/3329 = 1.5001 -> 2 = 0 mod 2
    assert [compress(x, 1) for x in (0, 832, 833, 1664, 2496, 2497, 3328)] == [0, 0, 1, 1, 1, 0, 0]
    # Decompress_1(1) = round(3329 / 2) = round(1664.5) = 1665 (half rounds up)
    assert decompress(1, 1) == 1665
    # d = 4: Compress_4(3328) = round(16 * 3328 / 3329) = round(15.995) = 16 = 0 mod 16
    assert compress(3328, 4) == 0
