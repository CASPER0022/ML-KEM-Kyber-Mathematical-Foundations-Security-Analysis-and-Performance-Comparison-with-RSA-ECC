"""Bit/byte conversion, ByteEncode/ByteDecode and Compress/Decompress.

FIPS 203, Section 4.2.1 (Algorithms 3-6, equations 4.7 and 4.8).
"""
from .params import N, Q


# ---------------------------------------------------------------------------
# Algorithms 3 and 4: bit lists <-> bytes (LSB first)
# ---------------------------------------------------------------------------

def bits_to_bytes(b: list[int]) -> bytes:
    """Algorithm 3: BitsToBytes. Bit i goes to byte i // 8, position i % 8."""
    if len(b) % 8:
        raise ValueError("bit list length must be a multiple of 8")
    B = bytearray(len(b) // 8)
    for i, bit in enumerate(b):
        B[i // 8] += bit << (i % 8)
    return bytes(B)


def bytes_to_bits(B: bytes) -> list[int]:
    """Algorithm 4: BytesToBits."""
    b = []
    for byte in B:
        for _ in range(8):
            b.append(byte & 1)
            byte >>= 1
    return b


# ---------------------------------------------------------------------------
# Algorithms 5 and 6: ByteEncode_d / ByteDecode_d
# ---------------------------------------------------------------------------

def _modulus(d: int) -> int:
    """m = 2^d for d < 12, and m = q for d = 12."""
    if not 1 <= d <= 12:
        raise ValueError(f"d must be in 1..12, got {d}")
    return Q if d == 12 else 1 << d


def byte_encode_ref(F: list[int], d: int) -> bytes:
    """Algorithm 5, written exactly as in the spec (reference for tests)."""
    _modulus(d)
    b = [0] * (N * d)
    for i in range(N):
        a = F[i]
        for j in range(d):
            b[i * d + j] = a & 1
            a = (a - b[i * d + j]) // 2
    return bits_to_bytes(b)


def byte_decode_ref(B: bytes, d: int) -> list[int]:
    """Algorithm 6, written exactly as in the spec (reference for tests)."""
    m = _modulus(d)
    b = bytes_to_bits(B)
    return [sum(b[i * d + j] << j for j in range(d)) % m for i in range(N)]


def byte_encode(F: list[int], d: int) -> bytes:
    """Algorithm 5: ByteEncode_d, 256 d-bit integers -> 32*d bytes.

    Packs the coefficients into one big integer (coefficient i at bit
    offset i*d, LSB first) -- same output as the bit-list version, faster.
    """
    m = _modulus(d)
    if len(F) != N:
        raise ValueError(f"expected {N} coefficients, got {len(F)}")
    acc = 0
    for i, a in enumerate(F):
        if not 0 <= a < m:
            raise ValueError(f"coefficient {a} out of range for d={d}")
        acc |= a << (i * d)
    return acc.to_bytes(32 * d, "little")


def byte_decode(B: bytes, d: int) -> list[int]:
    """Algorithm 6: ByteDecode_d, 32*d bytes -> 256 integers.

    For d = 12 each value is reduced mod q, so a 12-bit value in [q, 4096)
    decodes to something different from what was encoded. ML-KEM's
    encapsulation-key check (Section 7.2) relies on exactly this.
    """
    m = _modulus(d)
    if len(B) != 32 * d:
        raise ValueError(f"expected {32 * d} bytes, got {len(B)}")
    acc = int.from_bytes(B, "little")
    mask = (1 << d) - 1
    return [((acc >> (i * d)) & mask) % m for i in range(N)]


# ---------------------------------------------------------------------------
# Compress_d / Decompress_d (equations 4.7 and 4.8), d < 12
# ---------------------------------------------------------------------------

def compress(x: int, d: int) -> int:
    """Compress_d(x) = round((2^d / q) * x) mod 2^d, with 1/2 rounded up.

    round(a / q) = floor((a + q/2) / q). With q odd, (a + (q-1)/2) // q gives
    the same answer, since a / q is never exactly k + 1/2 for integer a.
    """
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress(y: int, d: int) -> int:
    """Decompress_d(y) = round((q / 2^d) * y), with 1/2 rounded up."""
    return (y * Q + (1 << (d - 1))) >> d


def compress_poly(f: list[int], d: int) -> list[int]:
    return [compress(x, d) for x in f]


def decompress_poly(f: list[int], d: int) -> list[int]:
    return [decompress(y, d) for y in f]
