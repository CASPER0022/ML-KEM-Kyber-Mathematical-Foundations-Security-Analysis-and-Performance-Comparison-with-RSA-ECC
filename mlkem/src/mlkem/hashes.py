"""Hash functions and XOF (FIPS 203, Section 4.1)."""
import hashlib


def H(s: bytes) -> bytes:
    """H(s) = SHA3-256(s), 32 bytes."""
    return hashlib.sha3_256(s).digest()


def J(s: bytes) -> bytes:
    """J(s) = SHAKE256(s, 8 * 32), 32 bytes."""
    return hashlib.shake_256(s).digest(32)


def G(c: bytes) -> tuple[bytes, bytes]:
    """G(c) = SHA3-512(c), split into two 32-byte halves (a, b)."""
    out = hashlib.sha3_512(c).digest()
    return out[:32], out[32:]


def PRF(eta: int, s: bytes, b: int) -> bytes:
    """PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta), 64 * eta bytes.

    s is a 32-byte seed and b is a single byte (0..255).
    """
    if eta not in (2, 3):
        raise ValueError(f"eta must be 2 or 3, got {eta}")
    if len(s) != 32:
        raise ValueError(f"PRF seed must be 32 bytes, got {len(s)}")
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def XOF(rho: bytes, i: int, j: int, n: int) -> bytes:
    """First n bytes of SHAKE128(rho || i || j).

    hashlib's SHAKE does not stream, so callers ask for n bytes and ask again
    with a larger n if they run out. The output for a smaller n is always a
    prefix of the output for a larger n, so this matches a streaming XOF.
    """
    if len(rho) != 32:
        raise ValueError(f"XOF seed must be 32 bytes, got {len(rho)}")
    return hashlib.shake_128(rho + bytes([i, j])).digest(n)
