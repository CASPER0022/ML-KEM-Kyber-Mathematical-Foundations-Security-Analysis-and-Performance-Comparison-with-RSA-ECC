"""ML-KEM: Fujisaki-Okamoto transform over K-PKE, plus the public API.

FIPS 203, Section 6 (Algorithms 16-18, deterministic internal functions) and
Section 7 (Algorithms 19-21, randomized public API with input checks).

NOT constant-time: Python cannot guarantee it. hmac.compare_digest is used
for the re-encryption check, but the surrounding code still branches and
allocates on secret data. See the report's limitations section.
"""
import hmac
import os

from . import kpke
from .encoding import byte_decode, byte_encode
from .hashes import G, H, J
from .params import Params


# ---------------------------------------------------------------------------
# Internal (deterministic) algorithms -- these are what the NIST vectors test
# ---------------------------------------------------------------------------

def keygen_internal(p: Params, d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """Algorithm 16: ML-KEM.KeyGen_internal(d, z) -> (ek, dk)."""
    if len(z) != 32:
        raise ValueError(f"z must be 32 bytes, got {len(z)}")
    ek_pke, dk_pke = kpke.keygen(d, p)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z  # 384k + (384k + 32) + 32 + 32 = 768k + 96
    return ek, dk


def encaps_internal(p: Params, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Algorithm 17: ML-KEM.Encaps_internal(ek, m) -> (K, c)."""
    if len(m) != 32:
        raise ValueError(f"m must be 32 bytes, got {len(m)}")
    K, r = G(m + H(ek))
    c = kpke.encrypt(ek, m, r, p)
    return K, c


def decaps_internal(p: Params, dk: bytes, c: bytes) -> bytes:
    """Algorithm 18: ML-KEM.Decaps_internal(dk, c) -> K.

    Decrypts, re-encrypts, and compares. On mismatch returns the pseudorandom
    K_bar = J(z || c) instead of an error (implicit rejection).
    """
    k = p.k
    dk_pke = dk[0:384 * k]
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m_prime = kpke.decrypt(dk_pke, c, p)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = kpke.encrypt(ek_pke, m_prime, r_prime, p)
    if not hmac.compare_digest(c, c_prime):
        K_prime = K_bar
    return K_prime


# ---------------------------------------------------------------------------
# Input checks (Sections 7.2 and 7.3)
# ---------------------------------------------------------------------------

def check_ek(p: Params, ek: bytes) -> None:
    """Section 7.2: encapsulation key type check and modulus check."""
    if len(ek) != p.ek_size:
        raise ValueError(f"ek must be {p.ek_size} bytes, got {len(ek)}")
    t_bytes = ek[:384 * p.k]
    for i in range(p.k):
        chunk = t_bytes[384 * i:384 * (i + 1)]
        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            raise ValueError("ek modulus check failed: a coefficient is >= q")


def check_ciphertext(p: Params, c: bytes) -> None:
    """Section 7.3, check 1: ciphertext type check."""
    if len(c) != p.ct_size:
        raise ValueError(f"c must be {p.ct_size} bytes, got {len(c)}")


def check_dk(p: Params, dk: bytes) -> None:
    """Section 7.3, checks 2 and 3: dk type check and hash check."""
    if len(dk) != p.dk_size:
        raise ValueError(f"dk must be {p.dk_size} bytes, got {len(dk)}")
    k = p.k
    if H(dk[384 * k:768 * k + 32]) != dk[768 * k + 32:768 * k + 64]:
        raise ValueError("dk hash check failed: stored H(ek) does not match ek")


def check_decaps_inputs(p: Params, dk: bytes, c: bytes) -> None:
    """Section 7.3: all decapsulation input checks."""
    check_ciphertext(p, c)
    check_dk(p, dk)


# ---------------------------------------------------------------------------
# Public API (Algorithms 19-21) -- randomness from the OS CSPRNG
# ---------------------------------------------------------------------------

def keygen(p: Params) -> tuple[bytes, bytes]:
    """Algorithm 19: ML-KEM.KeyGen() -> (ek, dk)."""
    d, z = os.urandom(32), os.urandom(32)
    return keygen_internal(p, d, z)


def encaps(p: Params, ek: bytes) -> tuple[bytes, bytes]:
    """Algorithm 20: ML-KEM.Encaps(ek) -> (K, c). Raises ValueError on a bad ek."""
    check_ek(p, ek)
    m = os.urandom(32)
    return encaps_internal(p, ek, m)


def decaps(p: Params, dk: bytes, c: bytes) -> bytes:
    """Algorithm 21: ML-KEM.Decaps(dk, c) -> K. Raises ValueError on bad inputs.

    A tampered (but well-formed) ciphertext does NOT raise: it yields J(z || c).
    """
    check_decaps_inputs(p, dk, c)
    return decaps_internal(p, dk, c)
