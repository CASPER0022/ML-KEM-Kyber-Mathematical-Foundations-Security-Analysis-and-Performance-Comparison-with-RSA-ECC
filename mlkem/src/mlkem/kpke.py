"""K-PKE: the Module-LWE public-key encryption core (FIPS 203, Section 5, Algorithms 13-15).

K-PKE is only IND-CPA secure and must not be used on its own; ML-KEM (Step 07)
wraps it in the Fujisaki-Okamoto transform.
"""
from .encoding import byte_decode, byte_encode, compress_poly, decompress_poly
from .hashes import G, PRF
from .ntt import (
    inner_ntt, mat_T_vec_mul_ntt, mat_vec_mul_ntt, ntt_inv, poly_add, poly_sub,
    vec_add, vec_intt, vec_ntt,
)
from .params import Params
from .sampling import sample_ntt, sample_poly_cbd

Poly = list[int]


def gen_matrix(rho: bytes, k: int) -> list[list[Poly]]:
    """A_hat[i][j] = SampleNTT(rho || j || i) -- note j comes first (Alg 13 line 5)."""
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]


def _sample_vec(seed: bytes, eta: int, k: int, n0: int) -> list[Poly]:
    """k CBD polynomials from PRF_eta(seed, n0), ..., PRF_eta(seed, n0 + k - 1)."""
    return [sample_poly_cbd(PRF(eta, seed, n0 + i), eta) for i in range(k)]


def _encode_vec(v: list[Poly], d: int) -> bytes:
    return b"".join(byte_encode(p, d) for p in v)


def _decode_vec(B: bytes, d: int, k: int) -> list[Poly]:
    size = 32 * d
    return [byte_decode(B[i * size:(i + 1) * size], d) for i in range(k)]


def keygen(d: bytes, p: Params) -> tuple[bytes, bytes]:
    """Algorithm 13: K-PKE.KeyGen(d) -> (ek_PKE, dk_PKE)."""
    if len(d) != 32:
        raise ValueError(f"seed d must be 32 bytes, got {len(d)}")
    k = p.k
    rho, sigma = G(d + bytes([k]))  # k appended as one byte: domain separation
    A_hat = gen_matrix(rho, k)
    s = _sample_vec(sigma, p.eta1, k, 0)
    e = _sample_vec(sigma, p.eta1, k, k)
    s_hat = vec_ntt(s)
    e_hat = vec_ntt(e)
    t_hat = vec_add(mat_vec_mul_ntt(A_hat, s_hat), e_hat)  # t = A s + e: an MLWE sample
    ek = _encode_vec(t_hat, 12) + rho
    dk = _encode_vec(s_hat, 12)
    return ek, dk


def encrypt(ek: bytes, m: bytes, r: bytes, p: Params) -> bytes:
    """Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r) -> c."""
    k = p.k
    if len(ek) != 384 * k + 32:
        raise ValueError(f"ek must be {384 * k + 32} bytes, got {len(ek)}")
    if len(m) != 32 or len(r) != 32:
        raise ValueError("m and r must be 32 bytes each")
    t_hat = _decode_vec(ek[:384 * k], 12, k)
    rho = ek[384 * k:]
    A_hat = gen_matrix(rho, k)
    y = _sample_vec(r, p.eta1, k, 0)
    e1 = _sample_vec(r, p.eta2, k, k)
    e2 = sample_poly_cbd(PRF(p.eta2, r, 2 * k), p.eta2)
    y_hat = vec_ntt(y)
    u = vec_add(vec_intt(mat_T_vec_mul_ntt(A_hat, y_hat)), e1)  # A^T here
    mu = decompress_poly(byte_decode(m, 1), 1)  # bit -> 0 or 1665
    v = poly_add(poly_add(ntt_inv(inner_ntt(t_hat, y_hat)), e2), mu)
    c1 = b"".join(byte_encode(compress_poly(ui, p.du), p.du) for ui in u)
    c2 = byte_encode(compress_poly(v, p.dv), p.dv)
    return c1 + c2


def decrypt_noisy(dk: bytes, c: bytes, p: Params) -> Poly:
    """Algorithm 15 up to line 6: w = v' - NTT^-1(s_hat^T . NTT(u')).

    w = mu + small noise. Exposed separately so the noise can be measured.
    """
    k = p.k
    if len(dk) != 384 * k:
        raise ValueError(f"dk must be {384 * k} bytes, got {len(dk)}")
    if len(c) != p.ct_size:
        raise ValueError(f"c must be {p.ct_size} bytes, got {len(c)}")
    split = 32 * p.du * k
    u = [decompress_poly(x, p.du) for x in _decode_vec(c[:split], p.du, k)]
    v = decompress_poly(byte_decode(c[split:], p.dv), p.dv)
    s_hat = _decode_vec(dk, 12, k)
    return poly_sub(v, ntt_inv(inner_ntt(s_hat, vec_ntt(u))))


def decrypt(dk: bytes, c: bytes, p: Params) -> bytes:
    """Algorithm 15: K-PKE.Decrypt(dk_PKE, c) -> m."""
    w = decrypt_noisy(dk, c, p)
    return byte_encode(compress_poly(w, 1), 1)
