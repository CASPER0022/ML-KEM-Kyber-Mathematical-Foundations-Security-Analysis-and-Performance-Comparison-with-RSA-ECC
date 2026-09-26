"""ML-KEM parameter sets (FIPS 203, Section 8, Tables 2 and 3)."""
from dataclasses import dataclass

N = 256        # polynomial degree: R_q = Z_q[X] / (X^256 + 1)
Q = 3329       # prime modulus, q = 13 * 256 + 1
ZETA = 17      # primitive 256-th root of unity mod q (FIPS 203, Section 4.3)


@dataclass(frozen=True)
class Params:
    """One ML-KEM parameter set (FIPS 203, Table 2)."""

    name: str
    k: int      # module rank: vectors have k polynomials, matrix A is k x k
    eta1: int   # CBD noise width for s, e (KeyGen) and y (Encrypt)
    eta2: int   # CBD noise width for e1, e2 (Encrypt)
    du: int     # compression bits for ciphertext part u
    dv: int     # compression bits for ciphertext part v
    rbg_strength: int  # required RBG security strength in bits (Section 3.3)

    # Sizes in bytes (FIPS 203, Table 3)
    @property
    def ek_size(self) -> int:
        return 384 * self.k + 32

    @property
    def dk_size(self) -> int:
        return 768 * self.k + 96

    @property
    def ct_size(self) -> int:
        return 32 * (self.du * self.k + self.dv)

    shared_secret_size = 32


ML_KEM_512 = Params("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4, rbg_strength=128)
ML_KEM_768 = Params("ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4, rbg_strength=192)
ML_KEM_1024 = Params("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5, rbg_strength=256)

PARAMS = {p.name: p for p in (ML_KEM_512, ML_KEM_768, ML_KEM_1024)}
