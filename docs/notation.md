# Shared Notation: ML-KEM Project

**Purpose:** everyone (A: math, B: scheme, C: code, D: report/slides) uses the **same symbols**, so the report and slides read as one document. Based on FIPS 203 §2. If you want to change something, say so in the group chat *before* using a different symbol.

## Rings and numbers

| Symbol | Meaning | In code |
|---|---|---|
| `n = 256` | polynomial degree | `N` |
| `q = 3329` | prime modulus | `Q` |
| `Z_q` | integers mod q, stored in `[0, q)` | `int` |
| `R_q = Z_q[X]/(X^n + 1)` | polynomial ring. Multiplication wraps around with `X^256 = −1` ("negacyclic") | `list[int]` of length 256 |
| `T_q` | NTT domain: same size as `R_q`, but multiplication is pointwise on pairs | `list[int]`, name ends in `_hat` |
| `ζ = 17` | primitive 256-th root of unity mod q | `ZETA` |
| `k` | module rank (2, 3, 4) | `p.k` |
| `R_q^k`, `R_q^{k×k}` | vectors / matrices of polynomials | `list[list[int]]`, `list[list[list[int]]]` |

## Typography
- **Bold lowercase** = vector (`𝐬`, `𝐞`, `𝐭`, `𝐲`, `𝐮`), **bold uppercase** = matrix (`𝐀`). In plain text and code we just write `s`, `A`.
- Hat `â` = the NTT representation of `a` (`a_hat` in code).
- `𝐀ᵀ` = transpose, `𝐬ᵀ𝐮` = inner product (a polynomial).
- `∘` = multiplication in the NTT domain (`MultiplyNTTs`).
- `‖` = byte-string concatenation.
- `⌈x⌋` = round to nearest, with ½ rounded **up**. `⌊x⌋` = floor.
- `x mod± q` = centered representative in `[−(q−1)/2, (q−1)/2]` (used when talking about "small" noise).
- `B^ℓ` = byte strings of length ℓ; `𝔹 = {0,…,255}`.

## Scheme names (use exactly these)

| Name | What it is | Security |
|---|---|---|
| **K-PKE** | inner public-key encryption (FIPS 203 §5) | IND-CPA only, never used alone |
| **ML-KEM** | the KEM = K-PKE + Fujisaki–Okamoto transform (§6–7) | IND-CCA2 |
| **ML-KEM-512/768/1024** | parameter sets (NIST categories 1/3/5) | |
| **Kyber / CRYSTALS-Kyber** | the round-3 submission ML-KEM came from. **Not byte-compatible** with ML-KEM | |

## Keys and values

| Symbol | Meaning | Size (bytes) |
|---|---|---|
| `ek` | encapsulation key (public) | 384k + 32 |
| `dk` | decapsulation key (secret) = `dk_PKE ‖ ek ‖ H(ek) ‖ z` | 768k + 96 |
| `c` | ciphertext = `c1 ‖ c2` (compressed `u`, `v`) | 32(d_u·k + d_v) |
| `K` | shared secret key | 32 |
| `d, z` | 32-byte random seeds for KeyGen (`z` is used for implicit rejection) | 32 each |
| `m` | 32-byte random message chosen in Encaps | 32 |
| `ρ` (rho) | public seed that expands to matrix `Â` | 32 |
| `σ` (sigma) | secret seed that expands to noise `s`, `e` | 32 |
| `r` | encryption randomness, `(K, r) = G(m ‖ H(ek))` | 32 |
| `s` | secret vector (the LWE secret) | |
| `e, e1, e2, y` | small noise from `CBD_η` | |
| `t = As + e` | public vector (**the Module-LWE sample**) | |
| `η1, η2` | noise widths | |
| `d_u, d_v` | compression bit widths for `u`, `v` | |

## Hash functions (FIPS 203 §4.1)
`H` = SHA3-256, `J` = SHAKE256→32 B, `G` = SHA3-512 split 32/32, `PRF_η` = SHAKE256→64η B, `XOF` = SHAKE128.

## Security terms (for A, B and D)
- **LWE / Module-LWE (MLWE):** given `(A, t = As + e)`, find `s` (search) or tell `t` apart from uniform (decision).
- **IND-CPA / IND-CCA2:** as in Katz–Lindell. Always write "IND-CCA2", not just "CCA".
- **Security categories 1/3/5:** at least as hard to break as AES-128/192/256 key search (FIPS 203 §8). Avoid claiming "exactly X bits".
- **Decapsulation failure rate:** 2^−138.8 / 2^−164.8 / 2^−174.8 (FIPS 203 Table 1).
