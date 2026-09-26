# Step 06 — K-PKE: the Module-LWE Encryption Core (Day 4)

**File:** `src/mlkem/kpke.py`
**Spec:** FIPS 203 §5, Algorithms 13–15

K-PKE is **IND-CPA secure only**, so it must never be used on its own. Step 07 wraps it in the FO transform to get IND-CCA security. Member B explains this part in the report.

---

## Shared helper: generate `Â` from `ρ`

```
for i in 0..k-1:
    for j in 0..k-1:
        Â[i][j] = SampleNTT(ρ ‖ byte(j) ‖ byte(i))
```

## Alg 13 `K-PKE.KeyGen(d)`, where `d` is a 32-byte seed

```
(ρ, σ) = G(d ‖ byte(k))        # ← k is appended as ONE byte (domain separation, final FIPS 203)
N = 0
Â = gen_matrix(ρ)
for i in 0..k-1:  s[i] = SamplePolyCBD_η1(PRF_η1(σ, byte(N))); N += 1
for i in 0..k-1:  e[i] = SamplePolyCBD_η1(PRF_η1(σ, byte(N))); N += 1
ŝ = NTT(s);  ê = NTT(e)
t̂ = Â ∘ ŝ + ê                   # mat_vec_mul_ntt, then add
ek_PKE = ByteEncode_12(t̂[0]) ‖ ... ‖ ByteEncode_12(t̂[k-1]) ‖ ρ     # 384k + 32 bytes
dk_PKE = ByteEncode_12(ŝ[0]) ‖ ... ‖ ByteEncode_12(ŝ[k-1])         # 384k bytes
```

**The LWE link (for your slide):** `t = A·s + e` is exactly a Module-LWE sample. Recovering `s` from `(A, t)` is the hard problem Member A describes.

## Alg 14 `K-PKE.Encrypt(ek_PKE, m, r)`, where `m` is the 32-byte message and `r` is the 32-byte randomness

```
N = 0
t̂ = ByteDecode_12 of each 384-byte chunk of ek[0 : 384k]
ρ = ek[384k : 384k + 32]
Â = gen_matrix(ρ)
for i in 0..k-1: y[i]  = SamplePolyCBD_η1(PRF_η1(r, N)); N += 1
for i in 0..k-1: e1[i] = SamplePolyCBD_η2(PRF_η2(r, N)); N += 1
e2 = SamplePolyCBD_η2(PRF_η2(r, N))
ŷ = NTT(y)
u = NTT⁻¹(Âᵀ ∘ ŷ) + e1                 # ← TRANSPOSE here
μ = Decompress_1(ByteDecode_1(m))       # each bit → 0 or ⌈q/2⌉ = 1665
v = NTT⁻¹(t̂ᵀ ∘ ŷ) + e2 + μ             # inner product
c1 = ByteEncode_du(Compress_du(u[i])) for each i
c2 = ByteEncode_dv(Compress_dv(v))
return c1 ‖ c2
```

## Alg 15 `K-PKE.Decrypt(dk_PKE, c)`

```
c1 = c[0 : 32·du·k];  c2 = c[32·du·k : ]
u' = Decompress_du(ByteDecode_du(each 32·du chunk of c1))
v' = Decompress_dv(ByteDecode_dv(c2))
ŝ  = ByteDecode_12 of each chunk of dk_PKE
w  = v' − NTT⁻¹(ŝᵀ ∘ NTT(u'))
m  = ByteEncode_1(Compress_1(w))
```

## Why decryption works (derive this by hand for the demo slide)

```
w = v − sᵀu
  = (tᵀy + e2 + μ) − sᵀ(Aᵀy + e1)
  = (sᵀAᵀ + eᵀ)y + e2 + μ − sᵀAᵀy − sᵀe1
  = μ + (eᵀy + e2 − sᵀe1) + compression errors
        └────── small noise ──────┘
```

Each coefficient of `μ` is 0 or ≈ q/2. As long as the noise stays below q/4, `Compress_1` rounds back to the right bit. The chance that it doesn't is the **decryption failure rate** (FIPS 203 lists 2^-138.8 / 2^-164.8 / 2^-174.8 for 512/768/1024).

---

## Tests (`tests/test_kpke.py`)

- [ ] Output sizes: `|ek| == 384k+32`, `|dk| == 384k`, `|c| == 32(du·k + dv)` for all 3 parameter sets
- [ ] **Round trip:** for 200 random `(d, m, r)`: `Decrypt(dk, Encrypt(ek, m, r)) == m`
- [ ] Deterministic: same `(d)` → same keys, same `(ek, m, r)` → same ciphertext
- [ ] **Experiment for the report:** track the noise term `‖w − μ‖∞` (centered) over many decryptions and plot it against the q/4 threshold. This visual shows *why* the failure rate is tiny.

## ✅ Done when all tests pass. Next: Step 07.
