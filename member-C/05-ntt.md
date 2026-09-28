# Step 05 — Number-Theoretic Transform (Day 3–4)

**File:** `src/mlkem/ntt.py`
**Spec:** FIPS 203 §4.3, Algorithms 9–12, and Appendix A (precomputed zeta tables)

---

## Why the NTT?
Multiplying two polynomials in `R_q = Z_q[X]/(X^256+1)` the schoolbook way costs 256² ≈ 65k multiplications. The NTT is an FFT over `Z_q`, which brings this down to O(n log n). Because `q − 1 = 3328 = 2^8 · 13`, `Z_q` has a primitive **256-th** root of unity (ζ = 17) but **not a 512-th** one. So ML-KEM's NTT is "incomplete": it splits `X^256+1` into **128 degree-2 factors** `X² − ζ^(2·BitRev7(i)+1)` instead of 256 linear ones. This is why `BaseCaseMultiply` multiplies pairs of coefficients.

## Precompute tables (compute them yourself, then compare to FIPS 203 Appendix A)

```python
def bitrev7(i): return int(f"{i:07b}"[::-1], 2)

ZETAS  = [pow(17, bitrev7(i), Q) for i in range(128)]           # for NTT / NTT^-1
GAMMAS = [pow(17, 2*bitrev7(i) + 1, Q) for i in range(128)]     # for BaseCaseMultiply
```

Check: `ZETAS[1] == 1729` and `GAMMAS[0] == 17`.

## Alg 9 `NTT(f)` (Cooley–Tukey butterflies)

```
f̂ = copy(f); i = 1
for len in 128, 64, ..., 2:
    for start in range(0, 256, 2*len):
        zeta = ZETAS[i]; i += 1
        for j in range(start, start + len):
            t = zeta * f̂[j + len] % q
            f̂[j + len] = (f̂[j] - t) % q
            f̂[j]       = (f̂[j] + t) % q
```

## Alg 10 `NTT⁻¹(f̂)` (Gentleman–Sande butterflies)

```
f = copy(f̂); i = 127
for len in 2, 4, ..., 128:
    for start in range(0, 256, 2*len):
        zeta = ZETAS[i]; i -= 1
        for j in range(start, start + len):
            t = f[j]
            f[j]       = (t + f[j + len]) % q
            f[j + len] = zeta * (f[j + len] - t) % q
multiply every f[j] by 3303 mod q        # 3303 = 128^{-1} mod 3329
```

## Alg 11 `MultiplyNTTs(f̂, ĝ)` and Alg 12 `BaseCaseMultiply`

```
for i in 0..127:
    a0, a1 = f̂[2i], f̂[2i+1];  b0, b1 = ĝ[2i], ĝ[2i+1];  γ = GAMMAS[i]
    ĥ[2i]   = (a0*b0 + a1*b1*γ) % q
    ĥ[2i+1] = (a0*b1 + a1*b0)   % q
```

This is multiplication in `Z_q[X]/(X² − γ)`. You can derive it by hand (another "derivation by hand" for the slides).

## Vector/matrix helpers (put them here too)
- `vec_ntt(v)`, `vec_intt(v)`: apply to each polynomial
- `poly_add`, `poly_sub`
- `mat_vec_mul_ntt(Â, v̂)`: `result[i] = Σ_j MultiplyNTTs(Â[i][j], v̂[j])`
- `mat_T_vec_mul_ntt(Â, v̂)`: uses `Â[j][i]` (the transpose, needed in Encrypt)
- `inner_ntt(â, b̂)`: `Σ_j MultiplyNTTs(â[j], b̂[j])`

---

## Tests (`tests/test_ntt.py`): these are what make the NTT trustworthy

- [x] **Round trip:** `NTT⁻¹(NTT(f)) == f` for 100 random `f`
- [x] **Correctness against schoolbook multiplication.** Write a slow reference:
  ```python
  def schoolbook_mul(a, b):            # multiplication in Z_q[X]/(X^256 + 1)
      c = [0]*512
      for i in range(256):
          for j in range(256):
              c[i+j] += a[i]*b[j]
      return [(c[i] - c[i+256]) % Q for i in range(256)]   # X^256 = -1
  ```
  Check: `NTT⁻¹(MultiplyNTTs(NTT(a), NTT(b))) == schoolbook_mul(a, b)` for random a, b.
  **If this passes, your NTT is correct.**
- [x] Linearity: `NTT(a+b) == NTT(a) + NTT(b)`
- [x] Tables match FIPS 203 Appendix A

## Benchmark teaser for the report
Time `schoolbook_mul` vs the NTT-based multiply in pure Python. The speedup is a concrete number Member A can use to explain why the ring structure matters.

## ✅ Done when all tests pass. Next: Step 06.
