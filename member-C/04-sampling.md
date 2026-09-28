# Step 04 — Sampling: SampleNTT and SamplePolyCBD (Day 3)

**File:** `src/mlkem/sampling.py`
**Spec:** FIPS 203 §4.2.2, Algorithms 7 and 8

---

## Alg 7 `SampleNTT(B)` → one polynomial **already in the NTT domain**

Input `B` is 34 bytes: `ρ ‖ j ‖ i` (32-byte seed plus two index bytes).
It generates the public matrix entries `Â[i][j]` uniformly mod q by **rejection sampling**:

```
stream = SHAKE128(B)
while fewer than 256 coefficients:
    take 3 bytes C0, C1, C2
    d1 = C0 + 256 * (C1 % 16)       # 12 bits
    d2 = C1 // 16 + 16 * C2         # 12 bits
    if d1 < q: accept d1
    if d2 < q and still need more: accept d2
```

Notes:
- Each 12-bit candidate is accepted with probability 3329/4096 ≈ 81%.
- **Index order:** K-PKE calls `SampleNTT(ρ ‖ j ‖ i)` for `Â[i][j]`, so **j comes first**. If you swap i and j you get `Âᵀ` and nothing matches the test vectors. Double-check this against Alg 13 line 5.
- Because of the Python XOF issue (Step 03), request ~504 bytes and retry with more if needed.

## Alg 8 `SamplePolyCBD_η(B)` → one noise polynomial (normal domain)

Input: `64·η` bytes (from `PRF_η`). Output: 256 coefficients from the **centered binomial distribution** on `[-η, η]`, stored mod q.

```
b = BytesToBits(B)
for i in 0..255:
    x = sum(b[2iη + j]      for j in 0..η-1)
    y = sum(b[2iη + η + j]  for j in 0..η-1)
    f[i] = (x - y) mod q
```

**Why CBD?** It approximates a discrete Gaussian (what the LWE hardness proofs assume) but only needs bit counting. That makes it fast and easy to make constant-time. Ask Member A to connect this to the LWE error distribution in the math section.

---

## Tests (`tests/test_sampling.py`)

- [x] `SampleNTT` returns exactly 256 values, all in `[0, q)`, and is deterministic for the same input
- [x] `SampleNTT(ρ‖j‖i) != SampleNTT(ρ‖i‖j)` for i ≠ j (sanity check that the order matters)
- [x] `SamplePolyCBD_η` values mapped to centered form (`v if v <= q//2 else v - q`) all lie in `[-η, η]`
- [x] **Distribution check (nice chart for the report!):** over 10,000 random samples with η=2, the histogram of centered values ≈ `[1, 4, 6, 4, 1] / 16` for `-2..2`. For η=3: `[1,6,15,20,15,6,1] / 64`.
- [x] Input length check: raise an error if `len(B) != 64*η`

## ✅ Done when all tests pass. Next: Step 05 (the hardest one; budget time for it).
