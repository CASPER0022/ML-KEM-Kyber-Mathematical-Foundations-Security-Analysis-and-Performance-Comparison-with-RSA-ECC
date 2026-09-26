# Step 02 — FIPS 203 Primer for Implementers (Day 1–2)

## Goal
Know which FIPS 203 sections you'll code, and agree on notation with A and B before writing code.

## Reading order in `NIST.FIPS.203.pdf`
1. **Section 2**: notation (read carefully, especially bit/byte order conventions)
2. **Section 4**: auxiliary algorithms (Alg 3–12): hashing, encoding, sampling, NTT
3. **Section 5**: K-PKE (Alg 13–15): the IND-CPA "inner" encryption
4. **Section 6**: ML-KEM internal (Alg 16–18): the FO transform, deterministic
5. **Section 7**: ML-KEM external (Alg 19–21) plus **input checks** (type/modulus/hash checks)
6. **Section 8**: parameter sets (Table 2 and Table 3)

## Global constants

| Symbol | Value | Meaning |
|---|---|---|
| `n` | 256 | polynomial degree; ring is `R_q = Z_q[X]/(X^256 + 1)` |
| `q` | 3329 | prime modulus (`q = 13·256 + 1`, so the NTT works) |
| `ζ` | 17 | primitive 256-th root of unity mod q |

## Parameter sets (FIPS 203 Table 2 and Table 3)

| Set | k | η1 | η2 | du | dv | ek bytes | dk bytes | ct bytes | K bytes | NIST category |
|---|---|---|---|---|---|---|---|---|---|---|
| ML-KEM-512  | 2 | 3 | 2 | 10 | 4 | 800  | 1632 | 768  | 32 | 1 (≈AES-128) |
| ML-KEM-768  | 3 | 2 | 2 | 10 | 4 | 1184 | 2400 | 1088 | 32 | 3 (≈AES-192) |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 | 3168 | 1568 | 32 | 5 (≈AES-256) |

Size formulas you can use to sanity-check your code:
- `|ek| = 384·k + 32`
- `|dk| = 768·k + 96`
- `|ct| = 32·(du·k + dv)`

## Algorithm map (build bottom-up)

```
Alg 19-21  ML-KEM.KeyGen / Encaps / Decaps        (random bytes + input checks)
    │
Alg 16-18  ML-KEM.*_internal                      (FO transform, implicit rejection)
    │
Alg 13-15  K-PKE.KeyGen / Encrypt / Decrypt       (Module-LWE encryption)
    │
    ├── Alg 9-12  NTT, NTT^-1, MultiplyNTTs, BaseCaseMultiply
    ├── Alg 7-8   SampleNTT (matrix Â), SamplePolyCBD (noise)
    ├── Alg 3-6   BitsToBytes, BytesToBits, ByteEncode_d, ByteDecode_d
    └── §4.1      H, J, G, PRF, XOF (SHA-3 family)
```

**Build and test each layer before starting the next one.** Most ML-KEM bugs are in encoding or the NTT, and they're very hard to find once everything is wired together.

## Notation to agree on with A and B
- Polynomials are lists of 256 ints in `[0, q)`. Vectors are lists of `k` polynomials. The matrix `Â` is a `k×k` list of lists.
- A hat (`â`) means "in the NTT domain". In code, use the suffix `_hat`, e.g. `s_hat`.
- `‖` means byte concatenation (`+` on `bytes` in Python).
- Byte order is **little-endian bits within bytes** (Alg 3/4). This is the #1 source of bugs.

## Python conventions for our code
- Plain Python `int` lists, no numpy in the core. That keeps it readable and matches the spec line by line.
- Every function's docstring cites its FIPS 203 algorithm number, e.g. `"""FIPS 203 Algorithm 9."""`.
- Reduce mod q after every arithmetic step (`% q`), so coefficients always stay in `[0, q)`.

## ✅ Done when
- [ ] You can explain in one sentence each of: K-PKE vs ML-KEM, why NTT, why compression, what `η` controls
- [ ] Notation doc agreed with A and B (put it in the shared report draft)
