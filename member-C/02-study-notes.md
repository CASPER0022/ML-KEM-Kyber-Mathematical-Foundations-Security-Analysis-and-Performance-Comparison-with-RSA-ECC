# Step 02 — Study Notes: FIPS 203 Details That Affect Our Code

Companion to `02-fips203-primer.md`. Each point below cites the FIPS 203 section so you can show it to faculty.

## A. Rules from §3.3 "Requirements for ML-KEM Implementations"

| Rule | What it means for us |
|---|---|
| **K-PKE is only a component.** It "shall not be used as a stand-alone cryptographic scheme" | Our `kpke.py` is internal. The public API is only `keygen/encaps/decaps` |
| **Controlled access to `_internal` functions.** Only for testing | We expose `*_internal` **only** for NIST test vectors; the demo uses the public API |
| **Equivalent implementations are allowed.** Any steps that give identical input/output | We may use bit-shifting instead of bit arrays, a streaming XOF, etc., as long as the vectors pass |
| **Randomness from an approved RBG.** Strength ≥128/192/256 bits for 512/768/1024 | Use `os.urandom` / `secrets` (OS CSPRNG). Never `random` |
| **Input checking is mandatory** (§7.2, §7.3) | Type, modulus and hash checks go into Step 07 |
| **Destroy intermediate values** | Python can't guarantee this (GC, immutable `bytes`), so it's a **limitation** for Step 12 |
| **No floating-point arithmetic** | Compress/Decompress must be integer-only (Step 03). Already verified: our integer formulas match exact rounding for all x, d |
| Seed `(d, z)` may be stored instead of `dk` | pyca/cryptography does exactly this: `private_bytes_raw()` = 64-byte seed |

## B. Appendix B: SampleNTT loop bound
The rejection loop in SampleNTT has no fixed length. FIPS 203 says **don't bound it** if possible. If bounded, use ≥ **280 iterations** (probability of hitting that is 2^−261). **Our choice:** unbounded `while` loop. Note it as a (theoretical) timing variation in the limitations section.

## C. Appendix C: ML-KEM ≠ Kyber (important for the Kyber-paper readers on the team!)
ML-KEM outputs **differ** from CRYSTALS-Kyber round 3, so Kyber test vectors or libraries labelled "Kyber768" will **not** match ours:
1. The shared secret is fixed at **32 bytes**
2. A different FO-transform variant: **K no longer includes a hash of the ciphertext**
3. Encaps **no longer hashes `m`** before use (it relies on the approved RBG instead)
4. **Explicit input checks** were added (the modulus check on `ek`)
5. Final vs draft (ipd): **domain separation** `G(d ‖ k)` in K-PKE.KeyGen, and the matrix index order was restored to Kyber's `Â[i][j] = SampleNTT(ρ ‖ j ‖ i)`

👉 When choosing a library or reference code (Step 09), make sure it says **ML-KEM / FIPS 203 (final)**, not "Kyber" or "FIPS 203 ipd". pyca 50.0.1's `mlkem` module is final ML-KEM (the sizes already match Table 3 in `tests/test_params.py`).

## D. Algorithm → section → page (FIPS 203 PDF)

| Alg | Name | § | Page |
|---|---|---|---|
| 3–4 | BitsToBytes / BytesToBits | 4.2.1 | 20 |
| 5–6 | ByteEncode / ByteDecode | 4.2.1 | 22 |
| 7 | SampleNTT | 4.2.2 | 23 |
| 8 | SamplePolyCBD | 4.2.2 | 23 |
| 9–10 | NTT / NTT⁻¹ | 4.3 | 26 |
| 11–12 | MultiplyNTTs / BaseCaseMultiply | 4.3.1 | 27 |
| 13–15 | K-PKE KeyGen / Encrypt / Decrypt | 5 | 29–31 |
| 16–18 | ML-KEM *_internal | 6 | 32–34 |
| 19–21 | ML-KEM KeyGen / Encaps / Decaps | 7 | 35–38 |
| — | Parameter sets, Tables 2–3 | 8 | 39 |
| — | Zeta tables | App. A | 44 |

## E. "Explain in one sentence" (the Step 02 done-criteria; practice saying these out loud)

- **K-PKE vs ML-KEM:** K-PKE is a Module-LWE encryption scheme that's only IND-CPA secure; ML-KEM wraps it with the Fujisaki–Okamoto transform (re-encrypt and compare, plus implicit rejection) to get IND-CCA2 security.
- **Why NTT:** it turns polynomial multiplication in `Z_q[X]/(X^256+1)` from O(n²) into O(n log n) plus pointwise work. It exists because q = 3329 was chosen with 256 | q − 1.
- **Why compression:** dropping the low-order bits of `u` and `v` shrinks the ciphertext (e.g. 12 → 10 bits per coefficient). The rounding error it adds is just extra noise the decryption margin (q/4) can absorb.
- **What η controls:** the size of the secret/noise coefficients (range [−η, η]). Bigger η means harder LWE but more decryption noise, so a higher failure rate. ML-KEM-512 uses η1 = 3 to make up for its smaller k.

## F. Deliverables of Step 02 (done)
- `mlkem/src/mlkem/params.py`: parameter sets and size formulas
- `mlkem/tests/test_params.py`: Table 2/3, q prime, 256 | q−1, ζ = 17 primitive, pyca sizes agree
- `docs/notation.md`: shared notation for all four members (**send it to A, B and D for agreement**)
