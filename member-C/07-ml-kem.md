# Step 07 — ML-KEM: FO Transform + Public API (Day 4–5)

**File:** `src/mlkem/mlkem.py`
**Spec:** FIPS 203 §6 (Alg 16–18, internal/deterministic) and §7 (Alg 19–21, public API plus input checks)

---

## Alg 16 `ML-KEM.KeyGen_internal(d, z)`

```
(ek_PKE, dk_PKE) = K-PKE.KeyGen(d)
ek = ek_PKE
dk = dk_PKE ‖ ek ‖ H(ek) ‖ z          # 384k + (384k+32) + 32 + 32 = 768k + 96 bytes
return (ek, dk)
```

## Alg 17 `ML-KEM.Encaps_internal(ek, m)`

```
(K, r) = G(m ‖ H(ek))
c = K-PKE.Encrypt(ek, m, r)
return (K, c)
```

## Alg 18 `ML-KEM.Decaps_internal(dk, c)`

```
dk_PKE = dk[0 : 384k]
ek_PKE = dk[384k : 768k + 32]
h      = dk[768k + 32 : 768k + 64]
z      = dk[768k + 64 : 768k + 96]
m'       = K-PKE.Decrypt(dk_PKE, c)
(K', r') = G(m' ‖ h)
K̄        = J(z ‖ c)                   # "fake" key for implicit rejection
c'       = K-PKE.Encrypt(ek_PKE, m', r')   # RE-ENCRYPT and compare
if c != c': K' = K̄
return K'
```

**This is the Fujisaki–Okamoto (FO) transform.** Re-encryption catches any tampered ciphertext. On failure, instead of returning an error (which would leak information), it returns a pseudorandom key `J(z‖c)`. This is **implicit rejection**. Member B owns the security argument; your code is the concrete version of it.

⚠️ In real implementations, the comparison `c != c'` and the selection of `K'` vs `K̄` **must be constant-time**. Python `!=` on bytes is not. Note this in the limitations section (Step 12). You can use `hmac.compare_digest` for the compare to show awareness, but the rest of the Python code is still not constant-time.

---

## Public API (Alg 19–21)

```python
import os

def keygen(params):                 # Alg 19
    d, z = os.urandom(32), os.urandom(32)
    return keygen_internal(params, d, z)

def encaps(params, ek):             # Alg 20
    check_ek(params, ek)            # input checks below
    m = os.urandom(32)
    return encaps_internal(params, ek, m)     # → (K, c)

def decaps(params, dk, c):          # Alg 21
    check_dk_and_c(params, dk, c)
    return decaps_internal(params, dk, c)
```

Use `os.urandom` (or `secrets.token_bytes`), a CSPRNG. **Never** use `random`.

## Input checks (§7.2, §7.3). Easy to forget, and faculty may ask about them.

**Encapsulation key (§7.2):**
1. **Type check:** `len(ek) == 384k + 32`
2. **Modulus check:** `ByteEncode_12(ByteDecode_12(ek[0:384k])) == ek[0:384k]`, i.e. every 12-bit coefficient is `< q`

**Decapsulation (§7.3):**
1. **Ciphertext type check:** `len(c) == 32(du·k + dv)`
2. **Decapsulation key type check:** `len(dk) == 768k + 96`
3. **Hash check:** `H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]`

Raise `ValueError` on failure.

---

## Tests (`tests/test_mlkem.py`)

- [ ] For all 3 parameter sets, 100 times: `K1, c = encaps(ek); K2 = decaps(dk, c); K1 == K2`, and `len(K1) == 32`
- [ ] Sizes of `ek`, `dk`, and `c` match Table 3 (Step 02)
- [ ] **Implicit rejection:** flip one bit of `c` → `decaps` returns a key `!= K1` **and** equal to `J(z ‖ c_tampered)`, without raising an exception
- [ ] **Modulus check:** craft an `ek` with a coefficient 4095 → `encaps` raises `ValueError`
- [ ] **Hash check:** corrupt the stored `H(ek)` inside `dk` → `decaps` raises `ValueError`
- [ ] Wrong lengths → `ValueError`

The implicit-rejection and tamper tests make great **live demo moments** (Step 12).

## ✅ Done when all tests pass. Next: Step 08 (prove it's actually FIPS 203 and not just self-consistent).
