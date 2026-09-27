# Step 03 — Hash Functions, Encoding, Compression (Day 3)

**Files:** `src/mlkem/params.py`, `src/mlkem/hashes.py`, `src/mlkem/encoding.py`
**Spec:** FIPS 203 §4.1 (hashes), §4.2.1 (Alg 3–6, Compress/Decompress)

---

## 3a. `params.py`

✅ **Already done in Step 02**: `Params` dataclass, `ML_KEM_512/768/1024`, `N`, `Q`, `ZETA`, size properties (`ek_size`, `dk_size`, `ct_size`), and tests in `tests/test_params.py`.

---

## 3b. `hashes.py` (FIPS 203 §4.1)

| Name | Definition | Output |
|---|---|---|
| `H(s)` | SHA3-256(s) | 32 bytes |
| `J(s)` | SHAKE256(s, 32 bytes) | 32 bytes |
| `G(c)` | SHA3-512(c), split into `(first 32, last 32)` | two 32-byte values |
| `PRF(eta, s, b)` | SHAKE256(s ‖ b, 64·η bytes), where `s` is 32 bytes and `b` is **one byte** | 64η bytes |
| `XOF(rho, i, j)` | SHAKE128(ρ ‖ i ‖ j), a byte stream | as many bytes as needed |

All of these are in `hashlib`: `sha3_256`, `sha3_512`, `shake_128`, `shake_256`.

⚠️ **XOF in Python:** `hashlib.shake_128(...).digest(n)` doesn't stream. It returns the first `n` bytes. That's fine: ask for enough bytes (e.g. 3·168 = 504), and if SampleNTT runs out, ask again for a larger `n`. The first `n` bytes are always the same, so this gives the same result as a streaming XOF.

---

## 3c. `encoding.py` (Alg 3–6)

### Alg 3 `BitsToBytes(b)` / Alg 4 `BytesToBits(B)`
Bit `i` goes to byte `i // 8`, at position `i % 8` (**LSB first**).
Quick test: `BytesToBits(b'\x01')` → `[1,0,0,0,0,0,0,0]`.

### Alg 5 `ByteEncode_d(F)` → `32·d` bytes
Each of the 256 integers is written as `d` bits, LSB first, then everything goes through BitsToBytes.
- For `d < 12`, each value is `< 2^d`.
- For `d = 12`, each value is `< q`.

### Alg 6 `ByteDecode_d(B)` → 256 ints
The inverse. For `d = 12`, reduce each value **mod q**. (This matters for the modulus check in Step 07.)

> You don't have to go through a bit list; bit-shifting into a big int is faster. But write the direct version first and keep it as a reference for tests.

### Compress / Decompress (§4.2.1, eq. 4.7 and 4.8)

```
Compress_d(x)   = round( (2^d / q) · x ) mod 2^d
Decompress_d(y) = round( (q / 2^d) · y )
```

Use **integer-only** arithmetic. Floats cause off-by-one errors at the rounding boundaries:

```python
def compress(x, d):   return ((x << d) + Q // 2) // Q % (1 << d)
def decompress(y, d): return (y * Q + (1 << (d - 1))) >> d
```

(Check the rounding convention yourself: FIPS 203 rounds ½ up. Go through a couple of edge values by hand and write them in your notes. This is a nice "derivation by hand" to show faculty.)

---

## Tests (`tests/test_encoding.py`)

- [x] `BytesToBits(BitsToBytes(bits)) == bits` for random bit lists (length a multiple of 8)
- [x] For each `d` in `1..12`: `ByteDecode_d(ByteEncode_d(F)) == F` for random valid `F`
- [x] `len(ByteEncode_d(F)) == 32*d`
- [x] `ByteDecode_12` of bytes that encode 4095 returns `4095 % 3329`
- [x] Compress/decompress error bound: for all `x` in `[0, q)`,
      `|decompress(compress(x,d),d) − x| mod± q  ≤  round(q / 2^(d+1))`
      (a centered difference; this is the error that K-PKE decryption has to tolerate)
- [x] `H(b'')` equals `hashlib.sha3_256(b'').digest()` (trivial, but catches wiring errors)

## ✅ Done when all tests pass. Next: Step 04.
