# Member C report sections (draft): Implementation, Benchmark Setup, Results, Limitations

> Draft for the shared report. Numbers come from `mlkem/results/bench_tables.md`
> (regenerate with `python bench/run_all.py` then `python bench/plots.py`).

## 1. Methodology: Implementation

### 1.1 Two tracks
- **Track 1: our own implementation.** A pure-Python ML-KEM written directly from
  NIST FIPS 203 (`mlkem/src/mlkem/`). No third-party crypto code: only Python's
  built-in `hashlib` for SHA-3/SHAKE. Its purpose is correctness and clarity.
- **Track 2: optimized libraries** for a fair speed comparison with RSA/ECC:
  liboqs 0.16.0 (C, Open Quantum Safe) and OpenSSL 4.0 via pyca/cryptography 50.0.1.

### 1.2 Architecture (bottom-up, one module per FIPS 203 layer)

```
Alg 19-21  keygen / encaps / decaps        mlkem.py     random bytes + input checks
Alg 16-18  *_internal                      mlkem.py     FO transform, implicit rejection
Alg 13-15  K-PKE KeyGen/Encrypt/Decrypt    kpke.py      Module-LWE encryption
Alg 9-12   NTT, NTT^-1, MultiplyNTTs       ntt.py       fast polynomial multiplication
Alg 7-8    SampleNTT, SamplePolyCBD        sampling.py  matrix A and noise
Alg 3-6    ByteEncode/Decode, Compress     encoding.py  serialization
Sec 4.1    H, J, G, PRF, XOF               hashes.py    SHA-3 family
Table 2    parameter sets                  params.py    ML-KEM-512 / 768 / 1024
```

### 1.3 Design choices
- Plain Python integer lists, no numpy, so each line maps to a line of the spec.
- Every function cites its FIPS 203 algorithm number in its docstring.
- Coefficients are reduced mod q = 3329 after every step and stay in [0, q).
- The deterministic `_internal` functions are separate from the random public
  API, exactly as in FIPS 203, so they can be tested against fixed vectors.
- Randomness comes from `os.urandom` (the OS CSPRNG), never `random`.
- Input checks from FIPS 203 §7.2/§7.3 are implemented: encapsulation-key
  length and modulus check; decapsulation-key length and hash check;
  ciphertext length check.
- NTT twiddle factors are computed (`17^BitRev7(i) mod q`) and checked against
  the tables in FIPS 203 Appendix A.

### 1.4 Testing strategy (442 automated tests, all passing)

| Level | What it proves | Tests |
|---|---|---|
| Unit | each algorithm behaves as specified (hashes, encoding round trips, compression error bound, NTT round trip, NTT multiply = schoolbook multiply, CBD distribution) | ~140 |
| Round trip | K-PKE decrypts what it encrypts (200 runs); ML-KEM both sides agree on the key (300 runs); implicit rejection returns J(z‖c) | ~60 |
| **NIST ACVP vectors** | **byte-for-byte FIPS 203 compliance: 240/240 official vectors pass** (keyGen 75, encapsulation 75, decapsulation 30, key checks 60) | 240 |
| Interop | our keys/ciphertexts work with liboqs and OpenSSL in both directions; seeded key generation matches liboqs and OpenSSL byte for byte | 16 |

Round-trip tests only show the code agrees with itself. The ACVP vectors
(from NIST's `usnistgov/ACVP-Server` repository) show it implements FIPS 203.

## 2. Methodology: Benchmark setup

- **Machine:** Intel Core i5-12450HX (4 P + 4 E cores, 12 threads), 15.7 GB RAM,
  Windows 11 (10.0.26200), Python 3.13.7. Full details: `mlkem/results/machine.txt`.
- **Libraries:** liboqs 0.16.0 (commit 5a1a854b), liboqs-python 0.16.0.1,
  cryptography 50.0.1 with OpenSSL 4.0.2.
- **One harness for everything** (`bench/harness.py`): warm-up, then timing with
  `time.perf_counter_ns` and the garbage collector disabled; at least N
  iterations and at least 2 s per operation. We report the **median and IQR**,
  not the mean. The whole suite ran **3 times** and samples were pooled; the
  per-run spread is recorded in `bench.csv` (`run_spread_pct`).
- **Fair KEM mapping** for schemes that are not KEMs:

| Scheme | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM | keygen() | encaps(ek) | decaps(dk, c) |
| RSA-OAEP (SHA-256), e = 65537 | generate key | encrypt a random 32-byte key | decrypt |
| ECDH (P-256/384/521, X25519) | static key pair | ephemeral key + ECDH with static public key | ECDH with static private key |

- **Security-level pairing** (NIST SP 800-57): ML-KEM-512 ≈ AES-128 ≈ RSA-3072 ≈ P-256/X25519;
  ML-KEM-768 ≈ AES-192 ≈ RSA-7680 ≈ P-384; ML-KEM-1024 ≈ AES-256 ≈ RSA-15360 ≈ P-521.
  **RSA-2048 is only ~112-bit.** RSA-15360 was not measured (key generation takes minutes).
- **Size encodings:** ML-KEM raw FIPS 203 bytes; RSA public key DER SPKI, private key
  DER PKCS#8, ciphertext = modulus length; ECC uncompressed points (X25519 raw 32 B).
- **Cycles are estimates** (median time × 2.4 GHz base clock). liboqs' `speed_kem`
  cycle counter gives wrong values on Windows, so it was not used.
- **Memory** is `tracemalloc` peak: Python-level allocations only; memory used
  inside C libraries is invisible to it.

## 3. Results

All numbers: median of 3 pooled runs on the machine above. Full tables with
IQRs: `mlkem/results/bench_tables.md`; charts: `mlkem/results/fig1..fig7`.

### 3.1 Correctness
- **240/240 NIST ACVP vectors pass** (Fig: `results/acvp_test_output.txt`).
- Our keys and ciphertexts interoperate with liboqs and OpenSSL in both
  directions; seeded key generation is byte-identical to both.
- Decryption noise (Fig 6): over 300 decryptions per parameter set, the largest
  noise coefficient was 345 / 284 / 236 for ML-KEM-512 / 768 / 1024, i.e. at most
  41% of the q/4 = 832 failure threshold. This is why the decryption failure rate
  (2^-139 to 2^-175 per FIPS 203) is negligible.
- SamplePolyCBD output matches the centered binomial distribution (Fig 5).

### 3.2 Speed (compiled implementations, Fig 2 and Fig 3)

| Operation (µs) | ML-KEM-768 liboqs | RSA-3072 | RSA-7680 | P-384 | X25519 |
|---|---:|---:|---:|---:|---:|
| keygen | 115 | 207,895 | 7,618,685 | 1,408 | 39 |
| encaps | 118 | 52 | 321 | 2,142 | 80 |
| decaps | 52 | 2,073 | 63,524 | 882 | 35 |
| **total** | **285** | **210,020** | **7,682,529** | **4,432** | **153** |

- **ML-KEM beats RSA by orders of magnitude** in key generation (RSA-3072 ~1,800×
  slower, RSA-7680 ~66,000×) and decapsulation (RSA-3072 ~40×, RSA-7680 ~1,200×).
- **RSA encryption alone is fast** (35-320 µs, small exponent e = 65537); this is
  the one operation where RSA is competitive, and we say so.
- **ML-KEM beats NIST P-curves at matched security**: ML-KEM-768 total 285 µs vs
  P-384 4,432 µs (~15×); ML-KEM-1024 358 µs vs P-521 8,379 µs (~23×).
- **X25519 is still the fastest classical option** (153 µs total), slightly faster
  than ML-KEM-512 (237 µs) in our measurements, but it offers no quantum
  resistance, and our liboqs build used portable C (no AVX2), so ML-KEM's
  numbers are conservative.
- **Scaling (Fig 3):** from 128-bit to 256-bit security ML-KEM's cost grows only
  ~1.5×; RSA keygen grows ~37× just from 3072 to 7680 bits; P-curves grow ~40×
  from P-256 to P-521.

### 3.3 Size (Fig 1 and Fig 7): where ML-KEM loses

| Bytes | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | RSA-3072 | P-256 | X25519 |
|---|---:|---:|---:|---:|---:|---:|
| public key | 800 | 1,184 | 1,568 | 422 | 65 | 32 |
| ciphertext | 768 | 1,088 | 1,568 | 384 | 65 | 32 |
| on the wire (pk + ct) | 1,568 | 2,272 | 3,136 | 806 | 130 | 64 |

ML-KEM-768 sends ~35× more bytes than X25519 and ~2.8× more than RSA-3072.
Bandwidth, not CPU time, is the main practical cost of post-quantum key exchange.

### 3.4 Implementation matters (Fig 4)
Our pure-Python ML-KEM is **39× to 204× slower** than liboqs C for the same
algorithm (e.g. ML-KEM-768: 20.5 ms vs 0.29 ms per keygen + encaps + decaps).
Profiling (cProfile) shows where Python time goes: CBD noise sampling ~30%,
encoding/compression ~20-25%, matrix generation (SampleNTT) ~15%, NTT ~10-15%,
hashing < 1% (SHA-3 runs in C inside `hashlib`). NTT multiplication itself is
~10× faster than schoolbook multiplication even in Python (Step 05 benchmark).

### 3.5 Measurement quality
Run-to-run spread of medians was 20-100%, and IQRs are wide. Likely causes:
Windows power management and the hybrid P-core/E-core CPU. Orders of magnitude
(which is what the conclusions rely on) are stable across runs; individual
numbers should be read as ±30%. **Before final submission, rerun
`bench/run_all.py` plugged in with Windows "Best performance" mode.**

## 4. Limitations (honest assessment)

- **Not constant-time.** Python big integers, `%`, list indexing, branches and the
  rejection-sampling loop all take data-dependent time. `hmac.compare_digest` is
  used for the ciphertext comparison in Decaps, but the choice between the real
  and the rejection key is still a normal `if`. In principle this is vulnerable to
  **timing side channels** (cf. KyberSlash, 2024, which affected even C
  implementations through secret-dependent division).
- **No side-channel or fault-attack countermeasures:** no masking, no power-analysis
  resistance, no fault detection.
- **No secure memory handling:** secret keys and shared secrets are not zeroized,
  and Python cannot guarantee that anyway (immutable `bytes`, garbage collector copies).
- **Performance:** the pure-Python code is 39-204× slower than liboqs C
  (see Fig 4). That is why the RSA/ECC comparison uses liboqs and OpenSSL.
- **liboqs ran its portable C code, not AVX2:** liboqs 0.16.0 only enables its AVX2
  ML-KEM code on Linux/macOS. On Linux, ML-KEM would be faster still, so our ML-KEM
  numbers are conservative.
- **Benchmark scope:** one laptop, Windows scheduler noise on a hybrid P/E-core CPU,
  Python-call overhead included in every measurement, Python-level memory only,
  estimated (not measured) cycle counts, RSA-15360 not measured.
- **Validation, not verification:** functionally validated against 240 NIST ACVP
  vectors and two independent implementations, but **not** formally verified and
  **not** CMVP/FIPS 140-3 certified.
- **Hybrid key exchange** (e.g. X25519 + ML-KEM-768, as deployed in TLS 1.3) is
  discussed but not implemented.

## 5. Appendix: how to run

```bash
cd mlkem
source .venv/Scripts/activate            # Windows Git Bash
pytest -q                                # all tests (442)
pytest tests/test_acvp.py -q             # NIST vectors only (240)
python demo/demo.py                      # live demo (ML-KEM-768)
python demo/demo.py --impl liboqs --params 1024
python bench/run_all.py                  # full benchmark (~25 min)
python bench/plots.py                    # all charts + tables from bench.csv
bash scripts/build_liboqs.sh             # optional: build liboqs (Step 09)
```
