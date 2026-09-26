# Step 10 — Benchmarking (Day 8–9, with Member D)

## Goal
Real numbers **from our own machine**: ML-KEM-512/768/1024 vs RSA-2048/3072/4096 vs ECC (P-256, P-384, X25519), all measured with **one shared harness**.

## 1. Agree on a fair comparison (do this with D at the Day 7 freeze)
RSA/ECC aren't KEMs, so define KEM-equivalent operations:

| Scheme | "KeyGen" | "Encaps" | "Decaps" |
|---|---|---|---|
| ML-KEM-x | `keygen()` | `encaps(ek)` | `decaps(dk, c)` |
| RSA-n (RSA-OAEP, SHA-256) | generate key (e=65537) | encrypt a random 32-byte key | decrypt |
| ECDH (P-256/P-384/X25519) | generate static key pair | generate ephemeral key + ECDH with the static public key (ECIES-style) | ECDH with the static private key + ephemeral public key |

Security-level pairing to use in charts (NIST SP 800-57):
- ML-KEM-512 ≈ AES-128 ≈ RSA-3072 ≈ P-256/X25519
- ML-KEM-768 ≈ AES-192 ≈ RSA-7680 ≈ P-384
- ML-KEM-1024 ≈ AES-256 ≈ RSA-15360 ≈ P-521

RSA-2048 is only ≈112-bit. Say so in the report, because it's a common mistake.

## 2. Metrics (freeze this list)

| Metric | How |
|---|---|
| Time per op (µs) plus ops/sec | `time.perf_counter_ns()`; warm up, then many iterations; report **median** and IQR, not just the mean |
| Public key / ciphertext / secret-key sizes (bytes) | `len()` of the serialized form. For RSA/ECC use DER or raw encodings; say which |
| Shared-secret size | 32 bytes for ML-KEM; the ECDH output size for ECC |
| Peak memory | `tracemalloc` (Python-level allocations only; note this limit) |
| CPU cycles | liboqs `speed_kem` if built (best on Linux/WSL); otherwise estimate `time × nominal clock` and **label it as an estimate** |

## 3. Harness skeleton (`bench/harness.py`)

```python
import time, statistics, gc

def bench(fn, *, warmup=20, iters=1000, min_time_s=2.0):
    for _ in range(warmup): fn()
    gc.disable()
    samples = []
    t_end = time.perf_counter() + min_time_s
    while len(samples) < iters or time.perf_counter() < t_end:
        t0 = time.perf_counter_ns(); fn(); samples.append(time.perf_counter_ns() - t0)
    gc.enable()
    q1, med, q3 = statistics.quantiles(samples, n=4)
    return {"median_us": med/1e3, "q1_us": q1/1e3, "q3_us": q3/1e3,
            "ops_per_sec": 1e9/med, "n": len(samples)}
```

- Pure-Python ML-KEM is slow (milliseconds per op), so use fewer iterations (e.g. 100) for it.
- RSA keygen is slow and has **high variance** (prime search), so use ~50–100 iterations and show the spread.

## 4. Benchmark scripts
- `bench/bench_mlkem.py`: Track 1 (our Python) **and** Track 2 (liboqs), all 3 parameter sets
- `bench/bench_classical.py`: RSA and ECC via `cryptography` (co-owned with D)
- `bench/run_all.py`: runs everything and writes **one** tidy CSV:
  `results/bench.csv` with columns `scheme, impl, level_bits, op, median_us, q1_us, q3_us, ops_per_sec, pk_bytes, ct_bytes, sk_bytes, n`

## 5. Reliable measurement checklist
- [ ] Laptop **plugged in**, Windows power mode "Best performance", other apps closed
- [ ] Run each suite **3 times**, confirm the results are stable (note the variance)
- [ ] Record Python, `cryptography`, and liboqs versions plus `results/machine.txt` in the CSV header or a JSON sidecar
- [ ] Never compare Python-ML-KEM against C-RSA without labelling it as such

## 6. Extra experiments (cheap, and they look good in the report)
- Time breakdown inside ML-KEM (Python track): how much goes to SampleNTT/Â generation vs NTT vs hashing (`cProfile`)
- NTT vs schoolbook multiplication speedup (from Step 05)
- Decryption-noise histogram vs the q/4 bound (from Step 06)
- Handshake-style total: keygen + encaps + decaps, and bytes on the wire (pk + ct), per scheme

## ✅ Done when
- [ ] `results/bench.csv` complete for all schemes/ops, reviewed with D
- [ ] Numbers sanity-checked: liboqs ML-KEM encaps/decaps should be in the **tens of µs** range, much faster than RSA decrypt (ms). RSA **encrypt** is very fast (small e). ECDH is in between. If you see something wildly different, investigate before trusting it.
