# Member C — Implementation Roadmap (ML-KEM / FIPS 203)

**Role:** Build a working ML-KEM, prove it's correct with NIST test vectors, benchmark it, and run the live demo.

## Strategy: two implementations

| Track | What | Why |
|---|---|---|
| **Track 1: from scratch** | Pure-Python ML-KEM written directly from FIPS 203 (Algorithms 3–21) | Shows you understand the scheme, and it's the demo that impresses faculty. Slow, but readable. |
| **Track 2: library** | `liboqs` (optimized C, used through `liboqs-python`) | Gives realistic performance numbers to compare against RSA/ECC. |

Both tracks are checked against the same NIST test vectors. Benchmarks report **both**: pure Python shows the algorithmic cost, and liboqs shows real-world speed. Comparing pure-Python ML-KEM against C-backed RSA would be unfair, so the report must say which is which.

## Step files

| # | File | Workflow days | Output |
|---|---|---|---|
| 01 | `01-environment-setup.md` | Day 1–2 | venv, libraries, folder layout |
| 02 | `02-fips203-primer.md` | Day 1–2 | Parameters, symbols, and a map of the algorithms |
| 03 | `03-hashes-and-encoding.md` | Day 3 | `hashes.py`, `encoding.py` (Alg 3–6, Compress/Decompress) |
| 04 | `04-sampling.md` | Day 3 | `sampling.py` (Alg 7–8) |
| 05 | `05-ntt.md` | Day 3–4 | `ntt.py` (Alg 9–12) |
| 06 | `06-k-pke.md` | Day 4 | `kpke.py` (Alg 13–15) |
| 07 | `07-ml-kem.md` | Day 4–5 | `mlkem.py` (Alg 16–21 plus input checks) |
| 08 | `08-test-vectors.md` | Day 5–7 | NIST ACVP vectors pass for all 3 parameter sets |
| 09 | `09-library-backend.md` | Day 5–7 | liboqs working and cross-checked against Track 1 |
| 10 | `10-benchmarking.md` | Day 8–9 | CSV results: time, sizes, memory, cycles |
| 11 | `11-charts-and-results.md` | Day 10–11 | Charts for the report and slides |
| 12 | `12-demo-and-limitations.md` | Day 12–14 | Live demo script, limitations section, backup |

## Target project layout

```
Project/
├── NIST.FIPS.203.pdf
├── workflow.txt
├── member-C/                 ← these guides
└── mlkem/                    ← code (created in Step 01)
    ├── src/mlkem/
    │   ├── __init__.py
    │   ├── params.py         # parameter sets (Table 2)
    │   ├── hashes.py         # H, J, G, PRF, XOF
    │   ├── encoding.py       # BitsToBytes, ByteEncode/Decode, Compress
    │   ├── sampling.py       # SampleNTT, SamplePolyCBD
    │   ├── ntt.py            # NTT, NTT^-1, MultiplyNTTs
    │   ├── kpke.py           # K-PKE (CPA-secure PKE)
    │   └── mlkem.py          # ML-KEM (CCA-secure KEM, FO transform)
    ├── tests/                # pytest unit tests + ACVP vector tests
    ├── vectors/              # NIST JSON test vectors
    ├── bench/                # benchmark scripts
    ├── results/              # CSVs + PNG charts
    └── demo/                 # live demo script
```

## Handoffs to other members

- **To B (scheme mechanics):** your `kpke.py`/`mlkem.py` code matches their algorithm walkthrough. Ask them to review Step 07 (the FO transform and implicit rejection).
- **To A (math):** the NTT and `X^256 + 1` ring code from Step 05 can go straight into the math section as a worked example.
- **To D (comparison):** agree on **one benchmark harness** (Step 10) so RSA/ECC and ML-KEM are measured the same way on the same machine.

## Definition of done (Day 7 checkpoint)

- [ ] `pytest` is green: unit tests plus **all** ACVP keyGen/encaps/decaps vectors for ML-KEM-512/768/1024
- [ ] Track 1 and Track 2 produce identical outputs for the same seeds, or Track 2 at least round-trips correctly
- [ ] Benchmark list is frozen and agreed with D
