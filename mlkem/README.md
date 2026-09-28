# ML-KEM (FIPS 203): educational implementation and benchmarks

A pure-Python implementation of ML-KEM (Kyber), written directly from
NIST FIPS 203 and benchmarked against RSA and ECC.

> **Not for production use.** It isn't constant-time and has no side-channel
> protection. See the limitations section of the report.

## Setup (Windows, Git Bash)

```bash
cd mlkem
py -3.13 -m venv .venv            # or: /c/Python313/python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r requirements.txt
python -m pip install -e .
pytest -q
```

### Optional: liboqs (optimized C ML-KEM, Step 09)

Needs git, CMake, Ninja and a C compiler (MinGW-w64 gcc works). Builds into
`Project/liboqs/` (gitignored) and installs `liboqs-python` into the venv:

```bash
bash scripts/build_liboqs.sh
```

Without it, the interop tests and liboqs benchmarks are skipped automatically.

## Layout

| Path | Contents |
|---|---|
| `src/mlkem/` | ML-KEM implementation (params, hashes, encoding, sampling, NTT, K-PKE, ML-KEM) |
| `tests/` | Unit tests, NIST ACVP test-vector tests, interop tests |
| `vectors/` | NIST ACVP JSON test vectors |
| `bench/` | Benchmark harness (ML-KEM vs RSA vs ECC) |
| `results/` | Benchmark CSVs, machine specs, charts |
| `demo/` | Live demo script |

## References
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
