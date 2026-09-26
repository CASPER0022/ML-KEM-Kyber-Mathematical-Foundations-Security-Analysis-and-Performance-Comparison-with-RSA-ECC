# Step 09 — Optimized Library Backend: liboqs (Day 5–7, in parallel)

## Goal
Get a production-grade (C, optimized) ML-KEM running, so the performance comparison with RSA/ECC is **fair** (C vs C, not pure Python vs C). Then cross-check it against your Track 1 implementation.

## ✅ Already available: pyca/cryptography 50.0.1 (found in Step 01)
`cryptography.hazmat.primitives.asymmetric.mlkem` has `MLKEM768PrivateKey` / `MLKEM1024PrivateKey`
(`generate`, `from_seed_bytes`, `decapsulate`, `public_key().encapsulate()` → `(K, c)`).
`private_bytes_raw()` returns the 64-byte seed `d ‖ z`, so `from_seed_bytes(d + z)` enables a
**byte-for-byte** comparison with our `keygen_internal(d, z)`. **ML-KEM-512 is not supported**, so we still
want liboqs for full 512/768/1024 benchmark coverage.

## Option A (for 512 + cycle counts): `liboqs-python`
The Open Quantum Safe project: `open-quantum-safe/liboqs` (C library) plus `open-quantum-safe/liboqs-python` (wrapper, module name `oqs`).

**Windows build steps (outline; follow the current README of both repos):**
1. Install **CMake**, and either **Visual Studio Build Tools** (C++ workload) or use your MinGW gcc with `-G "MinGW Makefiles"` / Ninja
2. Build liboqs as a **shared library**:
   ```bash
   git clone --depth 1 https://github.com/open-quantum-safe/liboqs
   cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
   cmake --build liboqs/build --parallel 8
   cmake --install liboqs/build     # note the install prefix
   ```
3. Install the Python wrapper into your venv: `python -m pip install git+https://github.com/open-quantum-safe/liboqs-python`
4. Point it at the DLL (see the README: the install directory must be on `PATH`, or set the env var it documents)

**Smoke test:**
```python
import oqs
print([a for a in oqs.get_enabled_kem_mechanisms() if "ML-KEM" in a])
with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    ek = kem.generate_keypair()
    c, K1 = kem.encap_secret(ek)
    K2 = kem.decap_secret(c)
    assert K1 == K2
```

Bonus: liboqs also builds `speed_kem` and `test_kem` executables (drop `-DOQS_BUILD_ONLY_LIB=ON`). `speed_kem` prints ops/sec and **CPU cycles**, which is useful for Step 10.

## Option B (fallbacks, if liboqs won't build on Windows)
- **WSL (Ubuntu)**: liboqs builds cleanly on Linux, and cycle counting works better there. Many students end up here. Run *all* benchmarks (RSA/ECC too) in the same environment so the comparison stays fair.
- **pyca/cryptography**: recent versions have been adding post-quantum KEMs. Check whether your installed version exposes ML-KEM (`python -c "import cryptography; print(cryptography.__version__)"`, then check its docs). If it does, it's the easiest option, since RSA/ECC come from the same library.
- Other PyPI wrappers exist (search "ml-kem" / "pqcrypto"). Check that they're maintained and that they implement **final FIPS 203** (not the older "Kyber round 3", whose outputs differ).

## Cross-check Track 1 vs Track 2
- **Minimum:** keys from one implementation work with the other:
  `ek` from liboqs → `encaps` with **your** code → `decap_secret` with liboqs → same K. And the reverse direction.
- **Stronger:** if the library supports deterministic keygen from a seed (liboqs has `generate_keypair_seed` in newer versions, check), compare byte-for-byte with your `keygen_internal(d, z)`.

Interop between two independent implementations is strong evidence. Put it in the report.

## ✅ Done when
- [ ] liboqs ML-KEM-512/768/1024 round-trip in Python
- [ ] Interop test passes in both directions (`tests/test_interop.py`, skipped automatically if `oqs` isn't installed)
- [ ] You've written down the exact library version and commit hash (for reproducibility in the report)
