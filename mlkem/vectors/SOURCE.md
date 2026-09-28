# NIST ACVP test vectors for ML-KEM (FIPS 203)

| File | Upstream path (usnistgov/ACVP-Server, branch master) | Last upstream commit touching file |
|---|---|---|
| `keygen.json` | `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` | `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` (2026-04-16) |
| `encapdecap.json` | `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` | `ad33b3d9504491767f1aa76382464f3b3fa2359e` (2026-07-28) |

Downloaded 2026-09-28 via the jsDelivr mirror
(`https://cdn.jsdelivr.net/gh/usnistgov/ACVP-Server@master/gen-val/json-files/...`)
because raw.githubusercontent.com was unreachable from our network.

Contents (240 cases): keyGen 3 x 25, encapsulation 3 x 25, decapsulation 3 x 10
(valid + modified ciphertexts), encapsulation-key check 3 x 10,
decapsulation-key check 3 x 10. Used by `tests/test_acvp.py`.
