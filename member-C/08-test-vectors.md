# Step 08 — Validate Against NIST Test Vectors (Day 5–7)

## Goal
Round-trip tests only prove your code is **self-consistent**. Two consistent-but-wrong implementations (e.g. i/j swapped in SampleNTT) still round-trip. Matching NIST's official vectors proves you implemented **FIPS 203**. This is the main deliverable of the Day 6–7 checkpoint.

## Where to get the vectors
NIST's ACVP server repository on GitHub: **`usnistgov/ACVP-Server`**, folder `gen-val/json-files/`:

| Folder | Tests | Uses which of your functions |
|---|---|---|
| `ML-KEM-keyGen-FIPS203/` | given `d`, `z` → expect `ek`, `dk` | `keygen_internal` |
| `ML-KEM-encapDecap-FIPS203/` | encaps: given `ek`, `m` → expect `c`, `k`<br>decaps: given `dk`, `c` → expect `k`<br>plus key-check test groups | `encaps_internal`, `decaps_internal`, input checks |

Each folder has `prompt.json` (inputs) and `expectedResults.json` (outputs), linked by `tgId` (test group) and `tcId` (test case). The **`internalProjection.json`** file contains both in one place, which is the easiest to use.

Download them into `mlkem/vectors/`:

```bash
cd mlkem/vectors
BASE=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
curl -L -o keygen.json   "$BASE/ML-KEM-keyGen-FIPS203/internalProjection.json"
curl -L -o encapdecap.json "$BASE/ML-KEM-encapDecap-FIPS203/internalProjection.json"
```

(If the path has moved, browse the repo and fix it. Commit the JSON files so the tests work offline during the demo.)

## Why the `_internal` functions matter
The public `keygen()`/`encaps()` use random bytes, so they can't be tested against fixed vectors. The deterministic `_internal` versions (with `d, z, m` passed in) can. This is exactly why FIPS 203 separates them.

## Test structure (`tests/test_acvp.py`)

**Open the JSON first and check the real field names**. Don't trust the names below blindly. The general shape:

```python
import json, pytest
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024
PARAMS = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}

def load_keygen_cases():
    data = json.load(open("vectors/keygen.json"))
    for g in data["testGroups"]:
        p = PARAMS[g["parameterSet"]]
        for t in g["tests"]:
            yield pytest.param(p, t, id=f"{g['parameterSet']}-tc{t['tcId']}")

@pytest.mark.parametrize("p,t", load_keygen_cases())
def test_keygen(p, t):
    ek, dk = keygen_internal(p, bytes.fromhex(t["d"]), bytes.fromhex(t["z"]))
    assert ek.hex().upper() == t["ek"].upper()
    assert dk.hex().upper() == t["dk"].upper()
```

Do the same for the encapDecap groups. Branch on the group's `function` field (`"encapsulation"` / `"decapsulation"` / key-check variants) and check the expected `c` and `k`, or pass/fail for the key checks.

## Debugging when a vector fails (do it in this order)
1. **keyGen fails:** compare `ρ, σ` from `G(d ‖ k)`. Did you append the `k` byte? Then compare `ek`'s last 32 bytes (that's ρ). If ρ matches but `t̂` doesn't, check SampleNTT (the i/j order), then CBD/PRF, then the NTT.
2. **keyGen passes, encaps fails:** check `Âᵀ` in Encrypt, the `N` counter sequence, Compress rounding, du/dv.
3. **encaps passes, decaps fails:** check the dk slicing offsets and implicit rejection (`J(z ‖ c)`).

Print intermediate values and compare them with a known-good implementation (Step 09's library, or the pure-Python `kyber-py` project on GitHub by Giacomo Pope as a readable reference). Compare against it, **don't copy** it.

## ✅ Checkpoint (Day 6–7): report this to the team
- [x] `pytest tests/test_acvp.py -q` → **all pass** for 512/768/1024 (240/240)
- [ ] Screenshot of the green test output (text log saved in `mlkem/results/acvp_test_output.txt`; take the screenshot yourself) for the report and slides
- [x] Short note in the report: "Our implementation passes 240/240 NIST ACVP test vectors"
