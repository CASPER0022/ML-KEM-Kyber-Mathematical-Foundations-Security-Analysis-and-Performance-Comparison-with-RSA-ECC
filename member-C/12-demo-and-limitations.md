# Step 12 — Live Demo, Limitations, Backup (Day 12–14)

## 1. Live demo script (`demo/demo.py`)

The goal is a 3–4 minute terminal demo that runs **our own** implementation, with timings on screen.

Suggested flow (use `rich` or plain prints with clear section headers):

1. **Choose a parameter set** (default ML-KEM-768, NIST's recommended default)
2. **KeyGen:** show `len(ek)`, `len(dk)`, first 32 hex chars of `ek`, time taken
3. **Encaps (Alice):** show `len(c)`, the shared key `K_alice` in hex, time taken
4. **Decaps (Bob):** show `K_bob`, time taken → big green **"KEYS MATCH ✔"**
5. **Tamper attack:** flip one bit of `c` → decaps gives a *different, random-looking* key, and **no error is raised**. Explain implicit rejection (the FO transform) in one sentence
6. **Use the key:** encrypt a message with AES-GCM using `K` (from `cryptography`) and decrypt it on the other side. This shows what a KEM is actually for
7. **Mini benchmark:** 100 runs each of ML-KEM (liboqs) vs RSA-3072 vs X25519, as a live table
8. (Optional) Run `pytest tests/test_acvp.py -q` live: "all NIST vectors pass"

CLI flags: `--params 512|768|1024`, `--impl python|liboqs`, `--fast` (skip the benchmark).

## 2. Rehearsal checklist
- [ ] Demo runs from a **fresh terminal** with one command (write it on a sticky note)
- [ ] Works **offline** (vectors committed, no pip installs during the demo)
- [ ] Font size large, terminal dark theme, window pre-sized
- [ ] You can answer these likely faculty questions:
  - Why is the NTT possible with q = 3329? (256 | q − 1)
  - What happens if decryption fails? (Implicit rejection; failure rate ≈ 2^-139 to 2^-175)
  - Why re-encrypt in Decaps? (FO transform → IND-CCA; B's section)
  - Why is ML-KEM-768 the default? (Category 3 margin; FIPS 203 §8)
  - Is your implementation secure for real use? (**No**, see limitations)

## 3. Backup plan
- [ ] Screen recording of a full successful demo run (OBS / Win+Alt+R Xbox Game Bar)
- [ ] Screenshots of each demo stage placed in the slide deck appendix
- [ ] Code + venv `requirements.txt` on a USB drive and in the git repo
- [ ] A second laptop (a teammate's) tested with the same repo

## 4. Honest limitations section (your part of the report)
Faculty specifically value this. Draft these points:

- **Not constant-time.** Python big-int arithmetic, `%`, list indexing, `!=` on bytes, and the rejection-sampling loop all have data-dependent timing. That means it's vulnerable in principle to **timing side-channels** (cf. KyberSlash, 2024, which hit even C implementations through division timing).
- **No side-channel / fault-attack countermeasures** (no masking, no power-analysis resistance).
- **No secure memory handling:** secrets aren't zeroized, and Python can't guarantee it anyway.
- **Performance:** the pure-Python track is orders of magnitude slower than optimized C/AVX2. We used liboqs for the fair comparison.
- **Benchmark scope:** a single machine, OS scheduler noise, Python-level memory measurements only, cycle counts estimated (unless measured with `speed_kem`).
- **Validated functionally** against NIST ACVP vectors, but **not** formally verified or CMVP-certified.
- **Hybrid modes** (e.g. X25519 + ML-KEM, as deployed in TLS) are discussed but not implemented.

## 5. Your sections in the final report
- **Methodology → Implementation:** architecture diagram (the layer map from Step 02), design choices, testing strategy (unit → round-trip → ACVP → interop)
- **Methodology → Benchmark setup:** machine specs, versions, harness, fairness decisions (Step 10 §1)
- **Results:** share with D (charts from Step 11)
- **Limitations:** from §4 above
- **Appendix:** how to run the code, test output screenshot

## ✅ Done when
- [ ] Full dry run done on Day 13 with team feedback applied
- [ ] Backup recording + screenshots ready on Day 14
