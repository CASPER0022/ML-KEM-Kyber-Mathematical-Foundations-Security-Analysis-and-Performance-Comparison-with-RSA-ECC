# Step 11 — Charts and Results Handoff (Day 10–11)

## Goal
Turn `results/bench.csv` into clean charts for D's results section and the slides. `bench/plots.py` reads the CSV and writes PNGs (300 dpi) to `results/`.

## Chart list

| # | Chart | Type | Message |
|---|---|---|---|
| 1 | Key + ciphertext sizes per scheme | grouped bar (log y-axis) | ML-KEM keys/ciphertexts are **bigger** than ECC, comparable to or smaller than RSA at matched security |
| 2 | Keygen / encaps / decaps time per scheme (C implementations only) | grouped bar, log y-axis, error bars = IQR | ML-KEM is fast, often faster than ECC, and far faster than RSA keygen/decrypt |
| 3 | Time vs security level (128/192/256) | line chart, one line per family | How cost scales: ML-KEM grows gently, RSA grows steeply |
| 4 | Python vs liboqs ML-KEM | bar | Why implementation matters (orders of magnitude) |
| 5 | CBD histogram (η=2, 3) vs theory | bar + markers | Step 04, supports A's math section |
| 6 | Decryption noise vs q/4 threshold | histogram | Step 06, shows why failures are negligible |
| 7 | Bytes on the wire per handshake | stacked bar (pk + ct) | The main practical cost of PQC |

## Style rules (so all members' charts look consistent)
- One color per **family** (ML-KEM / RSA / ECC), shades within a family for levels
- Label units on every axis (µs, bytes). Use a log scale when values span >10×, and **say so** in the caption
- Every caption states: machine, implementation (Python / liboqs / pyca), iterations, median ± IQR
- Also export a Markdown table from the same CSV, so the report has exact numbers, not just pictures

## Hand D the key interpretation points
- ML-KEM **wins** on speed (especially vs RSA keygen/decaps) **and** on quantum resistance
- ML-KEM **loses** on size compared with ECC: e.g. ML-KEM-768 ek 1184 B + ct 1088 B vs X25519's 32 B + 32 B
- RSA encryption alone is fast (e = 65537), so be honest about where RSA is competitive
- Python-track numbers show algorithmic structure, not deployable performance

## ✅ Done when
- [ ] All charts regenerate from one command: `python bench/plots.py`
- [ ] D has the PNGs + Markdown tables + interpretation notes
