"""Step 06 experiment: K-PKE decryption noise vs the q/4 failure threshold.

For each parameter set, encrypts random messages and measures the noise
w - mu (centered) that Decrypt has to round away. Decryption fails only if a
coefficient's noise reaches q/4 = 832.

Run from mlkem/:  .venv/Scripts/python bench/kpke_noise.py [trials]
Writes results/kpke_noise.csv and results/fig6_noise.png.
"""
import csv
import random
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from mlkem.encoding import byte_decode, decompress_poly
from mlkem.kpke import decrypt_noisy, encrypt, keygen
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, Q

RESULTS = Path(__file__).resolve().parent.parent / "results"
THRESHOLD = Q // 4  # 832


def centered(v: int) -> int:
    v %= Q
    return v if v <= Q // 2 else v - Q


def measure(p, trials, rng):
    """Return (Counter of per-coefficient noise, list of per-decryption max |noise|)."""
    hist, maxima = Counter(), []
    for t in range(trials):
        if t % 20 == 0:
            ek, dk = keygen(rng.randbytes(32), p)  # fresh key every 20 messages
        m = rng.randbytes(32)
        w = decrypt_noisy(dk, encrypt(ek, m, rng.randbytes(32), p), p)
        mu = decompress_poly(byte_decode(m, 1), 1)
        noise = [centered(a - b) for a, b in zip(w, mu)]
        hist.update(noise)
        maxima.append(max(abs(x) for x in noise))
    return hist, maxima


def main(trials=None, out_name="fig6_noise.png"):
    if trials is None:
        trials = int(sys.argv[1]) if __name__ == "__main__" and len(sys.argv) > 1 else 300
    rng = random.Random(2026)
    RESULTS.mkdir(exist_ok=True)
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2), sharey=True)
    rows = []
    for ax, p in zip(axes, (ML_KEM_512, ML_KEM_768, ML_KEM_1024)):
        hist, maxima = measure(p, trials, rng)
        total = sum(hist.values())
        xs = sorted(hist)
        ax.bar(xs, [hist[x] / total for x in xs], width=1.0, color="#2a78d6")
        for s in (-1, 1):
            ax.axvline(s * THRESHOLD, color="#d03b3b", linestyle="--", linewidth=1.5)
        ax.set_xlim(-THRESHOLD - 80, THRESHOLD + 80)
        ax.set_yscale("log")
        ax.set_title(f"{p.name}: max |noise| = {max(maxima)} (limit {THRESHOLD})")
        ax.set_xlabel("noise coefficient (w - mu, centered)")
        worst = max(maxima)
        rows.append([p.name, trials, total, worst, sum(maxima) / len(maxima),
                     f"{worst / THRESHOLD:.3f}"])
        print(f"{p.name}: {trials} decryptions, {total} coefficients, "
              f"max |noise| {worst}, mean per-decryption max {sum(maxima) / len(maxima):.1f}, "
              f"worst / (q/4) = {worst / THRESHOLD:.3f}")
    axes[0].set_ylabel("fraction of coefficients (log)")
    fig.suptitle("K-PKE decryption noise vs q/4 = 832 failure threshold (red dashed lines)")
    fig.tight_layout()
    fig.savefig(RESULTS / out_name, dpi=300)
    with open(RESULTS / "kpke_noise.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["param_set", "decryptions", "coefficients", "max_abs_noise",
                    "mean_max_abs_noise", "max_over_q4"])
        w.writerows(rows)
    print(f"wrote {RESULTS / out_name} and kpke_noise.csv")


if __name__ == "__main__":
    main()
