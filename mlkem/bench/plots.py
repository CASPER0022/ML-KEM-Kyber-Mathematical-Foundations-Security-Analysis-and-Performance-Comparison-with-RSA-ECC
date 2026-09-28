"""Step 11: all report charts + Markdown tables from results/bench.csv.

Run from mlkem/:  .venv/Scripts/python bench/plots.py
Writes results/fig1..fig7 *.png (300 dpi) and results/bench_tables.md.
Figure 6 re-runs the K-PKE noise experiment (about a minute).
"""
import csv
import json
import random
import sys
from collections import Counter
from math import comb
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import to_rgb

sys.path.insert(0, str(Path(__file__).resolve().parent))

RESULTS = Path(__file__).resolve().parent.parent / "results"

# Palette: one hue per family (validated: CVD all-pairs dE >= 9.2).
FAMILY = {"ML-KEM": "#2a78d6", "RSA": "#eb6834", "ECC": "#1baf7a"}
IMPL_SHADE = {"python": "#86b6ef", "liboqs": "#2a78d6", "pyca": "#104281"}  # blue ramp 250/450/650
SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3de"
CRITICAL = "#d03b3b"

ORDER = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "RSA-2048", "RSA-3072", "RSA-4096",
         "RSA-7680", "P-256", "P-384", "P-521", "X25519"]
IMPL_LABEL = {"python": "our Python", "liboqs": "liboqs C", "pyca": "OpenSSL"}
OPS = ("keygen", "encaps", "decaps")

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 9, "axes.titlesize": 10, "axes.titleweight": "bold", "legend.frameon": False,
})


def blend(hex_color, amount):
    """Mix a color toward the surface (amount 0 = color, 1 = surface)."""
    c, s = to_rgb(hex_color), to_rgb(SURFACE)
    return tuple(ci + (si - ci) * amount for ci, si in zip(c, s))


def load():
    rows = list(csv.DictReader(open(RESULTS / "bench.csv")))
    for r in rows:
        for k in ("median_us", "q1_us", "q3_us", "ops_per_sec", "run_spread_pct"):
            r[k] = float(r[k])
        for k in ("level_bits", "pk_bytes", "ct_bytes", "sk_bytes", "ss_bytes", "n", "peak_mem_bytes", "est_cycles"):
            r[k] = int(r[k])
    meta = json.loads((RESULTS / "bench_meta.json").read_text())
    return rows, meta


def caption(fig, text, meta):
    v = meta["versions"]
    machine = "Intel i5-12450HX, Windows 11"
    fig.text(0.01, 0.005, f"{text}\nMachine: {machine}; Python {v['python']}, cryptography {v['cryptography']} "
             f"({v['openssl']}), liboqs {v['liboqs']}. {meta['runs']} runs pooled.",
             fontsize=7, color=INK_2, va="bottom", ha="left")


def pick(rows, scheme, impl, op):
    for r in rows:
        if r["scheme"] == scheme and r["impl"] == impl and r["op"] == op:
            return r
    return None


def fmt_us(us):
    if us >= 1e6:
        return f"{us / 1e6:.2f} s"
    if us >= 1e3:
        return f"{us / 1e3:.2f} ms"
    return f"{us:.0f} µs" if us >= 10 else f"{us:.1f} µs"


def sizes_by_scheme(rows):
    out = {}
    for r in rows:
        out.setdefault(r["scheme"], r)
    return out


def fig1_sizes(rows, meta):
    sz = sizes_by_scheme(rows)
    schemes = [s for s in ORDER if s in sz]
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.6), sharey=True)
    for ax, (key, title) in zip(axes, [("pk_bytes", "Public key"), ("ct_bytes", "Ciphertext"),
                                      ("sk_bytes", "Secret key")]):
        vals = [sz[s][key] for s in schemes]
        colors = [FAMILY[sz[s]["family"]] for s in schemes]
        y = range(len(schemes))
        ax.barh(y, vals, color=colors, height=0.7, edgecolor=SURFACE, linewidth=1.5)
        for yi, v in zip(y, vals):
            ax.text(v * 1.08, yi, f"{v:,}", va="center", fontsize=7.5, color=INK)
        ax.set_xscale("log")
        ax.set_xlim(10, max(vals) * 6)
        ax.set_title(f"{title} (bytes, log scale)")
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(range(len(schemes)), schemes)
    axes[0].invert_yaxis()
    _family_legend(fig)
    caption(fig, "Fig 1. Key and ciphertext sizes. ML-KEM: FIPS 203 raw encodings. RSA: pk = DER SPKI, "
                 "sk = DER PKCS#8, ct = modulus. ECC: pk = ct = uncompressed point (X25519 raw), sk = scalar.", meta)
    fig.tight_layout(rect=(0, 0.07, 1, 0.94))
    fig.savefig(RESULTS / "fig1_sizes.png", dpi=300)
    plt.close(fig)


def _family_legend(fig, loc="upper center"):
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in FAMILY.values()]
    fig.legend(handles, list(FAMILY), loc=loc, ncol=3, bbox_to_anchor=(0.5, 1.0))


def c_rows(rows):
    """C/Rust-backed implementations only, in display order: (label, scheme, impl, family)."""
    out = []
    for s in ORDER:
        for impl in ("liboqs", "pyca"):
            r = pick(rows, s, impl, "keygen")
            if r is None:
                continue
            label = s if r["family"] != "ML-KEM" else f"{s} ({IMPL_LABEL[impl]})"
            out.append((label, s, impl, r["family"]))
    return out


def fig2_time(rows, meta):
    items = c_rows(rows)
    fig, axes = plt.subplots(1, 3, figsize=(13, 5.6), sharey=True)
    for ax, op in zip(axes, OPS):
        rs = [pick(rows, s, impl, op) for _, s, impl, _ in items]
        med = [r["median_us"] for r in rs]
        err = [[r["median_us"] - r["q1_us"] for r in rs], [r["q3_us"] - r["median_us"] for r in rs]]
        y = range(len(items))
        ax.barh(y, med, color=[FAMILY[f] for *_, f in items], height=0.7,
                edgecolor=SURFACE, linewidth=1.5, xerr=err, error_kw={"ecolor": INK_2, "elinewidth": 1, "capsize": 2})
        for yi, v, e in zip(y, med, err[1]):
            ax.text((v + e) * 1.45, yi, fmt_us(v), va="center", fontsize=7, color=INK)
        ax.set_xscale("log")
        ax.set_xlim(min(med) / 2, max(med) * 60)
        ax.set_title(f"{op} (µs, log scale)")
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(range(len(items)), [lab for lab, *_ in items])
    axes[0].invert_yaxis()
    _family_legend(fig)
    caption(fig, "Fig 2. Time per operation, compiled implementations only (bar = median, whisker = IQR). "
                 "ML-KEM liboqs = portable C (no AVX2 on Windows). RSA = OAEP-SHA256; ECC = ECDH as a KEM.", meta)
    fig.tight_layout(rect=(0, 0.07, 1, 0.95))
    fig.savefig(RESULTS / "fig2_time_compiled.png", dpi=300)
    plt.close(fig)


def fig3_scaling(rows, meta):
    lines = {
        "ML-KEM (liboqs)": ("ML-KEM", [("ML-KEM-512", "liboqs"), ("ML-KEM-768", "liboqs"), ("ML-KEM-1024", "liboqs")]),
        "RSA": ("RSA", [("RSA-2048", "pyca"), ("RSA-3072", "pyca"), ("RSA-4096", "pyca"), ("RSA-7680", "pyca")]),
        "ECC (P-curves)": ("ECC", [("P-256", "pyca"), ("P-384", "pyca"), ("P-521", "pyca")]),
    }
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.4), sharey=True)
    for ax, op in zip(axes, OPS):
        for name, (fam, pts) in lines.items():
            rs = [pick(rows, s, i, op) for s, i in pts]
            rs = [r for r in rs if r]
            xs = [r["level_bits"] for r in rs]
            ys = [r["median_us"] for r in rs]
            ax.plot(xs, ys, color=FAMILY[fam], linewidth=2, marker="o", markersize=7,
                    markeredgecolor=SURFACE, markeredgewidth=1.5, label=name)
            ax.annotate(name, (xs[-1], ys[-1]), xytext=(6, 0), textcoords="offset points",
                        va="center", fontsize=7.5, color=INK)
        ax.set_yscale("log")
        ax.set_xticks([112, 128, 140, 192, 256], ["112", "128", "", "192", "256"])
        ax.set_xlim(100, 300)
        ax.set_xlabel("classical security level (bits)")
        ax.set_title(f"{op} (µs, log scale)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.0))
    caption(fig, "Fig 3. Cost vs security level (median). RSA levels per NIST SP 800-57 (RSA-4096 plotted at ~140-bit, estimate); "
                 "RSA-15360 (256-bit) not measured: keygen takes minutes.", meta)
    fig.tight_layout(rect=(0, 0.08, 1, 0.93))
    fig.savefig(RESULTS / "fig3_scaling.png", dpi=300)
    plt.close(fig)


def fig4_python_vs_c(rows, meta):
    params = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    impls = [i for i in ("python", "liboqs", "pyca") if any(r["impl"] == i and r["family"] == "ML-KEM" for r in rows)]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.4), sharey=True)
    width = 0.8 / len(impls)
    for ax, s in zip(axes, params):
        for k, impl in enumerate(impls):
            xs, ys = [], []
            for j, op in enumerate(OPS):
                r = pick(rows, s, impl, op)
                if r:
                    xs.append(j + (k - (len(impls) - 1) / 2) * width)
                    ys.append(r["median_us"])
            ax.bar(xs, ys, width=width * 0.92, color=IMPL_SHADE[impl], label=IMPL_LABEL[impl],
                   edgecolor=SURFACE, linewidth=1.5)
        for j, op in enumerate(OPS):
            py, c = pick(rows, s, "python", op), pick(rows, s, "liboqs", op)
            if py and c:
                ax.text(j - (len(impls) - 1) / 2 * width, py["median_us"] * 1.25,
                        f"×{py['median_us'] / c['median_us']:.0f}", ha="center", fontsize=7.5, color=INK)
        ax.set_yscale("log")
        ax.set_xticks(range(3), OPS)
        ax.set_title(f"{s} (µs, log scale)")
        ax.grid(axis="x", visible=False)
    for ax in axes:
        lo, hi = ax.get_ylim()
        ax.set_ylim(lo, hi * 3)
    handles = [plt.Rectangle((0, 0), 1, 1, color=IMPL_SHADE[i]) for i in impls]
    fig.legend(handles, [IMPL_LABEL[i] for i in impls], loc="upper center", ncol=len(impls), bbox_to_anchor=(0.5, 1.0))
    caption(fig, "Fig 4. Same algorithm, different implementations (median). ×N = our Python time / liboqs C time. "
                 "OpenSSL (pyca) has no ML-KEM-512.", meta)
    fig.tight_layout(rect=(0, 0.08, 1, 0.93))
    fig.savefig(RESULTS / "fig4_python_vs_c.png", dpi=300)
    plt.close(fig)


def fig5_cbd(meta):
    from mlkem.params import Q
    from mlkem.sampling import sample_poly_cbd
    rng = random.Random(2026)
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, eta in zip(axes, (2, 3)):
        counts, polys = Counter(), 200
        for _ in range(polys):
            counts.update(v if v <= Q // 2 else v - Q for v in sample_poly_cbd(rng.randbytes(64 * eta), eta))
        total = polys * 256
        xs = list(range(-eta, eta + 1))
        ax.bar(xs, [counts[x] / total for x in xs], color=FAMILY["ML-KEM"], width=0.7,
               edgecolor=SURFACE, linewidth=1.5, label=f"observed ({total:,} coefficients)")
        theory = [comb(2 * eta, x + eta) / 4 ** eta for x in xs]
        ax.plot(xs, theory, linestyle="none", marker="D", markersize=8, color=INK,
                markeredgecolor=SURFACE, label=f"theory C(2η, k)/4^η")
        ax.set_xticks(xs)
        ax.set_title(f"CBD η = {eta}")
        ax.set_xlabel("coefficient value (centered)")
        ax.grid(axis="x", visible=False)
        ax.set_ylim(0, max(theory) * 1.4)
        ax.legend(loc="upper center", fontsize=7.5, ncol=2)
    axes[0].set_ylabel("probability")
    caption(fig, "Fig 5. SamplePolyCBD output vs the centered binomial distribution (our Python implementation).", meta)
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(RESULTS / "fig5_cbd.png", dpi=300)
    plt.close(fig)


def fig6_noise():
    import kpke_noise
    kpke_noise.main(out_name="fig6_noise.png")


def fig7_wire(rows, meta):
    sz = sizes_by_scheme(rows)
    schemes = [s for s in ORDER if s in sz]
    pk = [sz[s]["pk_bytes"] for s in schemes]
    ct = [sz[s]["ct_bytes"] for s in schemes]
    fams = [sz[s]["family"] for s in schemes]
    fig, ax = plt.subplots(figsize=(9, 4.8))
    y = range(len(schemes))
    ax.barh(y, pk, color=[FAMILY[f] for f in fams], height=0.7, edgecolor=SURFACE, linewidth=1.5)
    for yi, a, b, f in zip(y, pk, ct, fams):
        ax.barh(yi, b, left=a, color=blend(FAMILY[f], 0.6), height=0.7,
                edgecolor=SURFACE, linewidth=1.5, hatch="///", hatchcolor=FAMILY[f])
    for yi, a, b in zip(y, pk, ct):
        ax.text(a + b + 40, yi, f"{a + b:,} B", va="center", fontsize=7.5, color=INK)
    ax.set_yticks(list(y), schemes)
    ax.invert_yaxis()
    ax.set_xlabel("bytes on the wire per key exchange (linear scale)")
    ax.set_xlim(0, max(a + b for a, b in zip(pk, ct)) * 1.15)
    ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=INK_2),
               plt.Rectangle((0, 0), 1, 1, facecolor=blend(INK_2, 0.6), hatch="///", edgecolor=SURFACE)]
    ax.legend(handles, ["public key (solid)", "ciphertext / ephemeral key (hatched)"], loc="lower right")
    ax.set_title("Bytes on the wire: public key + ciphertext")
    caption(fig, "Fig 7. One KEM handshake sends the public key one way and the ciphertext back. "
                 "Colors: ML-KEM blue, RSA orange, ECC aqua.", meta)
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(RESULTS / "fig7_wire_bytes.png", dpi=300)
    plt.close(fig)


def tables(rows, meta):
    sz = sizes_by_scheme(rows)
    lines = ["# Benchmark tables (generated by bench/plots.py from results/bench.csv)", "",
             f"Date: {meta['date']}. {meta['runs']} runs pooled. Versions: " +
             ", ".join(f"{k} {v}" for k, v in meta["versions"].items()) + ".", "",
             "Times are median [Q1-Q3] in microseconds. `est_cycles` = median x 2.4 GHz base clock "
             "(ESTIMATE, not measured). Memory = Python-level tracemalloc peak only.", "",
             "## Sizes (bytes)", "",
             "| Scheme | Level (bits) | Public key | Ciphertext | Secret key | Shared secret | pk + ct |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for s in ORDER:
        if s in sz:
            r = sz[s]
            lines.append(f"| {s} | {r['level_bits']} | {r['pk_bytes']:,} | {r['ct_bytes']:,} | "
                         f"{r['sk_bytes']:,} | {r['ss_bytes']} | {r['pk_bytes'] + r['ct_bytes']:,} |")
    lines += ["", "## Time per operation", "",
              "| Scheme | Impl | keygen (µs) | encaps (µs) | decaps (µs) | total (µs) | run spread (max %) |",
              "|---|---|---:|---:|---:|---:|---:|"]
    for s in ORDER:
        for impl in ("python", "liboqs", "pyca"):
            rs = [pick(rows, s, impl, op) for op in OPS]
            if not all(rs):
                continue
            cells = [f"{r['median_us']:,.1f} [{r['q1_us']:,.1f}-{r['q3_us']:,.1f}]" for r in rs]
            total = sum(r["median_us"] for r in rs)
            spread = max(r["run_spread_pct"] for r in rs)
            lines.append(f"| {s} | {IMPL_LABEL[impl]} | " + " | ".join(cells) + f" | {total:,.1f} | {spread:.0f}% |")
    lines += ["", "## Estimated cycles and memory (median op)", "",
              "| Scheme | Impl | op | est. cycles | Python peak mem (bytes) | n samples |",
              "|---|---|---|---:|---:|---:|"]
    for s in ORDER:
        for impl in ("python", "liboqs", "pyca"):
            for op in OPS:
                r = pick(rows, s, impl, op)
                if r:
                    lines.append(f"| {s} | {IMPL_LABEL[impl]} | {op} | {r['est_cycles']:,} | "
                                 f"{r['peak_mem_bytes']:,} | {r['n']:,} |")
    prof = RESULTS / "profile_mlkem.csv"
    if prof.exists():
        lines += ["", "## Where pure-Python ML-KEM spends its time (cProfile, % of op)", "",
                  "| Scheme | op | breakdown |", "|---|---|---|"]
        groups = {}
        for r in csv.DictReader(open(prof)):
            groups.setdefault((r["scheme"], r["op"]), []).append(f"{r['bucket']} {float(r['share_pct']):.0f}%")
        for (s, op), parts in groups.items():
            lines.append(f"| {s} | {op} | " + "; ".join(parts) + " |")
    (RESULTS / "bench_tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    rows, meta = load()
    fig1_sizes(rows, meta)
    fig2_time(rows, meta)
    fig3_scaling(rows, meta)
    fig4_python_vs_c(rows, meta)
    fig5_cbd(meta)
    fig7_wire(rows, meta)
    tables(rows, meta)
    if "--no-noise" not in sys.argv:
        fig6_noise()
    print(f"wrote figures and bench_tables.md to {RESULTS}")


if __name__ == "__main__":
    main()
