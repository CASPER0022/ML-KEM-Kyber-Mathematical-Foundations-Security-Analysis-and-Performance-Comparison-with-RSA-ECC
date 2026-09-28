"""Step 10: run every benchmark and write one tidy CSV.

Run from mlkem/:
    .venv/Scripts/python bench/run_all.py            # full run (3 runs, ~15 min)
    .venv/Scripts/python bench/run_all.py --quick    # smoke test (1 run, seconds)

Outputs (in results/):
    bench.csv         one row per (scheme, impl, op); samples pooled over all runs
    bench_runs.csv    per-run medians, to show run-to-run stability
    bench_meta.json   machine, versions, settings, encodings
"""
import argparse
import csv
import datetime as dt
import json
import platform
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bench_classical  # noqa: E402
import bench_mlkem  # noqa: E402
from harness import bench, peak_memory, summarize  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "results"
OPS = ("keygen", "encaps", "decaps")
BASE_CLOCK_HZ = 2.4e9  # nominal base clock from results/machine.txt; turbo is higher

COLUMNS = [
    "scheme", "impl", "family", "level_bits", "op", "median_us", "q1_us", "q3_us",
    "ops_per_sec", "pk_bytes", "ct_bytes", "sk_bytes", "ss_bytes", "n",
    "peak_mem_bytes", "est_cycles", "run_spread_pct",
]


def all_cases():
    yield from bench_mlkem.cases()
    yield from bench_classical.cases()


def settings_for(case, op, quick):
    iters = case.get(f"{op}_iters", case["iters"])
    s = {
        "warmup": case.get(f"{op}_warmup", min(20, max(2, iters // 10))),
        "iters": iters,
        "min_time_s": 2.0,
        "max_time_s": case.get(f"{op}_max_s"),
    }
    if quick:
        s.update(warmup=min(s["warmup"], 1), iters=min(iters, 3), min_time_s=0.0, max_time_s=5)
    return s


def versions():
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from mlkem.oqs_backend import load_oqs
    oqs = load_oqs()
    return {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "liboqs": oqs.oqs_version() if oqs else None,
        "liboqs_python": oqs.oqs_python_version() if oqs else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--quick", action="store_true", help="tiny smoke test, results not meaningful")
    ap.add_argument("--only", default="", help="only schemes whose name contains this text")
    args = ap.parse_args()
    runs = 1 if args.quick else args.runs

    cases = [c for c in all_cases() if args.only in c["scheme"]]
    pooled = {}      # (scheme, impl, op) -> list of samples
    run_medians = {}  # (scheme, impl, op) -> [median per run]
    run_rows = []

    for r in range(1, runs + 1):
        for case in cases:
            for op in OPS:
                key = (case["scheme"], case["impl"], op)
                samples = bench(case["ops"][op], **settings_for(case, op, args.quick))
                med = statistics.median(samples) / 1e3
                pooled.setdefault(key, []).extend(samples)
                run_medians.setdefault(key, []).append(med)
                run_rows.append({"run": r, "scheme": key[0], "impl": key[1], "op": op,
                                 "median_us": round(med, 3), "n": len(samples)})
                print(f"run {r}/{runs}  {key[0]:<12} {key[1]:<7} {op:<7} "
                      f"median {med:12.2f} us  (n={len(samples)})", flush=True)

    rows = []
    for case in cases:
        for op in OPS:
            key = (case["scheme"], case["impl"], op)
            s = summarize(pooled[key])
            meds = run_medians[key]
            spread = (max(meds) - min(meds)) / statistics.median(meds) * 100 if len(meds) > 1 else 0.0
            mem = peak_memory(case["ops"][op])
            rows.append({
                "scheme": case["scheme"], "impl": case["impl"], "family": case["family"],
                "level_bits": case["level_bits"], "op": op,
                "median_us": round(s["median_us"], 3), "q1_us": round(s["q1_us"], 3),
                "q3_us": round(s["q3_us"], 3), "ops_per_sec": round(s["ops_per_sec"], 1),
                "pk_bytes": case["pk_bytes"], "ct_bytes": case["ct_bytes"],
                "sk_bytes": case["sk_bytes"], "ss_bytes": case["ss_bytes"], "n": s["n"],
                "peak_mem_bytes": mem,
                "est_cycles": round(s["median_us"] * 1e-6 * BASE_CLOCK_HZ),
                "run_spread_pct": round(spread, 1),
            })

    RESULTS.mkdir(exist_ok=True)
    suffix = "_quick" if args.quick else ""
    with open(RESULTS / f"bench{suffix}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(RESULTS / f"bench_runs{suffix}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["run", "scheme", "impl", "op", "median_us", "n"])
        w.writeheader()
        w.writerows(run_rows)
    meta = {
        "date": dt.datetime.now().isoformat(timespec="seconds"),
        "machine": (RESULTS / "machine.txt").read_text().splitlines(),
        "platform": platform.platform(),
        "versions": versions(),
        "runs": runs,
        "quick": args.quick,
        "timer": "time.perf_counter_ns, GC disabled during timing; median + IQR over samples pooled from all runs",
        "est_cycles": f"ESTIMATE = median time x {BASE_CLOCK_HZ / 1e9} GHz nominal base clock (turbo is higher); not measured",
        "peak_mem_bytes": "tracemalloc peak for one op: Python-level allocations only (C/OpenSSL/liboqs malloc invisible)",
        "run_spread_pct": "(max - min) / median of the per-run medians",
        "impls": {
            "python": "this project's pure-Python FIPS 203 implementation (Track 1)",
            "liboqs": "liboqs C, portable reference code path (no AVX2 on Windows builds)",
            "pyca": "pyca/cryptography -> OpenSSL",
        },
        "kem_mapping": bench_classical.__doc__,
        "not_measured": "RSA-15360 (256-bit level) omitted: keygen takes minutes per key",
    }
    (RESULTS / f"bench_meta{suffix}.json").write_text(json.dumps(meta, indent=2))
    print(f"wrote {RESULTS / f'bench{suffix}.csv'} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
