"""Step 10 extra: where does pure-Python ML-KEM spend its time? (cProfile)

Groups profiled time into: matrix generation (SampleNTT / SHAKE128), NTT and
inverse NTT, NTT-domain multiplication, CBD sampling, hashing (SHA-3 / SHAKE),
byte encoding + compression, and everything else.

Run from mlkem/:  .venv/Scripts/python bench/profile_mlkem.py
Writes results/profile_mlkem.csv.
"""
import cProfile
import csv
import pstats
from pathlib import Path

from mlkem import mlkem
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

RESULTS = Path(__file__).resolve().parent.parent / "results"
RUNS = 30

# (bucket, module file suffix, function names or None for "any function in that module")
BUCKETS = [
    ("matrix gen (SampleNTT)", "sampling.py", {"sample_ntt"}),
    ("CBD sampling", "sampling.py", {"sample_poly_cbd"}),
    ("NTT / NTT^-1", "ntt.py", {"ntt", "ntt_inv", "vec_ntt", "vec_intt"}),
    ("NTT-domain multiply", "ntt.py", {"multiply_ntts", "base_case_multiply", "inner_ntt",
                                       "mat_vec_mul_ntt", "mat_T_vec_mul_ntt", "poly_add",
                                       "poly_sub", "vec_add"}),
    ("encode / compress", "encoding.py", None),
    ("hashing (SHA-3 / SHAKE)", "hashes.py", None),
]


def bucket_of(filename: str, func: str) -> str:
    for name, suffix, funcs in BUCKETS:
        if filename.replace("\\", "/").endswith("mlkem/" + suffix) and (funcs is None or func in funcs):
            return name
    if "hashlib" in func or "sha3" in func or "shake" in func:
        return "hashing (SHA-3 / SHAKE)"
    return "other (Python overhead, bytes, lists)"


def profile(fn):
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(RUNS):
        fn()
    pr.disable()
    stats = pstats.Stats(pr).stats
    totals = {}
    for (filename, _, func), (_, _, tottime, _, callers) in stats.items():
        if _is_ours(filename) or not callers:
            b = bucket_of(filename, func)
            totals[b] = totals.get(b, 0.0) + tottime
            continue
        # Builtins (sum, list.append, hashlib, ...) have no parent in tottime:
        # charge each call edge's own time to the calling function's bucket.
        for (cfile, _, cfunc), edge in callers.items():
            b = bucket_of(cfile, cfunc) if _is_ours(cfile) else bucket_of(filename, func)
            totals[b] = totals.get(b, 0.0) + edge[2]
    return totals


def _is_ours(filename: str) -> bool:
    return "/mlkem/" in filename.replace("\\", "/") and "/bench/" not in filename.replace("\\", "/")


def main():
    rows = []
    for p in (ML_KEM_512, ML_KEM_768, ML_KEM_1024):
        ek, dk = mlkem.keygen(p)
        _, c = mlkem.encaps(p, ek)
        ops = {
            "keygen": lambda p=p: mlkem.keygen(p),
            "encaps": lambda p=p: mlkem.encaps(p, ek),
            "decaps": lambda p=p: mlkem.decaps(p, dk, c),
        }
        for op, fn in ops.items():
            totals = profile(fn)
            total = sum(totals.values())
            for b, t in sorted(totals.items(), key=lambda kv: -kv[1]):
                rows.append({"scheme": p.name, "op": op, "bucket": b,
                             "share_pct": round(100 * t / total, 1)})
            top = ", ".join(f"{b} {100 * t / total:.0f}%" for b, t in
                            sorted(totals.items(), key=lambda kv: -kv[1])[:3])
            print(f"{p.name:<12} {op:<7} {top}")
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "profile_mlkem.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scheme", "op", "bucket", "share_pct"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {RESULTS / 'profile_mlkem.csv'}")


if __name__ == "__main__":
    main()
