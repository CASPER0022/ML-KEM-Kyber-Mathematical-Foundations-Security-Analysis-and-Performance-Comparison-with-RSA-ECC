"""Shared benchmark harness (Step 10). Every scheme is measured with bench()."""
import gc
import statistics
import time
import tracemalloc


def bench(fn, *, warmup=20, iters=1000, min_time_s=2.0, max_time_s=None):
    """Time fn() repeatedly. Returns raw samples in nanoseconds.

    Runs at least `iters` times AND at least `min_time_s` seconds, unless
    `max_time_s` is hit first (for very slow ops such as RSA-7680 keygen).
    """
    for _ in range(warmup):
        fn()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    samples = []
    start = time.perf_counter()
    t_min_end = start + min_time_s
    try:
        while len(samples) < iters or time.perf_counter() < t_min_end:
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
            if max_time_s is not None and time.perf_counter() - start > max_time_s and len(samples) >= 3:
                break
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples


def summarize(samples_ns):
    """Median / quartiles in microseconds from raw nanosecond samples."""
    if len(samples_ns) >= 2:
        q1, med, q3 = statistics.quantiles(samples_ns, n=4, method="inclusive")
    else:
        q1 = med = q3 = samples_ns[0]
    return {
        "median_us": med / 1e3,
        "q1_us": q1 / 1e3,
        "q3_us": q3 / 1e3,
        "ops_per_sec": 1e9 / med,
        "n": len(samples_ns),
    }


def peak_memory(fn):
    """Peak Python-level allocation (bytes) during one call of fn().

    tracemalloc only sees Python allocations; memory malloc'd inside C
    libraries (liboqs, OpenSSL) is invisible to it.
    """
    gc.collect()
    tracemalloc.start()
    try:
        fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak
