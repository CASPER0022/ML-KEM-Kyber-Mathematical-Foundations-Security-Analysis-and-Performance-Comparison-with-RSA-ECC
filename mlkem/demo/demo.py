"""Step 12: live terminal demo of ML-KEM (FIPS 203).

Run from mlkem/:
    .venv/Scripts/python demo/demo.py                  # ML-KEM-768, our Python code
    .venv/Scripts/python demo/demo.py --params 512
    .venv/Scripts/python demo/demo.py --impl liboqs    # optimized C backend
    .venv/Scripts/python demo/demo.py --fast           # skip the mini benchmark
    .venv/Scripts/python demo/demo.py --vectors        # also run the NIST ACVP tests live
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import colorama
    colorama.just_fix_windows_console()
except ImportError:
    pass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mlkem import mlkem
from mlkem.hashes import J
from mlkem.oqs_backend import load_oqs
from mlkem.params import PARAMS

GREEN, RED, CYAN, YELLOW, BOLD, DIM, RESET = (
    "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[1m", "\033[2m", "\033[0m")
ROOT = Path(__file__).resolve().parent.parent


def header(n, title):
    print(f"\n{BOLD}{CYAN}[{n}] {title}{RESET}")
    print(f"{DIM}{'-' * 64}{RESET}")


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t0) * 1e3


def short(b: bytes, n=32) -> str:
    return b.hex()[:n] + "..."


class PythonKEM:
    name = "our pure-Python FIPS 203 code"

    def __init__(self, p):
        self.p = p

    def keygen(self):
        return mlkem.keygen(self.p)

    def encaps(self, ek):
        return mlkem.encaps(self.p, ek)

    def decaps(self, dk, c):
        return mlkem.decaps(self.p, dk, c)


class LiboqsKEM:
    name = "liboqs (optimized C)"

    def __init__(self, p):
        self.oqs = load_oqs()
        if self.oqs is None:
            sys.exit("liboqs is not available -- run with --impl python, or build it (scripts/build_liboqs.sh)")
        self.p = p

    def keygen(self):
        with self.oqs.KeyEncapsulation(self.p.name) as kem:
            ek = kem.generate_keypair()
            return ek, kem.export_secret_key()

    def encaps(self, ek):
        with self.oqs.KeyEncapsulation(self.p.name) as kem:
            c, K = kem.encap_secret(ek)
            return K, c

    def decaps(self, dk, c):
        with self.oqs.KeyEncapsulation(self.p.name, secret_key=dk) as kem:
            return kem.decap_secret(c)


def mini_benchmark(p, runs=100):
    header(7, f"Mini benchmark: {runs} runs each, keygen + encaps + decaps")
    oqs = load_oqs()
    rows = []

    def measure(label, keygen, encaps, decaps, n):
        tk = te = td = 0.0
        for _ in range(n):
            (ek, dk), a = timed(keygen)
            (K, c), b = timed(encaps, ek)
            _, d = timed(decaps, dk, c)
            tk, te, td = tk + a, te + b, td + d
        rows.append((label, tk / n, te / n, td / n))

    if oqs is not None:
        k = LiboqsKEM(p)
        measure(f"{p.name} (liboqs C)", k.keygen, k.encaps, k.decaps, runs)
    k = PythonKEM(p)
    measure(f"{p.name} (our Python)", k.keygen, k.encaps, k.decaps, max(5, runs // 10))

    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def rsa_keygen():
        sk = rsa.generate_private_key(65537, 3072)
        return sk.public_key(), sk

    def rsa_encaps(pk):
        K = os.urandom(32)
        return K, pk.encrypt(K, oaep)

    measure("RSA-3072 (OpenSSL)", rsa_keygen, rsa_encaps, lambda sk, c: sk.decrypt(c, oaep), 10)

    def x_keygen():
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key(), sk

    def x_encaps(pk):
        e = x25519.X25519PrivateKey.generate()
        return e.exchange(pk), e.public_key()

    measure("X25519 (OpenSSL)", x_keygen, x_encaps, lambda sk, epk: sk.exchange(epk), runs)

    print(f"{BOLD}{'scheme':<26}{'keygen':>12}{'encaps':>12}{'decaps':>12}{RESET}")
    for label, a, b, d in rows:
        print(f"{label:<26}{a:>10.3f}ms{b:>10.3f}ms{d:>10.3f}ms")
    print(f"{DIM}RSA-3072 keygen: 10 runs only (it is slow). Our Python: fewer runs. Averages.{RESET}")


def main():
    ap = argparse.ArgumentParser(description="ML-KEM live demo")
    ap.add_argument("--params", choices=["512", "768", "1024"], default="768")
    ap.add_argument("--impl", choices=["python", "liboqs"], default="python")
    ap.add_argument("--fast", action="store_true", help="skip the mini benchmark")
    ap.add_argument("--vectors", action="store_true", help="run the NIST ACVP tests at the end")
    args = ap.parse_args()

    # Windows consoles may default to cp1252, which cannot print ✔ / ✘.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = PARAMS[f"ML-KEM-{args.params}"]
    kem = PythonKEM(p) if args.impl == "python" else LiboqsKEM(p)

    print(f"{BOLD}ML-KEM (FIPS 203) live demo{RESET}  --  {p.name} using {kem.name}")

    header(1, f"Parameter set: {p.name}")
    print(f"k = {p.k}, eta1 = {p.eta1}, eta2 = {p.eta2}, du = {p.du}, dv = {p.dv}, q = 3329, n = 256")

    header(2, "KeyGen (Bob)")
    (ek, dk), t = timed(kem.keygen)
    print(f"encapsulation key ek : {len(ek):>5} bytes   {short(ek)}")
    print(f"decapsulation key dk : {len(dk):>5} bytes   (kept secret)")
    print(f"time: {YELLOW}{t:.2f} ms{RESET}")

    header(3, "Encaps (Alice, using Bob's public ek)")
    (K_alice, c), t = timed(kem.encaps, ek)
    print(f"ciphertext c         : {len(c):>5} bytes   {short(c)}")
    print(f"shared key K_alice   :    32 bytes   {K_alice.hex()}")
    print(f"time: {YELLOW}{t:.2f} ms{RESET}")

    header(4, "Decaps (Bob, using his secret dk)")
    K_bob, t = timed(kem.decaps, dk, c)
    print(f"shared key K_bob     :    32 bytes   {K_bob.hex()}")
    print(f"time: {YELLOW}{t:.2f} ms{RESET}")
    if K_alice == K_bob:
        print(f"\n{BOLD}{GREEN}   KEYS MATCH  ✔   {RESET}")
    else:
        print(f"\n{BOLD}{RED}   KEYS DIFFER ✘   {RESET}")
        sys.exit(1)

    header(5, "Tamper attack: flip ONE bit of the ciphertext")
    bad = bytearray(c)
    bad[0] ^= 1
    bad = bytes(bad)
    K_bad = kem.decaps(dk, bad)  # no exception
    print(f"tampered decaps key  :    32 bytes   {K_bad.hex()}")
    print(f"equals K_alice?      : {RED if K_bad == K_alice else GREEN}{K_bad == K_alice}{RESET}")
    if args.impl == "python":
        print(f"equals J(z || c')?   : {GREEN}{K_bad == J(dk[-32:] + bad)}{RESET}")
    print(f"{DIM}No error was raised. Decaps re-encrypts and sees c changed, so it returns a")
    print(f"pseudorandom key J(z || c) instead (implicit rejection, Fujisaki-Okamoto transform).{RESET}")

    header(6, "Use the shared key: AES-256-GCM")
    msg = b"Hello Bob, this message is protected by a post-quantum key!"
    nonce = os.urandom(12)
    ct = AESGCM(K_alice).encrypt(nonce, msg, None)
    print(f"Alice encrypts       : {short(ct, 48)}  ({len(ct)} bytes)")
    print(f"Bob decrypts         : {GREEN}{AESGCM(K_bob).decrypt(nonce, ct, None).decode()}{RESET}")
    try:
        AESGCM(K_bad).decrypt(nonce, ct, None)
        print(f"{RED}attacker key decrypted the message (unexpected){RESET}")
    except Exception:
        print(f"attacker's key       : {RED}decryption fails (InvalidTag){RESET}")

    if not args.fast:
        mini_benchmark(p)

    if args.vectors:
        header(8, "NIST ACVP test vectors")
        sys.stdout.flush()
        subprocess.run([sys.executable, "-m", "pytest", "tests/test_acvp.py", "-q"], cwd=ROOT)

    print(f"\n{DIM}Educational implementation: NOT constant-time, not for production use.{RESET}")


if __name__ == "__main__":
    main()
