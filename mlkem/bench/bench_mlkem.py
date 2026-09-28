"""Step 10: ML-KEM benchmark cases for every available implementation.

impl = "python"  our pure-Python FIPS 203 code (Track 1)
impl = "liboqs"  liboqs 0.16.0 C, portable reference path on Windows (Track 2)
impl = "pyca"    pyca/cryptography -> OpenSSL (768 / 1024 only)
"""
from mlkem import mlkem
from mlkem.oqs_backend import load_oqs
from mlkem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024

LEVEL = {"ML-KEM-512": 128, "ML-KEM-768": 192, "ML-KEM-1024": 256}
ALL = (ML_KEM_512, ML_KEM_768, ML_KEM_1024)


def _case(scheme, impl, ops, sizes, iters):
    return {"scheme": scheme, "impl": impl, "family": "ML-KEM", "level_bits": LEVEL[scheme],
            "ops": ops, "iters": iters, **sizes}


def _sizes(p):
    return {"pk_bytes": p.ek_size, "ct_bytes": p.ct_size, "sk_bytes": p.dk_size, "ss_bytes": 32}


def python_cases():
    for p in ALL:
        ek, dk = mlkem.keygen(p)
        _, c = mlkem.encaps(p, ek)
        ops = {
            "keygen": lambda p=p: mlkem.keygen(p),
            "encaps": lambda p=p, ek=ek: mlkem.encaps(p, ek),
            "decaps": lambda p=p, dk=dk, c=c: mlkem.decaps(p, dk, c),
        }
        yield _case(p.name, "python", ops, _sizes(p), iters=100)


def liboqs_cases():
    oqs = load_oqs()
    if oqs is None:
        return
    for p in ALL:
        kem = oqs.KeyEncapsulation(p.name)  # holds the decaps secret key
        ek = kem.generate_keypair()
        c, _ = kem.encap_secret(ek)
        keygen_kem = oqs.KeyEncapsulation(p.name)
        ops = {
            "keygen": keygen_kem.generate_keypair,
            "encaps": lambda kem=kem, ek=ek: kem.encap_secret(ek),
            "decaps": lambda kem=kem, c=c: kem.decap_secret(c),
        }
        yield _case(p.name, "liboqs", ops, _sizes(p), iters=1000)


def pyca_cases():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem as m
    except ImportError:
        return
    classes = {"ML-KEM-768": m.MLKEM768PrivateKey, "ML-KEM-1024": m.MLKEM1024PrivateKey}
    for p in ALL:
        if p.name not in classes:
            continue
        cls = classes[p.name]
        sk = cls.generate()
        pk = sk.public_key()
        _, c = pk.encapsulate()
        ops = {
            "keygen": cls.generate,
            "encaps": pk.encapsulate,
            "decaps": lambda sk=sk, c=c: sk.decapsulate(c),
        }
        yield _case(p.name, "pyca", ops, _sizes(p), iters=1000)


def cases():
    yield from python_cases()
    yield from liboqs_cases()
    yield from pyca_cases()
