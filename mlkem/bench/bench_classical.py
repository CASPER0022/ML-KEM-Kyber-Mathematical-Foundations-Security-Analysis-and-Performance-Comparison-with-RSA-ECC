"""Step 10 (co-owned with Member D): RSA and ECC as KEM-equivalents, via pyca/cryptography (OpenSSL).

KEM mapping (agreed in the Step 10 guide):
  RSA-n : keygen = generate (e = 65537); encaps = RSA-OAEP(SHA-256) encrypt a
          random 32-byte key; decaps = OAEP decrypt
  ECDH  : keygen = static key pair; encaps = fresh ephemeral key + ECDH with
          the static public key (ECIES-style); decaps = ECDH(static priv, eph pub)

Size encodings:
  RSA  pk = DER SubjectPublicKeyInfo, sk = DER PKCS#8, ct = modulus length
  EC   pk = ct = X9.62 uncompressed point (P-curves) or raw 32 B (X25519),
       sk = raw private scalar length
  ss   RSA = the 32-byte key it transports; ECDH = raw shared x-coordinate
"""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

# NIST SP 800-57 Pt 1 Rev 5, Table 2 (RSA-4096 is not listed; ~140-bit is the usual estimate).
RSA_SIZES = {2048: 112, 3072: 128, 4096: 140, 7680: 192}
EC_CURVES = {"P-256": (ec.SECP256R1, 128), "P-384": (ec.SECP384R1, 192), "P-521": (ec.SECP521R1, 256)}

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_DER = serialization.Encoding.DER
_UNCOMPRESSED = serialization.PublicFormat.UncompressedPoint


def rsa_cases():
    for bits, level in RSA_SIZES.items():
        sk = rsa.generate_private_key(65537, bits)
        pk = sk.public_key()
        key = os.urandom(32)
        c = pk.encrypt(key, OAEP)
        slow = bits >= 7680
        ops = {
            "keygen": lambda bits=bits: rsa.generate_private_key(65537, bits),
            "encaps": lambda pk=pk: pk.encrypt(os.urandom(32), OAEP),
            "decaps": lambda sk=sk, c=c: sk.decrypt(c, OAEP),
        }
        pk_bytes = len(pk.public_bytes(_DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        sk_bytes = len(sk.private_bytes(_DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        yield {
            "scheme": f"RSA-{bits}", "impl": "pyca", "family": "RSA", "level_bits": level, "ops": ops,
            # keygen is slow and noisy (prime search): fewer iterations, capped time
            "iters": 100, "keygen_iters": 5 if slow else 50, "keygen_max_s": 60 if slow else 30,
            "keygen_warmup": 0 if slow else 2,
            "pk_bytes": pk_bytes, "ct_bytes": len(c), "sk_bytes": sk_bytes, "ss_bytes": 32,
        }


def ecdh_cases():
    for name, (curve_cls, level) in EC_CURVES.items():
        curve = curve_cls()
        sk = ec.generate_private_key(curve)
        pk = sk.public_key()
        eph = ec.generate_private_key(curve)
        eph_pub = eph.public_key()

        def encaps(pk=pk, curve=curve):
            e = ec.generate_private_key(curve)
            return e.public_key().public_bytes(serialization.Encoding.X962, _UNCOMPRESSED), e.exchange(ec.ECDH(), pk)

        ops = {
            "keygen": lambda curve=curve: ec.generate_private_key(curve),
            "encaps": encaps,
            "decaps": lambda sk=sk, eph_pub=eph_pub: sk.exchange(ec.ECDH(), eph_pub),
        }
        point_len = len(pk.public_bytes(serialization.Encoding.X962, _UNCOMPRESSED))
        yield {
            "scheme": name, "impl": "pyca", "family": "ECC", "level_bits": level, "ops": ops,
            "iters": 1000, "pk_bytes": point_len, "ct_bytes": point_len,
            "sk_bytes": (curve.key_size + 7) // 8,
            "ss_bytes": len(sk.exchange(ec.ECDH(), eph_pub)),
        }


def x25519_cases():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    eph_pub = x25519.X25519PrivateKey.generate().public_key()

    def encaps(pk=pk):
        e = x25519.X25519PrivateKey.generate()
        return e.public_key().public_bytes_raw(), e.exchange(pk)

    ops = {
        "keygen": x25519.X25519PrivateKey.generate,
        "encaps": encaps,
        "decaps": lambda: sk.exchange(eph_pub),
    }
    yield {
        "scheme": "X25519", "impl": "pyca", "family": "ECC", "level_bits": 128, "ops": ops,
        "iters": 1000, "pk_bytes": 32, "ct_bytes": 32, "sk_bytes": 32, "ss_bytes": 32,
    }


def cases():
    yield from rsa_cases()
    yield from ecdh_cases()
    yield from x25519_cases()
