"""Step 01 sanity checks: environment and dependencies are wired up."""
import hashlib


def test_mlkem_package_importable():
    import mlkem  # noqa: F401


def test_sha3_available():
    assert hashlib.sha3_256(b"").hexdigest() == (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


def test_pyca_mlkem_roundtrip():
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

    sk = MLKEM768PrivateKey.generate()
    key, ct = sk.public_key().encapsulate()
    assert sk.decapsulate(ct) == key
    assert len(ct) == 1088
