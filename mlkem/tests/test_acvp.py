"""Step 08: NIST ACVP test vectors for ML-KEM (FIPS 203).

Vectors: usnistgov/ACVP-Server, gen-val/json-files/ML-KEM-*-FIPS203/
internalProjection.json, stored in vectors/ (see vectors/SOURCE.md).
"""
import json
from pathlib import Path

import pytest

from mlkem.mlkem import check_dk, check_ek, decaps_internal, encaps_internal, keygen_internal
from mlkem.params import PARAMS

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


def _cases(filename: str, function: str | None = None) -> list:
    return list(_iter_cases(filename, function))


def _iter_cases(filename: str, function: str | None = None):
    data = json.loads((VECTORS / filename).read_text())
    for g in data["testGroups"]:
        if function is not None and g["function"] != function:
            continue
        p = PARAMS[g["parameterSet"]]
        for t in g["tests"]:
            yield pytest.param(p, t, id=f"{g['parameterSet']}-tc{t['tcId']}")


def b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


@pytest.mark.parametrize("p,t", _cases("keygen.json"))
def test_keygen(p, t):
    ek, dk = keygen_internal(p, b(t["d"]), b(t["z"]))
    assert ek == b(t["ek"])
    assert dk == b(t["dk"])


@pytest.mark.parametrize("p,t", _cases("encapdecap.json", "encapsulation"))
def test_encapsulation(p, t):
    K, c = encaps_internal(p, b(t["ek"]), b(t["m"]))
    assert c == b(t["c"])
    assert K == b(t["k"])


@pytest.mark.parametrize("p,t", _cases("encapdecap.json", "decapsulation"))
def test_decapsulation(p, t):
    """Covers both valid ciphertexts and modified ones (implicit rejection)."""
    assert decaps_internal(p, b(t["dk"]), b(t["c"])) == b(t["k"])


def _passes(check, p, key) -> bool:
    try:
        check(p, key)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("p,t", _cases("encapdecap.json", "encapsulationKeyCheck"))
def test_encapsulation_key_check(p, t):
    assert _passes(check_ek, p, b(t["ek"])) == t["testPassed"], t["reason"]


@pytest.mark.parametrize("p,t", _cases("encapdecap.json", "decapsulationKeyCheck"))
def test_decapsulation_key_check(p, t):
    assert _passes(check_dk, p, b(t["dk"])) == t["testPassed"], t["reason"]
