"""Optional liboqs backend (Track 2): the optimized C ML-KEM from Open Quantum Safe.

liboqs-python auto-downloads and builds liboqs when it cannot find one, which
we never want mid-test or mid-demo. So we only import `oqs` after pointing it
at our own build (Project/liboqs/install, or $OQS_INSTALL_PATH), and return
None if that build is missing.
"""
import os
from pathlib import Path

_DEFAULT_INSTALL = Path(__file__).resolve().parents[3] / "liboqs" / "install"

OQS_NAMES = {"ML-KEM-512": "ML-KEM-512", "ML-KEM-768": "ML-KEM-768", "ML-KEM-1024": "ML-KEM-1024"}


def _install_dir() -> Path | None:
    path = Path(os.environ.get("OQS_INSTALL_PATH", _DEFAULT_INSTALL))
    for dll in ("bin/liboqs.dll", "bin/oqs.dll", "lib/liboqs.so", "lib/liboqs.dylib"):
        if (path / dll).exists():
            return path
    return None


def load_oqs():
    """Return the `oqs` module, or None if liboqs or liboqs-python is unavailable."""
    install = _install_dir()
    if install is None:
        return None
    os.environ["OQS_INSTALL_PATH"] = str(install)
    if hasattr(os, "add_dll_directory") and (install / "bin").is_dir():
        os.add_dll_directory(str(install / "bin"))
    try:
        import oqs
    except (ImportError, RuntimeError, OSError):
        return None
    return oqs


def liboqs_version() -> str | None:
    oqs = load_oqs()
    return None if oqs is None else oqs.oqs_version()
