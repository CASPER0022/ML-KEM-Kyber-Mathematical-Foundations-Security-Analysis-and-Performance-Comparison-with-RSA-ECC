# Step 01 — Environment Setup (Day 1–2)

## Goal
Get a clean, reproducible Python environment with the crypto libraries and the project skeleton.

## What's already on this machine
- ⚠️ The first `python` on PATH (`E:\bin\python.exe`) is **broken**: it prints "Could not find platform independent libraries". **Don't use it.**
- ✅ `C:\Python313\python.exe` (3.13.7) is used for the venv. `C:\Program Files\Python312` (3.12.4) also works.
- ✅ `gcc` (MinGW-w64) 15.2
- Once the venv is activated, `python` and `pip` both point inside `.venv`, so the PATH mix-up no longer matters.

## ✅ STATUS: DONE (2026-09-26)
- venv at `mlkem/.venv` (Python 3.13.7), packages pinned in `mlkem/requirements.txt`
- `cryptography` **50.0.1** ships **ML-KEM-768/1024 natively** (`cryptography.hazmat.primitives.asymmetric.mlkem`), with no ML-KEM-512. That's a second, independent reference for Step 09.
- `pytest` → 3 passed (`tests/test_env.py`)
- `results/machine.txt` recorded (i5-12450HX, 8C/12T, 15.7 GB, Win 11)
- `.gitignore` at the repo root (`Project/`), `.gitkeep` in the empty folders. **You do:** `git init`, add the remote, commit, push.

## 1. Create the project folder and venv (Git Bash)

```bash
cd "E:/Downloads/SEM 7/Cryptography/Project"
mkdir -p mlkem/{src/mlkem,tests,vectors,bench,results,demo}
cd mlkem
/c/Python313/python -m venv .venv    # NOT the bare `python` (broken E:\bin one)
source .venv/Scripts/activate        # Git Bash on Windows
python -m pip install --upgrade pip
```

Check that the venv is active: `which python` should point inside `.venv/Scripts/`.

## 2. Install packages

```bash
python -m pip install pytest cryptography matplotlib pandas numpy psutil
python -m pip freeze > requirements.txt
```

| Package | Used for |
|---|---|
| `pytest` | unit tests and test-vector tests |
| `cryptography` (pyca) | RSA-2048/3072/4096, P-256/P-384, X25519 baselines (shared with Member D) |
| `matplotlib`, `pandas`, `numpy` | charts and result tables |
| `psutil` | recording machine info (CPU, RAM) in benchmark output |

`hashlib` (SHA3-256/512, SHAKE128/256) is in the standard library, so the from-scratch implementation has **no external crypto dependency**.

## 3. liboqs (Track 2)

This is covered in detail in Step 09. On Windows it's the fiddliest part, so **start it early** in parallel. You need `cmake` plus a compiler (Visual Studio Build Tools is the most reliable on Windows). A fallback plan is in Step 09.

## 4. Make `src/mlkem` importable

Create `mlkem/pyproject.toml`:

```toml
[project]
name = "mlkem"
version = "0.1.0"
requires-python = ">=3.10"

[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

Then:

```bash
touch src/mlkem/__init__.py
python -m pip install -e .
```

## 5. Version control

Share the code with the team through a git repo, e.g. a private GitHub repo:

```bash
cd "E:/Downloads/SEM 7/Cryptography/Project"
git init
printf ".venv/\n__pycache__/\n*.pyc\nresults/*.png\n" > .gitignore
```

## 6. Record the machine specs now (needed for the report)

```bash
python -c "import platform, psutil; print(platform.processor()); print(platform.platform()); print(psutil.cpu_count(logical=False), 'cores'); print(round(psutil.virtual_memory().total/2**30,1), 'GB RAM'); print(psutil.cpu_freq())"
```

Save the output to `results/machine.txt`.

## ✅ Done when
- [ ] `python -c "import mlkem, cryptography, hashlib; print(hashlib.sha3_256(b'').hexdigest())"` runs from inside the venv
      (expected: `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`)
- [ ] `pytest` runs (0 tests is fine for now)
- [ ] `results/machine.txt` saved
