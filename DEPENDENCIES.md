# PeMCP Dependency Notes

This document records known dependency conflicts, version constraints,
and workarounds used in the Docker build.  If the container build breaks
after a `--no-cache` rebuild, start here.

---

## Quick reference — build-time assertions

The Dockerfile includes a build-time check that will **fail the build**
if the unicorn module is broken:

```
assert hasattr(unicorn, 'UC_ARCH_RISCV'), 'UC_ARCH_RISCV missing!'
```

If you see `UC_ARCH_RISCV missing!` during `podman build`, the unicorn
namespace collision (described below) has resurfaced.

---

## 1. The unicorn trilogy: angr, speakeasy, unipacker

Three packages each need the `unicorn` CPU emulator, but they need
**incompatible versions** and two of them silently clobber each other's
files.

| Package            | Needs unicorn | Why                                                         |
|--------------------|---------------|-------------------------------------------------------------|
| **angr\[unicorn\]**   | 2.x           | `archinfo` references `UC_ARCH_RISCV` (added in unicorn 2.0) |
| **speakeasy-emulator** | 1.x (==1.0.2) | Uses the internal `_uc` C API removed in unicorn 2.x        |
| **unipacker**      | 1.x (via `unicorn-unipacker`) | Fork of unicorn 1.x with the same Python namespace |

### The namespace collision (unicorn vs unicorn-unipacker)

`unicorn-unipacker` is a **separate pip package** but installs its files
into the same `site-packages/unicorn/` directory as the real `unicorn`
package.  When pip installs `unicorn-unipacker` *after* `unicorn`, the
1.x module files silently overwrite the 2.x files.  Critically, **pip's
package registry still records `unicorn==2.1.x`** so commands like
`pip install --upgrade "unicorn>=2.0.0"` see "Requirement already
satisfied" and do nothing.

Even `--force-reinstall` can be confused by the stale metadata.

### Current fix (Dockerfile lines 83-90)

```dockerfile
# Nuke both packages, then install unicorn fresh from PyPI.
RUN pip uninstall -y unicorn unicorn-unipacker 2>/dev/null; \
    pip install --no-cache-dir "unicorn>=2.0.0"
```

**This MUST remain the last `pip install` in the Dockerfile.**  Any later
`pip install` that pulls in `unicorn-unipacker` (or any other package
that writes to `site-packages/unicorn/`) will re-break angr.

### Speakeasy isolation

speakeasy-emulator is installed in a **separate virtualenv**
(`/app/speakeasy-venv`) because it hard-requires `unicorn==1.0.2`.
The main environment keeps unicorn 2.x for angr.

### Runtime safety net (pemcp/config.py)

The angr import block catches both `ImportError` and `AttributeError`:

```python
try:
    import angr
    import angr.analyses.decompiler
    ANGR_AVAILABLE = True
except (ImportError, AttributeError):
    ANGR_AVAILABLE = False
```

If unicorn is still broken at runtime, the server starts with angr
disabled instead of crashing.

---

## 2. setuptools < 81

The `unicorn` package calls `import pkg_resources` at import time.
setuptools 81+ removed `pkg_resources` entirely, causing an
`ImportError` on `import unicorn`.

**Fix:** Pin `setuptools<81` in the Dockerfile pip upgrade step.

A deprecation warning is also suppressed in application code
(`pemcp/__init__.py`).

---

## 3. oscrypto + OpenSSL 3.x

The PyPI release of `oscrypto` (1.3.0) does not support OpenSSL 3.x,
which is the default in Debian Bookworm.  Importing `signify` (which
depends on `oscrypto`) fails with an `OpenSSL` error.

**Fix:** Force-reinstall from a specific commit that adds OpenSSL 3
support:

```dockerfile
RUN pip install --no-cache-dir --force-reinstall \
    git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8
```

`--force-reinstall` is required because pip sees the same version number
(1.3.0) and skips the install otherwise.

---

## 4. Best-effort packages (unipacker, dotnetfile, binwalk, pygore)

These are installed with `|| true` so a failure in one does not block
the others or the entire build.  They may have fragile or conflicting
dependencies.

If any of these break the build, the simplest fix is to comment them
out — PeMCP will detect their absence at runtime and disable the
corresponding tools.

---

## 5. stringsifter pins

`stringsifter` pins `numpy<1.25`, `scikit-learn<1.4`, and
`joblib==1.3.x`.  These older versions are pulled in automatically by
pip's resolver.  If a future package requires newer numpy/scikit-learn,
stringsifter will need to be updated or isolated.

---

## Debugging a broken build

1. **Read the build log carefully.** Look for packages that install into
   the `unicorn` namespace or downgrade existing packages.
2. **Check the diagnostic step output.** The build prints both the main
   env and speakeasy venv unicorn versions.  Main env must be 2.x.
3. **Run an interactive shell** in a partial build to inspect:
   ```bash
   podman run --rm -it --entrypoint bash pemcp-toolkit
   python -c "import unicorn; print(unicorn.__version__, dir(unicorn))"
   pip list | grep -i unicorn
   ```
4. **If the assert fails**, the unicorn namespace has been clobbered
   again.  Check whether a new package (added after the uninstall step)
   pulls in `unicorn-unipacker` or another unicorn fork.

---

## Dockerfile install order (and why it matters)

```
1. angr[unicorn], nampa  → installs unicorn 2.x + archinfo, pyvex, cle, FLIRT parser
2. flare-floss, capa, vivisect
3. Core deps (pefile, requests, mcp, etc.)
4. Extended libs (lief, capstone, dnfile, dncil, etc.)
5. speakeasy-emulator    → isolated in /app/speakeasy-venv (unicorn 1.x)
6. unipacker             → installs unicorn-unipacker (clobbers unicorn 2.x!)
7. dotnetfile, binwalk, pygore
8. oscrypto patch
9. NUKE unicorn-unipacker + reinstall unicorn 2.x   ← MUST BE LAST
10. Assert UC_ARCH_RISCV exists                      ← build-time guard
```

Adding new pip packages?  Insert them **before step 9**.  Never add
anything after the unicorn restore step that could re-introduce a
unicorn fork.
