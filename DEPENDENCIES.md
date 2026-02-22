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

## 1. The unicorn quartet: angr, speakeasy, unipacker, qiling

Four packages each need the `unicorn` CPU emulator, but they need
**incompatible versions** and some of them silently clobber each other's
files.

| Package            | Needs unicorn | Why                                                         |
|--------------------|---------------|-------------------------------------------------------------|
| **angr\[unicorn\]**   | 2.x           | `archinfo` references `UC_ARCH_RISCV` (added in unicorn 2.0) |
| **speakeasy-emulator** | 1.x (==1.0.2) | Uses the internal `_uc` C API removed in unicorn 2.x        |
| **unipacker**      | 1.x (via `unicorn-unipacker`) | Fork of unicorn 1.x with the same Python namespace |
| **qiling**         | 1.x           | Uses unicorn 1.x internal APIs for CPU emulation            |

### The namespace collision (unicorn vs unicorn-unipacker)

`unicorn-unipacker` is a **separate pip package** but installs its files
into the same `site-packages/unicorn/` directory as the real `unicorn`
package.  When pip installs `unicorn-unipacker` *after* `unicorn`, the
1.x module files silently overwrite the 2.x files.  Critically, **pip's
package registry still records `unicorn==2.1.x`** so commands like
`pip install --upgrade "unicorn>=2.0.0"` see "Requirement already
satisfied" and do nothing.

Even `--force-reinstall` can be confused by the stale metadata.

### Current fix: venv isolation for speakeasy, unipacker, and qiling

All three unicorn-1.x packages are installed in **separate virtualenvs**
so their dependencies never touch the main environment:

- **speakeasy-emulator** → `/app/speakeasy-venv` (unicorn 1.x via
  `unicorn==1.0.2`).  Invoked via `scripts/speakeasy_runner.py`.
- **unipacker** → `/app/unipacker-venv` (unicorn 1.x via
  `unicorn-unipacker`).  Invoked via `scripts/unipacker_runner.py`.
- **qiling** → `/app/qiling-venv` (unicorn 1.x).  Invoked via
  `scripts/qiling_runner.py`.

The main environment keeps unicorn 2.x for angr.  No nuke-and-reinstall
step is needed because no conflicting package is installed in the
main env.

All three runners use the same subprocess pattern: the tool function
sends a JSON command via stdin, the runner script (executed with the
venv's Python) does the work, and returns a JSON result via stdout.

#### Stdout pollution guard

Emulator libraries (unipacker's `engine.emu()`, Qiling's emulation
core) print log and debug messages directly to stdout during execution.
Since the runners use stdout for JSON IPC with the parent process,
these log lines corrupt the JSON output and cause `json.loads()` to
fail in the parent.

**Fix:** Each runner redirects `sys.stdout` to `sys.stderr` before
dispatching the action, then restores it in a `finally` block before
writing the JSON result.  This sends emulator log output to stderr
(which the parent captures separately) while keeping stdout clean for
the JSON response.

#### Qiling Windows rootfs and registry hive stubs

Qiling requires OS-specific rootfs directories containing DLLs,
registry hives, and system files to initialise emulation.  Rootfs
content is downloaded from the dedicated **qilingframework/rootfs**
GitHub repository (not the main qiling repo, where `examples/rootfs/`
is a git submodule that GitHub archive zips do not include).

For Windows targets, Qiling's `RegistryManager` requires five registry
hive files (`NTUSER.DAT`, `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`)
that cannot be legally distributed.  PeMCP generates minimal valid
stubs — structurally correct regf-format files with an empty root key
node — at both Docker build time and at runtime (on first use).
These stubs satisfy Qiling's format parser so emulation can proceed.

The rootfs directory (`/app/qiling-rootfs`) is pre-populated at Docker
build time with Linux rootfs files.  Windows PE emulation additionally
requires real DLL files (ntdll.dll, kernel32.dll, etc.) copied from a
Windows installation — see `docs/QILING_ROOTFS.md` for instructions.

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

## 4. Best-effort packages (dotnetfile, binwalk, pygore)

These are installed with `|| true` so a failure in one does not block
the others or the entire build.  They may have fragile or conflicting
dependencies.

If any of these break the build, the simplest fix is to comment them
out — PeMCP will detect their absence at runtime and disable the
corresponding tools.

Note: unipacker was previously in this group but is now installed in
its own isolated venv (see section 1).

---

## 5. stringsifter pins

`stringsifter` pins `numpy<1.25`, `scikit-learn<1.4`, and
`joblib==1.3.x`.  These older versions are pulled in automatically by
pip's resolver.  If a future package requires newer numpy/scikit-learn,
stringsifter will need to be updated or isolated.

**Important:** The PyPI package name is **`stringsifter`**, not
`flare-stringsifter` (which does not exist on PyPI).

---

## 6. capa-rules version alignment

The bundled capa-rules must match the capa major version.  If you bump
`flare-capa` to a new major version, update the rules download URL in
**both** places:

- `pemcp/config.py` → `CAPA_RULES_ZIP_URL`
- `Dockerfile` → the `urllib.request.urlretrieve(...)` URL

Current alignment: **flare-capa >=9.0** with **capa-rules v9.3.0**.

---

## 7. Library API renames (runtime compatibility)

Several libraries renamed classes or APIs in newer versions, breaking
PeMCP's imports.  These are handled with compatibility shims:

| Library | Old API | New API (current) | Affected PeMCP files | Shim |
|---------|---------|-------------------|---------------------|------|
| **dncil** >=1.0.2 | `dncil.cil.error.CilError` | `dncil.cil.error.MethodBodyFormatError` | `config.py`, `tools_dotnet.py` | `import MethodBodyFormatError as CilError` |
| **angr** >=9.2.199 | `analyses.FlirtAnalysis()` | `analyses.Flirt()` | `tools_angr_disasm.py` | Direct rename + auto-load FLIRT sigs |
| **unipacker** >=1.0.8 | `UnpackerEngine(filepath, ...)` | `UnpackerEngine(Sample(filepath), ...)` | `scripts/unipacker_runner.py` | Wrap path in `Sample()` object (in venv runner) |
| **angr** >=9.2.199 | `ProcedureEngine()` (no args) | `ProcedureEngine(project)` | `tools_angr_dataflow.py` | Monkey-patch `VFG._get_simsuccessors` |

### dncil: CilError → MethodBodyFormatError

dncil v1.0.2 renamed the exception class.  PeMCP imports the new name
with an alias (`as CilError`) so all downstream `except CilError`
handlers continue to work.  Without this, `DNCIL_AVAILABLE` is set to
`False` at startup, silently disabling all .NET CIL tools.

### angr: FlirtAnalysis → Flirt

angr v9.2.199 renamed the FLIRT analysis plugin.  Additionally, the new
`Flirt()` API requires signatures to be pre-loaded via
`angr.flirt.load_signatures(path)`, unlike the old `FlirtAnalysis()`
which handled this internally.  PeMCP auto-discovers FLIRT signature
files from FLOSS's bundled sigs directory.

### unipacker: Sample object required

unipacker v1.0.8 changed `UnpackerEngine.__init__()` to expect a
`Sample` instance (from `unipacker.core`) instead of a raw file path
string.  `Sample()` wraps the path and performs YARA-based packer
detection.

### angr: VFG ProcedureEngine missing project argument

angr v9.2.199 refactored the engine class hierarchy so that
`SimEngine.__init__()` requires a `project` argument (it uses
`self.project.arch` internally).  The inheritance chain is:

```
SimEngine.__init__(self, project)        ← requires project
  └── SuccessorsEngine.__init__(self, project)
        └── ProcedureEngine (ProcedureMixin + SuccessorsEngine)
```

The bug is in `VFG._get_simsuccessors()` (in
`angr/analyses/vfg.py`), which has 3 error-handling fallback paths
that still call `ProcedureEngine()` **without** passing `project`:

```python
# angr/analyses/vfg.py, lines ~1432/1438/1445 (the buggy code)
except SimIRSBError as ex:
    inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
    sim_successors = ProcedureEngine().process(state, procedure=inst)
    #                              ^^^ missing self.project
```

The **main** execution path (`self.project.factory.successors()`) works
fine.  The crash only triggers when VFG encounters unsupported VEX
instructions (`SimIRSBError`), Claripy solver errors (`ClaripyError`),
or generic simulation errors (`SimError`) — all of which fall through
to the broken `ProcedureEngine()` calls.

**Fix:** PeMCP monkey-patches `VFG._get_simsuccessors` at import time
(in `pemcp/mcp/tools_angr_dataflow.py`).  The patched version is a
faithful copy of the original method with one change on each of the 3
error paths: `ProcedureEngine()` → `ProcedureEngine(self.project)`.
The `self.project` attribute is always available because `VFG` inherits
from `Analysis`, and the `AnalysisFactory` sets `self.project` before
`__init__` is called (see `angr/analyses/analysis.py` line ~246).

```python
# The patch (applied at module load time)
from angr.analyses.vfg import VFG

def _patched_get_simsuccessors(self, state, addr):
    # ... same as original, except:
    sim_successors = ProcedureEngine(self.project).process(state, procedure=inst)
    #                                ^^^^^^^^^^^^^ fix

VFG._get_simsuccessors = _patched_get_simsuccessors
```

The entire patch is wrapped in `try/except (ImportError, AttributeError)`
so it silently skips if a future angr version removes `VFG`, renames
`_get_simsuccessors`, or restructures the class hierarchy.

**Upstream status:** Bug present in angr 9.2.199 (latest on PyPI).
Not fixed upstream.  These are the only 3 call sites in the angr
codebase that call `ProcedureEngine()` without arguments.

**To remove this patch:** If a future angr release fixes the bug,
delete the monkey-patch block in `tools_angr_dataflow.py` (the
`try` block between the `import networkx` and the
`# ---- Reaching Definitions Analysis` comment).  No other code
changes are needed — the tool will use angr's native `VFG` method
automatically.

---

## 8. PyPI version ceilings for optional packages

Several optional packages have low version ceilings on PyPI — the latest
available version is *below* the minimum you might naively expect:

| Package | Latest on PyPI | Notes |
|---------|---------------|-------|
| **nampa** | 0.1.1 | Last release 2017 — unmaintained but functional |
| **dotnetfile** | 0.2.10 | Active; still pre-1.0 |
| **binwalk** | 2.1.0 | PyPI release is from 2015; 2.3.x+ only via GitHub |
| **pygore** | 0.5.0 | Last release Oct 2021 |
| **keystone-engine** | 0.9.2 | Last release 2020 |

The `requirements.txt` minimum constraints are set to values that can
actually be satisfied from PyPI.  If a package needs a newer version
only available from GitHub, install it in the Dockerfile via
`pip install git+https://...`.

---

## 9. Binary Refinery sub-dependencies

Binary Refinery is a large framework with 200+ units.  Many units are
self-contained, but some require optional packages that are **not** pulled
in automatically by `pip install binary-refinery`.  These are installed
best-effort in the Dockerfile:

| Package | Required by | Purpose |
|---------|-------------|---------|
| **pypcapkit[scapy]** | `pcap` unit | PCAP network capture parsing |
| **python-registry** | `winreg` unit | Windows registry hive parsing |
| **LnkParse3** | `lnk` unit | Windows .lnk shortcut parsing |
| **olefile** | OLE units | OLE/CFB document extraction |
| **msoffcrypto-tool** | `officecrypt` unit | Office document decryption |
| **Pillow** | `stego` unit | Image steganography extraction |
| **xdis** | `pyc` unit | Python bytecode decompilation |
| **xlrd2** | `xlmdeobf` unit | Excel 4.0 XLM macro deobfuscation |
| **python-evtx** | `evtx` unit | Windows Event Log (.evtx) parsing |
| **XLMMacroDeobfuscator** | `xlmdeobf` unit | XLM macro emulation engine |
| **pikepdf** (<=9.5) | `xtpdf` unit | PDF object/stream extraction |

If any of these are missing at runtime, the corresponding refinery unit
returns a `MissingModule` stub instead of functioning normally.  PeMCP's
tool wrappers detect this and return a clear error message.

---

## Debugging a broken build

1. **Read the build log carefully.** Look for packages that install into
   the `unicorn` namespace or downgrade existing packages.
2. **Check the diagnostic step output.** The build prints the main env,
   speakeasy venv, and unipacker venv unicorn versions.  Main env must
   be 2.x.
3. **Run an interactive shell** in a partial build to inspect:
   ```bash
   podman run --rm -it --entrypoint bash pemcp-toolkit
   python -c "import unicorn; print(unicorn.__version__, dir(unicorn))"
   pip list | grep -i unicorn
   ```
4. **If the assert fails**, the unicorn namespace has been clobbered
   again.  Check whether a new package installed in the main env pulls
   in `unicorn-unipacker` or another unicorn fork.

---

## Dockerfile install order (and why it matters)

```
 1. angr[unicorn], nampa  → installs unicorn 2.x + archinfo, pyvex, cle, FLIRT parser
 2. flare-floss, capa, vivisect
 3. Core deps (pefile, requests, mcp, etc.)
 4. Extended libs (lief, capstone, dnfile, dncil, binary-refinery, etc.)
 5. speakeasy-emulator    → isolated in /app/speakeasy-venv (unicorn 1.x)
 6. unipacker             → isolated in /app/unipacker-venv (unicorn 1.x)
 7. qiling                → isolated in /app/qiling-venv (unicorn 1.x)
 8. Qiling rootfs download + Windows registry hive stubs
 9. Binary Refinery sub-deps (best-effort): pypcapkit, python-registry,
    LnkParse3, olefile, msoffcrypto-tool, Pillow, xdis, xlrd2,
    python-evtx, XLMMacroDeobfuscator, pikepdf
10. dotnetfile, binwalk, pygore (best-effort, main env)
11. oscrypto patch
12. Assert UC_ARCH_RISCV exists                      ← build-time guard
```

Since speakeasy, unipacker, and qiling are all in isolated venvs,
there is no longer a nuke-and-reinstall step.  The main env's
unicorn 2.x is never touched after step 1.
