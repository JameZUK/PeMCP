# --- Base Image ---
# For reproducible production builds, pin by digest:
#   docker pull python:3.11-bookworm
#   docker inspect python:3.11-bookworm --format='{{index .RepoDigests 0}}'
# Then replace the FROM line with: FROM python:3.11-bookworm@sha256:<digest>
FROM python:3.11-bookworm

# --- Set Working Directory ---
WORKDIR /app

# Suppress "Running pip as root" warnings — we're in a container,
# there is no system package manager to conflict with.
ENV PIP_ROOT_USER_ACTION=ignore

# --- Install System Dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    cmake \
    libffi-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Upgrade Pip ---
# setuptools<81 is required: the unicorn package does `import pkg_resources`
# at import time, and setuptools 81+ removed pkg_resources entirely.
# The resulting deprecation *warning* is suppressed in application code
# (pemcp/__init__.py).
RUN pip install --no-cache-dir --upgrade pip "setuptools<81" wheel

# --- Install Heavy Dependencies (Cached Layer) ---
RUN pip install --no-cache-dir \
    "angr[unicorn]" \
    nampa \
    flare-floss \
    flare-capa \
    vivisect

# --- Install Core Dependencies ---
RUN pip install --no-cache-dir \
    pefile \
    requests \
    cryptography \
    signify \
    yara-python \
    stringsifter \
    joblib \
    numpy \
    "mcp[cli]" \
    rapidfuzz \
    networkx

# --- Install Extended Analysis Libraries (Optional but included in Docker) ---
RUN pip install --no-cache-dir \
    lief \
    capstone \
    keystone-engine \
    ppdeep \
    py-tlsh \
    pyelftools \
    dnfile \
    dncil \
    rustbininfo \
    rust-demangler

# --- Install speakeasy in an isolated venv (requires unicorn 1.x) ---
# speakeasy-emulator requires unicorn 1.x (uses internal _uc API removed
# in 2.x).  Instead of downgrading the main env's unicorn (which breaks
# angr's native unicorn bridge), we install speakeasy into its own venv
# and invoke it via subprocess at runtime.  This keeps angr fast (native
# unicorn 2.x) while speakeasy still works (unicorn 1.x in its venv).
RUN python -m venv /app/speakeasy-venv && \
    /app/speakeasy-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/speakeasy-venv/bin/pip install --no-cache-dir speakeasy-emulator

# --- Install unipacker in an isolated venv (requires unicorn 1.x) ---
# unipacker pulls in unicorn-unipacker, a fork of unicorn 1.x that
# installs into the same site-packages/unicorn/ namespace as the real
# unicorn package, silently overwriting 2.x module files with 1.x code.
# By isolating unipacker in its own venv we avoid the namespace collision
# entirely -- no more nuke-and-reinstall of unicorn after the build.
RUN python -m venv /app/unipacker-venv && \
    /app/unipacker-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/unipacker-venv/bin/pip install --no-cache-dir unipacker

# --- Install Qiling Framework in an isolated venv (requires unicorn 1.x) ---
# Qiling is built on the Unicorn engine and requires unicorn 1.x, which
# conflicts with the main env's unicorn 2.x (used by angr).  By isolating
# Qiling in its own venv we keep angr's native unicorn bridge intact while
# gaining Qiling's cross-platform binary emulation capabilities.
RUN python -m venv /app/qiling-venv && \
    /app/qiling-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/qiling-venv/bin/pip install --no-cache-dir qiling

# --- Pre-populate Qiling rootfs (OS-specific files needed for emulation) ---
# Qiling requires rootfs directories containing DLLs, registry hives, and
# other OS-specific files to emulate binaries.  We download these at build
# time from the official Qiling repository to avoid runtime downloads.
#
# IMPORTANT: Rootfs content lives in the dedicated qilingframework/rootfs
# repository, NOT in the main qiling repo (where examples/rootfs/ is a git
# submodule that GitHub archive zips do not include).
RUN python <<'PYEOF'
import urllib.request, zipfile, os, shutil, pathlib
rootfs_dir = pathlib.Path("/app/qiling-rootfs")
rootfs_dir.mkdir(exist_ok=True)
url = "https://github.com/qilingframework/rootfs/archive/refs/heads/master.zip"
zip_path = "/tmp/qiling-rootfs.zip"
urllib.request.urlretrieve(url, zip_path)
prefix = "rootfs-master/"
with zipfile.ZipFile(zip_path, 'r') as zf:
    for member in zf.namelist():
        if not member.startswith(prefix):
            continue
        rel = member[len(prefix):]
        if not rel:
            continue
        dest = rootfs_dir / rel
        if member.endswith('/'):
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(dest, 'wb') as dst:
                dst.write(src.read())
os.remove(zip_path)

# Windows rootfs needs registry hive files that the repo cannot legally
# distribute.  Generate minimal valid stubs (regf format with an empty
# root key) so Qiling's RegistryManager can initialise.
import struct
def _create_minimal_hive():
    base = bytearray(4096)
    base[0:4] = b'regf'
    struct.pack_into('<I', base, 0x04, 1)
    struct.pack_into('<I', base, 0x08, 1)
    struct.pack_into('<I', base, 0x14, 1)
    struct.pack_into('<I', base, 0x18, 5)
    struct.pack_into('<I', base, 0x20, 1)
    struct.pack_into('<I', base, 0x24, 0x20)
    struct.pack_into('<I', base, 0x28, 0x1000)
    struct.pack_into('<I', base, 0x2C, 1)
    ck = 0
    for i in range(0, 0x1FC, 4):
        ck ^= struct.unpack_from('<I', base, i)[0]; ck &= 0xFFFFFFFF
    struct.pack_into('<I', base, 0x1FC, ck)
    hbin = bytearray(4096)
    hbin[0:4] = b'hbin'
    struct.pack_into('<I', hbin, 0x08, 0x1000)
    # Root key cell: [size:4][nk record...]
    # nk record starts at co+4; field offsets are from nk start
    co = 0x20
    nk = co + 4
    kn = b'CMI-CreateHive{00000000-0000-0000-0000-000000000000}'
    ct = (4 + 0x4C + len(kn) + 7) & ~7  # cell size + nk header + name
    struct.pack_into('<i', hbin, co, -ct)
    hbin[nk:nk+2] = b'nk'
    struct.pack_into('<H', hbin, nk+0x02, 0x24)
    struct.pack_into('<I', hbin, nk+0x10, 0xFFFFFFFF)  # parent
    struct.pack_into('<I', hbin, nk+0x1C, 0xFFFFFFFF)  # stable subkey list
    struct.pack_into('<I', hbin, nk+0x20, 0xFFFFFFFF)  # volatile subkey list
    struct.pack_into('<I', hbin, nk+0x28, 0xFFFFFFFF)  # value list
    struct.pack_into('<I', hbin, nk+0x2C, 0xFFFFFFFF)  # security desc
    struct.pack_into('<I', hbin, nk+0x30, 0xFFFFFFFF)  # class name
    struct.pack_into('<H', hbin, nk+0x48, len(kn))     # key name length
    struct.pack_into('<H', hbin, nk+0x4A, 0)           # class name length
    hbin[nk+0x4C:nk+0x4C+len(kn)] = kn
    fo = co + ct
    fs = 0x1000 - fo
    if fs > 4: struct.pack_into('<i', hbin, fo, fs)
    return bytes(base + hbin)

hive_data = _create_minimal_hive()
for win_dir in ["x86_windows", "x8664_windows"]:
    reg_dir = rootfs_dir / win_dir / "Windows" / "registry"
    reg_dir.mkdir(parents=True, exist_ok=True)
    for hive in ["NTUSER.DAT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "HARDWARE"]:
        hive_path = reg_dir / hive
        if not hive_path.exists():
            hive_path.write_bytes(hive_data)
            print(f"  Created registry stub: {win_dir}/Windows/registry/{hive}")

# Verify key rootfs directories exist and have content.
# NOTE: Windows DLL stubs are generated at runtime by qiling_runner.py's
# _ensure_windows_dlls() function (called from _find_rootfs on first use).
# This avoids duplicating the PE generation code in the Dockerfile.
for d in ["x86_windows", "x8664_windows", "x8664_linux"]:
    p = rootfs_dir / d
    count = sum(1 for _ in p.rglob('*') if _.is_file()) if p.is_dir() else 0
    if count > 0:
        print(f"  rootfs OK: {d} ({count} files)")
    else:
        print(f"  rootfs MISSING or EMPTY: {d}")
PYEOF

# Make rootfs world-writable so the runtime download_qiling_rootfs tool can
# add new OS/arch combinations when the container runs as a non-root UID.
RUN chmod -R 777 /app/qiling-rootfs

# --- Install libraries that may have complex deps (best-effort) ---
# Each installed separately so a failure in one doesn't block the others,
# but combined into a single layer to reduce image layer count.
RUN pip install --no-cache-dir dotnetfile || true && \
    pip install --no-cache-dir binwalk || true && \
    pip install --no-cache-dir pygore || true

# --- Patch oscrypto for OpenSSL 3.x compatibility (bookworm ships OpenSSL 3) ---
RUN pip install --no-cache-dir --force-reinstall \
    git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8

# Show the final unicorn versions for build-log diagnostics.
# Main env: unicorn 2.x → angr native unicorn bridge works.
# Speakeasy venv: unicorn 1.x → speakeasy emulation works.
# Unipacker venv: unicorn 1.x (via unicorn-unipacker) → unipacker works.
# Qiling venv: unicorn 1.x → Qiling Framework emulation works.
RUN python -c "import unicorn; print('main env unicorn', unicorn.__version__); assert hasattr(unicorn, 'UC_ARCH_RISCV'), 'UC_ARCH_RISCV missing!'" && \
    /app/speakeasy-venv/bin/python -c "import unicorn; print('speakeasy venv unicorn', unicorn.__version__)" && \
    /app/unipacker-venv/bin/python -c "import unicorn; print('unipacker venv unicorn', unicorn.__version__)" && \
    /app/qiling-venv/bin/python -c "import unicorn; print('qiling venv unicorn', unicorn.__version__); from qiling import Qiling; print('qiling import OK')"

# --- Pre-populate capa rules (avoids runtime download + write permission issues) ---
# Downloaded at build time so the container never needs write access to /app.
RUN python <<'PYEOF' && rm -f /tmp/capa-rules.zip
import urllib.request, zipfile, shutil, os, pathlib
urllib.request.urlretrieve(
    "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.3.0.zip",
    "/tmp/capa-rules.zip")
zipfile.ZipFile("/tmp/capa-rules.zip").extractall("/tmp")
top = next(p for p in pathlib.Path("/tmp").iterdir() if p.name.startswith("capa-rules") and p.is_dir())
# The archive may have rules at top level or in a rules/ subdir — handle both
source = top / "rules" if (top / "rules").is_dir() else top
os.makedirs("/app/capa_rules_store", exist_ok=True)
shutil.move(str(source), "/app/capa_rules_store/rules")
if top.exists():
    shutil.rmtree(str(top))
PYEOF

# --- Copy Application Files ---
COPY PeMCP.py .
COPY pemcp/ ./pemcp/
COPY scripts/ ./scripts/
COPY userdb.txt .
COPY FastPrompt.txt .

# --- Create writable home directory for runtime data ---
# run.sh passes --user "$(id -u):$(id -g)" so the container runs as the
# host user.  HOME is set to /app/home which is world-readable/executable
# so any UID can create ~/.pemcp/cache and config.json inside it.
# 777 is intentional: the container runs as an arbitrary non-root UID
# (via --user) so the directory must be world-writable.
RUN mkdir -p /app/home/.pemcp/cache && chmod -R 777 /app/home

# --- Declare volume for persistent cache and configuration ---
VOLUME ["/app/home/.pemcp"]

# --- Expose Port ---
EXPOSE 8082

# --- Healthcheck for HTTP mode ---
# Only meaningful when running with --mcp-transport streamable-http.
# In stdio mode the port isn't open, so the check will fail (container
# still runs, Docker just marks it "unhealthy" — harmless).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8082/mcp')"]

# --- Set Entrypoint ---
ENTRYPOINT ["python", "./PeMCP.py"]
