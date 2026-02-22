# --- Base Image ---
# Pinned by digest for reproducible builds.  To update:
#   docker pull python:3.11-bookworm
#   docker inspect python:3.11-bookworm --format='{{index .RepoDigests 0}}'
# Then replace the digest below with the new one.
FROM python:3.11-bookworm@sha256:94c2dca43c9c127e42dfd021039cc83d8399752097612b49bdc7b00716b6d826

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
    rust-demangler \
    binary-refinery

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

# Copy the registry hive script early so the rootfs setup can use it.
# (Full scripts/ COPY happens later to preserve Docker layer caching.)
COPY scripts/create_registry_hives.py /app/scripts/create_registry_hives.py

RUN python <<'PYEOF'
import urllib.request, zipfile, os, sys, shutil, pathlib
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

# Create registry hive stubs using the shared script
# (canonical implementation lives in scripts/create_registry_hives.py)
sys.path.insert(0, "/app/scripts")
from create_registry_hives import ensure_registry_hives
ensure_registry_hives(str(rootfs_dir))

# Verify key rootfs directories exist and have content.
# NOTE: Windows DLLs are NOT included — users must provide them from a real
# Windows installation.  See docs/QILING_ROOTFS.md for setup instructions.
for d in ["x86_windows", "x8664_windows", "x8664_linux"]:
    p = rootfs_dir / d
    count = sum(1 for _ in p.rglob('*') if _.is_file()) if p.is_dir() else 0
    if count > 0:
        print(f"  rootfs OK: {d} ({count} files)")
    else:
        print(f"  rootfs MISSING or EMPTY: {d}")
PYEOF

# Make rootfs group-writable so the runtime registry-stub generator and
# user-mounted rootfs volumes work when the container runs as a non-root UID.
# A dedicated group (gid 1500) is used so the container user can write without
# full world-writable (777) permissions.  run.sh passes --group-add 1500.
RUN groupadd -g 1500 pemcp && \
    chown -R root:pemcp /app/qiling-rootfs && \
    chmod -R 775 /app/qiling-rootfs

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
# run.sh passes --user "$(id -u):$(id -g)" --group-add 1500 so the
# container runs as the host user with membership in the pemcp group.
# Group-writable (775) so any UID in the pemcp group can create
# ~/.pemcp/cache and config.json inside it.
RUN mkdir -p /app/home/.pemcp/cache && \
    chown -R root:pemcp /app/home && \
    chmod -R 775 /app/home

# --- Create writable output directory ---
# Default export/output directory for project archives, patched binaries, and reports.
# run.sh mounts a host directory here; without a mount this provides a writable fallback.
RUN mkdir -p /output && chown root:pemcp /output && chmod 775 /output

# --- Declare volumes ---
# Persistent cache and configuration
VOLUME ["/app/home/.pemcp"]
# Qiling rootfs — users can mount their own Windows DLLs, Linux libs, etc.
# See docs/QILING_ROOTFS.md for setup instructions.
VOLUME ["/app/qiling-rootfs"]

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
