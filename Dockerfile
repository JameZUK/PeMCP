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

# --- Install libraries that may have complex deps (best-effort) ---
# Each installed separately so a failure in one doesn't block the others,
# but combined into a single layer to reduce image layer count.
RUN pip install --no-cache-dir unipacker || true && \
    pip install --no-cache-dir dotnetfile || true && \
    pip install --no-cache-dir binwalk || true && \
    pip install --no-cache-dir pygore || true

# --- Patch oscrypto for OpenSSL 3.x compatibility (bookworm ships OpenSSL 3) ---
RUN pip install --no-cache-dir --force-reinstall \
    git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8

# --- Restore unicorn 2.x (MUST be the last pip install) ---
# unicorn-unipacker (pulled in by unipacker) installs into the same
# site-packages/unicorn/ namespace as the real unicorn package,
# overwriting the 2.x module files with 1.x code.  pip's registry
# still shows unicorn==2.1.x so even --force-reinstall can be confused
# by the stale metadata.  Nuke both packages first, then install fresh.
RUN pip uninstall -y unicorn unicorn-unipacker 2>/dev/null; \
    pip install --no-cache-dir "unicorn>=2.0.0"

# Show the final unicorn versions for build-log diagnostics.
# Main env: unicorn 2.x → angr native unicorn bridge works.
# Speakeasy venv: unicorn 1.x → speakeasy emulation works.
RUN python -c "import unicorn; print('main env unicorn', unicorn.__version__); assert hasattr(unicorn, 'UC_ARCH_RISCV'), 'UC_ARCH_RISCV missing!'" && \
    /app/speakeasy-venv/bin/python -c "import unicorn; print('speakeasy venv unicorn', unicorn.__version__)"

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
