# --- Base Image ---
FROM python:3.11-bullseye

# --- Set Working Directory ---
WORKDIR /app

# --- Install System Dependencies ---
# ADDED: 'cmake' is required to build the Unicorn engine bindings from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# --- Upgrade Pip ---
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# --- Install Heavy Dependencies (Cached Layer) ---
RUN pip install --no-cache-dir \
    "angr[unicorn]" \
    flare-floss \
    flare-capa \
    vivisect

# --- Install Remaining Dependencies ---
# ADDED: 'unicorn' for fast emulation
RUN pip install --no-cache-dir \
    pefile \
    requests \
    cryptography \
    signify \
    yara-python \
    stringsifter \
    "mcp[cli]" \
    rapidfuzz

# --- Copy Script ---
COPY PeMCP.py .

# --- Expose Port ---
EXPOSE 8082

# --- Set Entrypoint ---
ENTRYPOINT ["python", "./PeMCP.py"]
