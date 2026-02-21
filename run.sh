#!/usr/bin/env bash
#
# PeMCP Helper Script
#
# Detects Docker or Podman and runs PeMCP with sensible defaults.
# Handles volume mounts, environment variables, and common modes.
#
# Usage:
#   ./run.sh                              Start HTTP MCP server
#   ./run.sh --stdio                      Start stdio MCP server
#   ./run.sh --analyze samples/mal.exe    Analyze a file (CLI mode)
#   ./run.sh --samples /path/to/files     Mount a custom samples directory
#   ./run.sh --build                      Build the container image
#   ./run.sh --shell                      Open a shell in the container
#   ./run.sh --help                       Show this help

set -euo pipefail

IMAGE_NAME="pemcp-toolkit"
CONTAINER_PORT="${PEMCP_PORT:-8082}"
SAMPLES_DIR="${PEMCP_SAMPLES:-$(cd "$(dirname "$0")" && pwd)/samples}"
CONTAINER_SAMPLES="/$(basename "$SAMPLES_DIR")"
ROOTFS_DIR="${PEMCP_ROOTFS:-$(cd "$(dirname "$0")" && pwd)/qiling-rootfs}"
OUTPUT_DIR="${PEMCP_OUTPUT:-$(cd "$(dirname "$0")" && pwd)/output}"

# --- Detect container runtime ---
detect_runtime() {
    if command -v docker &>/dev/null; then
        # Check if docker is actually working (not just installed alias)
        if docker info &>/dev/null 2>&1; then
            echo "docker"
            return
        fi
    fi
    if command -v podman &>/dev/null; then
        echo "podman"
        return
    fi
    echo ""
}

RUNTIME=$(detect_runtime)

if [[ -z "$RUNTIME" ]]; then
    echo "Error: Neither Docker nor Podman found (or Docker daemon not running)."
    echo ""
    echo "Install one of:"
    echo "  Docker:  https://docs.docker.com/get-docker/"
    echo "  Podman:  https://podman.io/getting-started/installation"
    exit 1
fi

echo "[*] Using container runtime: $RUNTIME"

# --- SELinux: add :z to bind mounts so the container can read/write files ---
SELINUX_SUFFIX=""
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    SELINUX_SUFFIX=",z"
fi

# --- Build image if it doesn't exist ---
ensure_image() {
    if ! $RUNTIME image inspect "$IMAGE_NAME" &>/dev/null; then
        echo "[*] Image '$IMAGE_NAME' not found. Building..."
        build_image
    fi
}

build_image() {
    echo "[*] Building $IMAGE_NAME..."
    $RUNTIME build -t "$IMAGE_NAME" "$(dirname "$0")"
    echo "[*] Build complete."
}

# --- Common run arguments ---
common_args() {
    local args=(
        --rm
        --user "$(id -u):$(id -g)"
        -e "HOME=/app/home"
        -e "USER=${USER:-pemcp}"
        -e "PEMCP_HOST_SAMPLES=$SAMPLES_DIR"
        -v "$SAMPLES_DIR:$CONTAINER_SAMPLES:ro${SELINUX_SUFFIX}"
        -v "pemcp-data:/app/home/.pemcp"
    )

    # Mount output directory if it exists (create it on first use)
    if [[ -n "${OUTPUT_DIR:-}" ]]; then
        mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
        if [[ -d "$OUTPUT_DIR" ]]; then
            args+=(-v "$OUTPUT_DIR:/output:rw${SELINUX_SUFFIX}")
            args+=(-e "PEMCP_HOST_EXPORT=$OUTPUT_DIR")
            args+=(-e "PEMCP_EXPORT_DIR=/output")
        fi
    fi

    # Mount Qiling rootfs if the directory exists on the host.
    # Users place Windows DLLs, Linux libs, etc. here for Qiling emulation.
    # See docs/QILING_ROOTFS.md for setup instructions.
    if [[ -d "$ROOTFS_DIR" ]]; then
        args+=(-v "$ROOTFS_DIR:/app/qiling-rootfs")
    fi

    # Pass VT_API_KEY if set
    if [[ -n "${VT_API_KEY:-}" ]]; then
        args+=(-e "VT_API_KEY=$VT_API_KEY")
    fi

    # Load .env file if present
    local env_file="$(dirname "$0")/.env"
    if [[ -f "$env_file" ]]; then
        args+=(--env-file "$env_file")
    fi

    echo "${args[@]}"
}

# --- Commands ---
cmd_http() {
    ensure_image
    local pemcp_vol_path
    pemcp_vol_path=$($RUNTIME volume inspect pemcp-data --format '{{.Mountpoint}}' 2>/dev/null || echo "pemcp-data (named volume)")
    echo "[*] Starting PeMCP HTTP server on port $CONTAINER_PORT..."
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)"
    echo "[*] Config/cache (.pemcp): $pemcp_vol_path"
    echo "[*] MCP endpoint: http://127.0.0.1:$CONTAINER_PORT/mcp"
    echo "[*] Press Ctrl+C to stop."
    echo ""
    # shellcheck disable=SC2046
    $RUNTIME run -it \
        $(common_args) \
        -p "$CONTAINER_PORT:8082" \
        "$IMAGE_NAME" \
        --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
        --samples-path "$CONTAINER_SAMPLES" \
        "$@"
}

cmd_stdio() {
    ensure_image
    local pemcp_vol_path
    pemcp_vol_path=$($RUNTIME volume inspect pemcp-data --format '{{.Mountpoint}}' 2>/dev/null || echo "pemcp-data (named volume)")
    echo "[*] Starting PeMCP in stdio MCP mode..." >&2
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)" >&2
    echo "[*] Config/cache (.pemcp): $pemcp_vol_path" >&2
    # shellcheck disable=SC2046
    $RUNTIME run -i \
        $(common_args) \
        "$IMAGE_NAME" \
        --mcp-server \
        --samples-path "$CONTAINER_SAMPLES" \
        "$@"
}

cmd_analyze() {
    ensure_image
    local file="$1"
    shift

    if [[ ! -f "$file" ]]; then
        echo "Error: File not found: $file"
        exit 1
    fi

    local abs_file
    abs_file="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    local dir
    dir="$(dirname "$abs_file")"
    local base
    base="$(basename "$abs_file")"

    echo "[*] Analyzing: $abs_file"
    # shellcheck disable=SC2046
    $RUNTIME run -it \
        $(common_args) \
        -v "$dir:/app/input:$MOUNT_OPTS" \
        "$IMAGE_NAME" \
        --input-file "/app/input/$base" --verbose \
        "$@"
}

cmd_shell() {
    ensure_image
    echo "[*] Opening shell in PeMCP container..."
    # shellcheck disable=SC2046
    $RUNTIME run -it \
        $(common_args) \
        --entrypoint /bin/bash \
        "$IMAGE_NAME"
}

show_help() {
    cat <<'EOF'
PeMCP Container Helper

Usage:
  ./run.sh [--samples <dir>] <command>

Commands:
  (default)                              Start HTTP MCP server
  --stdio                                Start stdio MCP server
  --analyze <file> [opts]                Analyze a file in CLI mode
  --build                                Build/rebuild the container image
  --shell                                Open a shell in the container
  --help                                 Show this help

Options:
  --samples <dir>   Mount a custom directory read-only into the container.
                    The container path mirrors the host folder name
                    (e.g. --samples ~/Downloads → /Downloads inside).
                    Default: ./samples/ next to this script (→ /samples).
  --output <dir>    Mount a writable output directory into the container at /output.
                    Used for project exports, patched binaries, and reports.
                    Default: ./output/ next to this script.
  --rootfs <dir>    Mount a Qiling rootfs directory into the container.
                    Place Windows DLLs, Linux libs, etc. here for emulation.
                    Default: ./qiling-rootfs/ next to this script.
                    See docs/QILING_ROOTFS.md for setup instructions.

Environment variables:
  VT_API_KEY        VirusTotal API key (passed into container)
  PEMCP_PORT        Host port for HTTP mode (default: 8082)
  PEMCP_SAMPLES     Default samples directory (overridden by --samples)
  PEMCP_OUTPUT      Default output directory (overridden by --output)
  PEMCP_ROOTFS      Default Qiling rootfs directory (overridden by --rootfs)

Examples:
  ./run.sh                                         # HTTP server, default samples/
  ./run.sh --stdio                                 # stdio server for Claude Code
  ./run.sh --samples ~/malware-zoo --stdio         # Mounted at /malware-zoo
  ./run.sh --analyze samples/suspicious.exe        # Analyze a single file
  ./run.sh --rootfs ~/qiling-rootfs                # Custom rootfs for Qiling
  VT_API_KEY=abc123 PEMCP_PORT=9000 ./run.sh       # Custom port + API key
  PEMCP_SAMPLES=~/samples ./run.sh --stdio         # Via environment variable

Notes:
  - Sample files are mounted read-only; the output directory is writable
  - The container path mirrors the host folder name
    (e.g. --samples ~/Downloads → /Downloads/yourfile.exe inside the container)
  - Default samples: ./samples/ → /samples/yourfile.exe
  - Default output: ./output/ → /output/ (writable, for exports and patched binaries)
  - Analysis cache persists in a named volume (pemcp-data)
  - Auto-detects Docker or Podman
EOF
}

# --- Parse all arguments, separating global flags from command + extras ---
COMMAND=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --samples)
            if [[ $# -lt 2 ]]; then
                echo "Error: --samples requires a directory path."
                exit 1
            fi
            SAMPLES_DIR="$(cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Samples directory not found: $2"
                exit 1
            }
            CONTAINER_SAMPLES="/$(basename "$SAMPLES_DIR")"
            shift 2
            ;;
        --rootfs)
            if [[ $# -lt 2 ]]; then
                echo "Error: --rootfs requires a directory path."
                exit 1
            fi
            ROOTFS_DIR="$(cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Rootfs directory not found: $2"
                exit 1
            }
            shift 2
            ;;
        --output)
            if [[ $# -lt 2 ]]; then
                echo "Error: --output requires a directory path."
                exit 1
            fi
            OUTPUT_DIR="$(mkdir -p "$2" 2>/dev/null; cd "$2" 2>/dev/null && pwd)" || {
                echo "Error: Cannot create/access output directory: $2"
                exit 1
            }
            shift 2
            ;;
        --help|-h|--build|--stdio|--analyze|--shell)
            COMMAND="$1"
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# --- Main ---
case "${COMMAND:-}" in
    --help|-h)
        show_help
        ;;
    --build)
        build_image
        ;;
    --stdio)
        cmd_stdio "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
    --analyze)
        if [[ ${#EXTRA_ARGS[@]} -lt 1 ]]; then
            echo "Error: --analyze requires a file path."
            echo "Usage: ./run.sh --analyze <file>"
            exit 1
        fi
        cmd_analyze "${EXTRA_ARGS[@]}"
        ;;
    --shell)
        cmd_shell
        ;;
    *)
        cmd_http "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
esac
