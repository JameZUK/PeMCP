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
        -v "$SAMPLES_DIR:$CONTAINER_SAMPLES:ro"
        -v "pemcp-data:/app/home/.pemcp"
    )

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
    echo "[*] Starting PeMCP HTTP server on port $CONTAINER_PORT..."
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)"
    echo "[*] MCP endpoint: http://127.0.0.1:$CONTAINER_PORT/mcp"
    echo "[*] Press Ctrl+C to stop."
    echo ""
    # shellcheck disable=SC2046
    $RUNTIME run -it \
        $(common_args) \
        -p "$CONTAINER_PORT:8082" \
        "$IMAGE_NAME" \
        --mcp-server --mcp-transport streamable-http --mcp-host 0.0.0.0 \
        "$@"
}

cmd_stdio() {
    ensure_image
    echo "[*] Starting PeMCP in stdio MCP mode..." >&2
    echo "[*] Samples mounted at: $CONTAINER_SAMPLES (from $SAMPLES_DIR)" >&2
    # shellcheck disable=SC2046
    $RUNTIME run -i \
        $(common_args) \
        "$IMAGE_NAME" \
        --mcp-server \
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
        -v "$dir:/app/input:ro" \
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

Environment variables:
  VT_API_KEY        VirusTotal API key (passed into container)
  PEMCP_PORT        Host port for HTTP mode (default: 8082)
  PEMCP_SAMPLES     Default samples directory (overridden by --samples)

Examples:
  ./run.sh                                         # HTTP server, default samples/
  ./run.sh --stdio                                 # stdio server for Claude Code
  ./run.sh --samples ~/malware-zoo --stdio         # Mounted at /malware-zoo
  ./run.sh --analyze samples/suspicious.exe        # Analyze a single file
  VT_API_KEY=abc123 PEMCP_PORT=9000 ./run.sh       # Custom port + API key
  PEMCP_SAMPLES=~/samples ./run.sh --stdio         # Via environment variable

Notes:
  - Files are mounted read-only; the container path mirrors the host folder name
    (e.g. --samples ~/Downloads → /Downloads/yourfile.exe inside the container)
  - Default: ./samples/ → /samples/yourfile.exe
  - Analysis cache persists in a named volume (pemcp-data)
  - Auto-detects Docker or Podman
EOF
}

# --- Parse global flags ---
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
        *)
            break
            ;;
    esac
done

# --- Main ---
case "${1:-}" in
    --help|-h)
        show_help
        ;;
    --build)
        build_image
        ;;
    --stdio)
        shift
        cmd_stdio "$@"
        ;;
    --analyze)
        shift
        if [[ $# -lt 1 ]]; then
            echo "Error: --analyze requires a file path."
            echo "Usage: ./run.sh --analyze <file>"
            exit 1
        fi
        cmd_analyze "$@"
        ;;
    --shell)
        cmd_shell
        ;;
    *)
        cmd_http "$@"
        ;;
esac
