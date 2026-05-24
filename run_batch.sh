#!/bin/bash
# Batch runner for CodeBadger vulnerability detection baseline
#
# This script handles:
#   1. Starting Joern Docker container (if not running)
#   2. Starting CodeBadger MCP server (if not running)
#   3. Auto-detecting model name from vLLM endpoint
#   4. Running vulnerability detection on all test projects
#
# Usage:
#   ./run_batch.sh --vllm-url http://localhost:8000    # Only need vLLM address
#   ./run_batch.sh --vllm-url http://10.0.0.5:9015 --task-id exp_01
#   ./run_batch.sh --vllm-url http://localhost:8000 --projects-dir /path/to/projects

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEBADGER_DIR="${SCRIPT_DIR}/codebadger"
CODEBADGER_PORT=4242
VLLM_URL=""
TASK_ID=""
PROJECTS_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --vllm-url) VLLM_URL="$2"; shift 2;;
        --task-id) TASK_ID="$2"; shift 2;;
        --projects-dir) PROJECTS_DIR="$2"; shift 2;;
        --codebadger-port) CODEBADGER_PORT="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 --vllm-url <URL> [OPTIONS]"
            echo ""
            echo "Required:"
            echo "  --vllm-url URL        vLLM server URL (e.g. http://localhost:8000)"
            echo ""
            echo "Optional:"
            echo "  --task-id ID          Task ID for results (default: auto-generated)"
            echo "  --projects-dir DIR    Path to test projects directory"
            echo "  --codebadger-port N   CodeBadger port (default: 4242)"
            echo "  -h, --help            Show this help"
            exit 0;;
        *) echo "[ERROR] Unknown option: $1"; exit 1;;
    esac
done

if [[ -z "$VLLM_URL" ]]; then
    echo "[ERROR] --vllm-url is required"
    echo "Usage: $0 --vllm-url http://localhost:8000"
    exit 1
fi

# Strip trailing slash
VLLM_URL="${VLLM_URL%/}"

echo "========================================"
echo "  CodeBadger Baseline Runner"
echo "========================================"

# ─── Step 1: Check vLLM and auto-detect model ────────────────────────────────

echo "[1/4] Checking vLLM at ${VLLM_URL} ..."

MODELS_RESPONSE=$(curl -s "${VLLM_URL}/v1/models" 2>/dev/null) || true
if [[ -z "$MODELS_RESPONSE" ]]; then
    echo "[ERROR] vLLM not reachable at ${VLLM_URL}"
    echo "Make sure vLLM is running: vllm serve <model> --host 0.0.0.0 --port <port>"
    exit 1
fi

# Auto-detect model name from /v1/models response
MODEL=$(echo "$MODELS_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
models = data.get('data', [])
if models:
    print(models[0]['id'])
else:
    sys.exit(1)
" 2>/dev/null)

if [[ -z "$MODEL" ]]; then
    echo "[ERROR] Could not detect model from ${VLLM_URL}/v1/models"
    echo "Response: $MODELS_RESPONSE"
    exit 1
fi

echo "       Model detected: $MODEL"

# ─── Step 2: Start Joern Docker container ────────────────────────────────────

echo "[2/4] Starting Joern container ..."

if docker ps --format '{{.Names}}' | grep -q "codebadger-joern-server"; then
    echo "       Joern container already running."
else
    echo "       Starting Joern container via docker compose ..."
    docker compose -f "${CODEBADGER_DIR}/docker-compose.yml" up -d
    echo "       Waiting for container to be ready ..."
    sleep 3
    if ! docker ps --format '{{.Names}}' | grep -q "codebadger-joern-server"; then
        echo "[ERROR] Joern container failed to start"
        echo "Check: docker compose -f ${CODEBADGER_DIR}/docker-compose.yml logs"
        exit 1
    fi
    echo "       Joern container started."
fi

# ─── Step 3: Start CodeBadger MCP server ─────────────────────────────────────

echo "[3/4] Starting CodeBadger MCP server on port ${CODEBADGER_PORT} ..."

if curl -s "http://localhost:${CODEBADGER_PORT}/health" > /dev/null 2>&1; then
    echo "       CodeBadger already running."
else
    # Find Python in conda env or use system python
    PYTHON_BIN=""
    if [[ -n "$CONDA_PREFIX" ]]; then
        PYTHON_BIN="${CONDA_PREFIX}/bin/python"
    elif command -v python &>/dev/null; then
        PYTHON_BIN="python"
    elif command -v python3 &>/dev/null; then
        PYTHON_BIN="python3"
    fi

    if [[ -z "$PYTHON_BIN" ]]; then
        echo "[ERROR] No Python found. Activate your conda env first."
        exit 1
    fi

    echo "       Using Python: $PYTHON_BIN"
    echo "       Starting CodeBadger (log: /tmp/codebadger.log) ..."

    cd "${CODEBADGER_DIR}"
    nohup "$PYTHON_BIN" main.py > /tmp/codebadger.log 2>&1 &
    CODEBADGER_PID=$!
    cd "${SCRIPT_DIR}"

    # Wait for CodeBadger to become healthy (up to 30s)
    echo -n "       Waiting for health check "
    for i in $(seq 1 30); do
        if curl -s "http://localhost:${CODEBADGER_PORT}/health" > /dev/null 2>&1; then
            echo " OK (${i}s)"
            break
        fi
        echo -n "."
        sleep 1
        if [[ $i -eq 30 ]]; then
            echo " FAILED"
            echo "[ERROR] CodeBadger did not start within 30s"
            echo "Check logs: cat /tmp/codebadger.log"
            kill $CODEBADGER_PID 2>/dev/null || true
            exit 1
        fi
    done
fi

# ─── Step 4: Run detection ───────────────────────────────────────────────────

echo "[4/4] Running vulnerability detection ..."
echo ""
echo "  Model:       $MODEL"
echo "  vLLM:        ${VLLM_URL}/v1"
echo "  CodeBadger:  http://localhost:${CODEBADGER_PORT}/mcp"
if [[ -n "$TASK_ID" ]]; then
    echo "  Task ID:     $TASK_ID"
fi
if [[ -n "$PROJECTS_DIR" ]]; then
    echo "  Projects:    $PROJECTS_DIR"
fi
echo "========================================"
echo ""

# Build command args
EXTRA_ARGS=""
if [[ -n "$TASK_ID" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --task-id $TASK_ID"
fi
if [[ -n "$PROJECTS_DIR" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --projects-dir $PROJECTS_DIR"
fi

"${PYTHON_BIN:-python}" "${SCRIPT_DIR}/run_codebadger_agent.py" \
    --all \
    --model "$MODEL" \
    --model-server "${VLLM_URL}/v1" \
    --codebadger-url "http://localhost:${CODEBADGER_PORT}/mcp" \
    $EXTRA_ARGS

echo ""
echo "[*] Batch complete."
