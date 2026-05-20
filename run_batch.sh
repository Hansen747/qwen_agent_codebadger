#!/bin/bash
# Batch runner for CodeBadger vulnerability detection baseline
#
# Usage:
#   ./run_batch.sh                    # Run all projects with default model
#   ./run_batch.sh --model Qwen/Qwen3-8B --port 8000
#   ./run_batch.sh --model Qwen/Qwen2.5-72B-Instruct --port 8001

set -e

MODEL="${MODEL:-Qwen/Qwen3-32B}"
PORT="${PORT:-8000}"
CODEBADGER_PORT="${CODEBADGER_PORT:-4242}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --model) MODEL="$2"; shift 2;;
        --port) PORT="$2"; shift 2;;
        --codebadger-port) CODEBADGER_PORT="$2"; shift 2;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

MODEL_SHORT=$(echo "$MODEL" | sed 's|.*/||' | tr '[:upper:]' '[:lower:]')
RESULTS_DIR="results/${MODEL_SHORT}_$(date +%Y%m%d_%H%M%S)"

echo "========================================"
echo "CodeBadger Baseline Runner"
echo "========================================"
echo "Model:       $MODEL"
echo "vLLM port:   $PORT"
echo "CodeBadger:  localhost:$CODEBADGER_PORT"
echo "Results:     $RESULTS_DIR"
echo "========================================"

# Check vLLM is running
if ! curl -s "http://localhost:${PORT}/v1/models" > /dev/null 2>&1; then
    echo "[ERROR] vLLM not reachable at localhost:${PORT}"
    echo "Start with: vllm serve $MODEL --port $PORT"
    exit 1
fi

# Check CodeBadger is running
if ! curl -s "http://localhost:${CODEBADGER_PORT}/health" > /dev/null 2>&1; then
    echo "[ERROR] CodeBadger not reachable at localhost:${CODEBADGER_PORT}"
    echo "Start with: cd codebadger && docker compose up -d && python main.py"
    exit 1
fi

echo "[*] Both services are running. Starting analysis..."

python run_codebadger_agent.py \
    --all \
    --model "$MODEL" \
    --model-server "http://localhost:${PORT}/v1" \
    --codebadger-url "http://localhost:${CODEBADGER_PORT}/mcp" \
    --output-dir "$RESULTS_DIR"

echo "[*] Batch complete. Results in: $RESULTS_DIR"
