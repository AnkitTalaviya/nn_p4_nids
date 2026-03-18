#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
cd "$SCRIPT_DIR"

if [ -n "${VIRTUAL_ENV:-}" ]; then
  PYTHON_EXEC="${VIRTUAL_ENV}/bin/python3"
else
  PYTHON_EXEC=$(which python3)
fi

N_SWITCHES=${N_SWITCHES:-4}
BASE_THRIFT_PORT=${BASE_THRIFT_PORT:-9090}
MODEL_JSON=${MODEL_JSON:-"$REPO_ROOT/9-8-4-1/offline/python/output/ptq_model_9_8_4_1.json"}
CSV_FILE=${CSV_FILE:-"$REPO_ROOT/data/UNSW_NB15_testing-set.csv"}
SAMPLE_COUNT=${SAMPLE_COUNT:-1000}
POST_SEND_SLEEP_MS=${POST_SEND_SLEEP_MS:-8}
FEATURE_PORT=${FEATURE_PORT:-5555}
LIVE_TABLE=${LIVE_TABLE:-yes}
LIVE_TABLE_MAX_ROWS=${LIVE_TABLE_MAX_ROWS:-120}
MODEL_PROFILE=two_hidden
OUT_DIR="$SCRIPT_DIR/python/output"
ACC_LOG="$OUT_DIR/final_multi_switch_test.log"
ACC_CSV="$OUT_DIR/final_multi_switch_results.csv"

DYN_MULTI_RESET="$REPO_ROOT/dynamic_runtime_template/multi_switch/reset_and_run_multi.sh"

if [ ! -f "$DYN_MULTI_RESET" ]; then
  echo "Error: dynamic multi reset script not found: $DYN_MULTI_RESET" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
: > "$ACC_LOG"
exec > >(tee -a "$ACC_LOG") 2>&1

echo "========================================="
echo "DYNAMIC 4-SWITCH BMV2 NN IDS DEPLOYMENT"
echo "========================================="
echo "Model JSON    : $MODEL_JSON"
echo "Model profile : $MODEL_PROFILE"
echo "N_SWITCHES    : $N_SWITCHES"

echo "[1/2] Deploying dynamic multi-switch pipeline"
N_SWITCHES="$N_SWITCHES" \
MODEL_JSON="$MODEL_JSON" \
MODEL_PROFILE="$MODEL_PROFILE" \
BASE_THRIFT_PORT="$BASE_THRIFT_PORT" \
"$DYN_MULTI_RESET"

TAIL_THRIFT=$((BASE_THRIFT_PORT + N_SWITCHES - 1))

echo "[2/2] Running final multi-switch accuracy test"
export OUTPUT_CSV="$ACC_CSV"
sudo -E env \
  PATH="$PATH" \
  IFACE_IN=veth_h1 \
  THRIFT_S4="$TAIL_THRIFT" \
  MODEL_FILE="$MODEL_JSON" \
  CSV_FILE="$CSV_FILE" \
  SAMPLE_COUNT="$SAMPLE_COUNT" \
  FEATURE_PORT="$FEATURE_PORT" \
  POST_SEND_SLEEP_MS="$POST_SEND_SLEEP_MS" \
  LIVE_TABLE="$LIVE_TABLE" \
  LIVE_TABLE_MAX_ROWS="$LIVE_TABLE_MAX_ROWS" \
  OUTPUT_CSV="$OUTPUT_CSV" \
  "$PYTHON_EXEC" "$SCRIPT_DIR/final_multi_switch_accuracy_test.py"

echo "========================================="
echo "DONE: dynamic multi-switch deployment"
echo "========================================="
echo "Accuracy log: $ACC_LOG"
echo "Accuracy CSV: $ACC_CSV"
