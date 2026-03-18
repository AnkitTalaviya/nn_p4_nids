#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$SCRIPT_DIR"

if [ -n "${VIRTUAL_ENV:-}" ]; then
  PYTHON_EXEC="${VIRTUAL_ENV}/bin/python3"
else
  PYTHON_EXEC=$(which python3)
fi

MODEL_JSON=${MODEL_JSON:-"$SCRIPT_DIR/python/output/ptq_model.json"}
MODEL_PROFILE=one_hidden
DYN_P4="$REPO_ROOT/dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4"
DYN_GEN="$REPO_ROOT/dynamic_runtime_template/scripts/generate_commands.py"
P4_JSON="$SCRIPT_DIR/p4/output/ids_neuralnet_dynamic_9_32_1.json"
OUT_DIR="$SCRIPT_DIR/python/output"
ACC_LOG="$OUT_DIR/final_switch_test.log"
ACC_CSV="$OUT_DIR/final_switch_results.csv"
P4_TMP_LOG="$(mktemp "/tmp/9_32_1_p4c_XXXX.log")"
SW_TMP_LOG="$(mktemp "/tmp/9_32_1_bmv2_XXXX.log")"

cleanup() {
  rm -f "$P4_TMP_LOG" 2>/dev/null || true
  sudo rm -f "$SW_TMP_LOG" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$OUT_DIR"
: > "$ACC_LOG"
exec > >(tee -a "$ACC_LOG") 2>&1

if [ ! -f "$MODEL_JSON" ]; then
  echo "Error: model JSON not found: $MODEL_JSON" >&2
  exit 1
fi

if [ ! -f "$DYN_P4" ]; then
  echo "Error: dynamic P4 profile not found: $DYN_P4" >&2
  exit 1
fi

if [ ! -f "$DYN_GEN" ]; then
  echo "Error: dynamic command generator not found: $DYN_GEN" >&2
  exit 1
fi

echo "========================================="
echo "DYNAMIC SINGLE-SWITCH IDS DEPLOYMENT"
echo "========================================="
echo "Model JSON    : $MODEL_JSON"
echo "Model profile : $MODEL_PROFILE"
echo "P4 source     : $DYN_P4"
echo "Python        : $PYTHON_EXEC"

echo "--- 0. GENERATING COMMANDS (dynamic) ---"
"$PYTHON_EXEC" "$DYN_GEN" \
  --model-json "$MODEL_JSON" \
  --profile "$MODEL_PROFILE" \
  --output "$SCRIPT_DIR/commands.txt"

echo "--- 1. COMPILING DYNAMIC P4 ---"
mkdir -p "$SCRIPT_DIR/p4/output"
if command -v p4c-bm2-ss >/dev/null 2>&1; then
  if ! p4c-bm2-ss --arch v1model -o "$P4_JSON" "$DYN_P4" > "$P4_TMP_LOG" 2>&1; then
    echo "Error: P4 compilation failed"
    echo ""
    echo "--- P4 compile log ---"
    cat "$P4_TMP_LOG"
    echo "--- End P4 compile log ---"
    exit 1
  fi
elif command -v p4c >/dev/null 2>&1; then
  if ! p4c --target bmv2 --arch v1model -o "$P4_JSON" "$DYN_P4" > "$P4_TMP_LOG" 2>&1; then
    echo "Error: P4 compilation failed"
    echo ""
    echo "--- P4 compile log ---"
    cat "$P4_TMP_LOG"
    echo "--- End P4 compile log ---"
    exit 1
  fi
else
  echo "Error: no P4 compiler found (p4c-bm2-ss / p4c)" >&2
  exit 1
fi

echo "--- 2. KILLING OLD SWITCH ---"
sudo killall -9 simple_switch 2>/dev/null || true
sudo rm -f /tmp/bmv2-0-notifications.ipc
sleep 1

echo "--- 3. SETTING UP VETH INTERFACES ---"
sudo ip link del veth0_switch 2>/dev/null || true
sudo ip link del veth1_switch 2>/dev/null || true
sudo ip link add veth0_switch type veth peer name veth0_host
sudo ip link set veth0_switch up
sudo ip link set veth0_host up
sudo ip link add veth1_switch type veth peer name veth1_host
sudo ip link set veth1_switch up
sudo ip link set veth1_host up

echo "--- 4. STARTING SWITCH ---"
sudo simple_switch --log-file "$SW_TMP_LOG" -i 0@veth0_switch -i 1@veth1_switch "$P4_JSON" >/dev/null 2>&1 &
sleep 1

echo "--- 4b. WAITING FOR THRIFT (9090) ---"
ready=no
for _ in $(seq 1 20); do
  if echo "show_tables" | simple_switch_CLI --thrift-port 9090 >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 1
done
if [ "$ready" != "yes" ]; then
  echo "Error: simple_switch_CLI did not become ready on thrift port 9090" >&2
  if sudo test -s "$SW_TMP_LOG"; then
    echo ""
    echo "--- BMv2 startup log ---"
    sudo cat "$SW_TMP_LOG"
    echo "--- End BMv2 startup log ---"
  fi
  exit 1
fi

echo "--- 5. LOADING COMMANDS ---"
simple_switch_CLI --thrift-port 9090 < "$SCRIPT_DIR/commands.txt" > /dev/null

echo "--- 6. USING MODEL THRESHOLD ---"

echo "--- 7. RUNNING FINAL ACCURACY TEST ---"
export OUTPUT_CSV="$ACC_CSV"
sudo -E env PATH="$PATH" OUTPUT_CSV="$OUTPUT_CSV" "$PYTHON_EXEC" "$SCRIPT_DIR/final_switch_test.py"

echo "========================================="
echo "DONE: dynamic single-switch deployment"
echo "========================================="
