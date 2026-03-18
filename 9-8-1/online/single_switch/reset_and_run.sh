#!/bin/bash
set -euo pipefail

# 9-8-1 end-to-end BMv2 deployment + accuracy/confusion-matrix test.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

if [ -n "${VIRTUAL_ENV:-}" ]; then
  PYTHON_EXEC="${PYTHON_EXEC:-${VIRTUAL_ENV}/bin/python3}"
else
  PYTHON_EXEC="${PYTHON_EXEC:-$(command -v python3)}"
fi
MODEL_JSON="${MODEL_JSON:-${REPO_ROOT}/9-8-1/offline/python/output/ptq_model_9_8_1.json}"
DATASET="${DATASET:-${REPO_ROOT}/data/UNSW_NB15_testing-set.csv}"
THRIFT_PORT="${THRIFT_PORT:-9090}"
SAMPLE_COUNT="${SAMPLE_COUNT:-1000}"              # 0 => full dataset
POST_SEND_SLEEP_MS="${POST_SEND_SLEEP_MS:-8}"
DYN_P4="${REPO_ROOT}/dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4"

OUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUT_DIR}"
P4_JSON="${P4_JSON:-${OUT_DIR}/ids_neuralnet_dynamic_9_32_1.json}"
ACC_LOG="${OUT_DIR}/final_switch_test_9_8_1.log"
ACC_CSV="${OUT_DIR}/final_switch_results_9_8_1.csv"
P4_TMP_LOG="$(mktemp "/tmp/9_8_1_p4c_XXXX.log")"
SW_TMP_LOG="$(mktemp "/tmp/9_8_1_bmv2_XXXX.log")"

cleanup() {
  rm -f "${P4_TMP_LOG}" 2>/dev/null || true
  sudo rm -f "${SW_TMP_LOG}" 2>/dev/null || true
}
trap cleanup EXIT

: > "${ACC_LOG}"
exec > >(tee -a "${ACC_LOG}") 2>&1

echo "========================================="
echo "9-8-1 BMV2 RESET AND RUN"
echo "========================================="
echo "Python:              ${PYTHON_EXEC}"
echo "Model:               ${MODEL_JSON}"
echo "P4 JSON:             ${P4_JSON}"
echo "Dataset:             ${DATASET}"
echo "Sample count:        ${SAMPLE_COUNT}"
echo ""

echo "--- 0) GENERATE COMMANDS (9-8-1 -> BMv2 tables) ---"
"${PYTHON_EXEC}" "${SCRIPT_DIR}/generate_cmd.py" --model-json "${MODEL_JSON}" --output "${SCRIPT_DIR}/commands.txt"

echo "--- 0b) COMPILE SHARED P4 PIPELINE ---"
if command -v p4c-bm2-ss >/dev/null 2>&1; then
  if ! p4c-bm2-ss --arch v1model -o "${P4_JSON}" "${DYN_P4}" > "${P4_TMP_LOG}" 2>&1; then
    echo "ERROR: P4 compilation failed."
    echo ""
    echo "--- P4 compile log ---"
    cat "${P4_TMP_LOG}"
    echo "--- End P4 compile log ---"
    exit 1
  fi
elif command -v p4c >/dev/null 2>&1; then
  if ! p4c --target bmv2 --arch v1model -o "${P4_JSON}" "${DYN_P4}" > "${P4_TMP_LOG}" 2>&1; then
    echo "ERROR: P4 compilation failed."
    echo ""
    echo "--- P4 compile log ---"
    cat "${P4_TMP_LOG}"
    echo "--- End P4 compile log ---"
    exit 1
  fi
else
  echo "ERROR: no P4 compiler found" >&2
  exit 1
fi

echo "--- 1) CLEANUP OLD SWITCH/INTERFACES ---"
sudo killall -9 simple_switch 2>/dev/null || true
sudo rm -f /tmp/bmv2-0-notifications.ipc
sudo ip link del veth0_switch 2>/dev/null || true
sudo ip link del veth1_switch 2>/dev/null || true
sleep 1

echo "--- 2) SETUP VETH INTERFACES ---"
sudo ip link add veth0_switch type veth peer name veth0_host
sudo ip link set veth0_switch up
sudo ip link set veth0_host up
sudo ip link add veth1_switch type veth peer name veth1_host
sudo ip link set veth1_switch up
sudo ip link set veth1_host up

echo "--- 3) START BMV2 SWITCH ---"
sudo simple_switch --log-file "${SW_TMP_LOG}" \
  -i 0@veth0_switch -i 1@veth1_switch "${P4_JSON}" >/dev/null 2>&1 &
SW_PID=$!
sleep 3
if ! ps -p "${SW_PID}" >/dev/null; then
  echo "ERROR: simple_switch failed to start."
  if sudo test -s "${SW_TMP_LOG}"; then
    echo ""
    echo "--- BMv2 startup log ---"
    sudo cat "${SW_TMP_LOG}"
    echo "--- End BMv2 startup log ---"
  fi
  exit 1
fi
echo "Switch PID: ${SW_PID}"

echo "--- 4) LOAD TABLE/REGISTER COMMANDS ---"
simple_switch_CLI --thrift-port "${THRIFT_PORT}" < "${SCRIPT_DIR}/commands.txt" >/dev/null

echo "--- 5) RUN 9-8-1 ACCURACY + CONFUSION MATRIX TEST ---"
sudo -E "${PYTHON_EXEC}" "${SCRIPT_DIR}/final_switch_test.py" \
  --dataset "${DATASET}" \
  --model-json "${MODEL_JSON}" \
  --sample-count "${SAMPLE_COUNT}" \
  --thrift-port "${THRIFT_PORT}" \
  --post-send-sleep-ms "${POST_SEND_SLEEP_MS}" \
  --output-csv "${ACC_CSV}"

echo ""
echo "========================================="
echo "DONE"
echo "========================================="
echo "Accuracy log: ${ACC_LOG}"
echo "Accuracy CSV: ${ACC_CSV}"
echo "Stop switch: sudo killall -9 simple_switch"
