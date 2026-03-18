#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

N_SWITCHES=${N_SWITCHES:-2}
MODEL_JSON=${MODEL_JSON:-9-8-1/offline/python/output/ptq_model_9_8_1.json}
MODEL_PROFILE=${MODEL_PROFILE:-auto}
BASE_THRIFT_PORT=${BASE_THRIFT_PORT:-9090}

if ! [[ "$N_SWITCHES" =~ ^[0-9]+$ ]]; then
  echo "Error: N_SWITCHES must be an integer >= 2" >&2
  exit 1
fi
if [ "$N_SWITCHES" -lt 2 ]; then
  echo "Error: N_SWITCHES must be >= 2" >&2
  exit 1
fi
if [[ ! "$MODEL_PROFILE" =~ ^(auto|one_hidden|two_hidden)$ ]]; then
  echo "Error: MODEL_PROFILE must be one of: auto, one_hidden, two_hidden" >&2
  exit 1
fi

if [ "$MODEL_PROFILE" = "auto" ]; then
  MODEL_PROFILE=$(python3 - "$MODEL_JSON" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    d = json.load(f)
print("two_hidden" if "layer_2" in d else "one_hidden")
PY
  )
fi

if [ "$MODEL_PROFILE" = "two_hidden" ] && [ "$N_SWITCHES" -ne 4 ]; then
  echo "Error: two_hidden profile requires N_SWITCHES=4" >&2
  exit 1
fi

cleanup() {
  N_SWITCHES="$N_SWITCHES" "$ROOT_DIR/stop_and_cleanup_multi.sh" >/tmp/dyn_smoke_cleanup.log 2>&1 || true
}
trap cleanup EXIT

echo "[smoke] Deploying N=$N_SWITCHES profile=$MODEL_PROFILE model=$MODEL_JSON"
N_SWITCHES="$N_SWITCHES" MODEL_JSON="$MODEL_JSON" MODEL_PROFILE="$MODEL_PROFILE" BASE_THRIFT_PORT="$BASE_THRIFT_PORT" \
  "$ROOT_DIR/reset_and_run_multi.sh" >/tmp/dyn_smoke_deploy.log 2>&1

echo "[smoke] Checking simple_switch process count"
count=$(pgrep -c simple_switch || true)
if [ "$count" -lt "$N_SWITCHES" ]; then
  echo "FAIL: expected at least $N_SWITCHES simple_switch processes, got $count" >&2
  exit 1
fi

echo "[smoke] Checking command files"
for ((i=1; i<=N_SWITCHES; i++)); do
  if [ ! -s "$ROOT_DIR/commands_s${i}.txt" ]; then
    echo "FAIL: missing or empty commands_s${i}.txt" >&2
    exit 1
  fi
done

echo "[smoke] Checking feature mask and threshold registers"
out_s1=$(echo 'register_read MyIngress.feature_mask_reg 0' | simple_switch_CLI --thrift-port "$BASE_THRIFT_PORT" 2>/dev/null || true)
if ! echo "$out_s1" | grep -q "MyIngress.feature_mask_reg\[0\]="; then
  echo "FAIL: could not read feature_mask_reg on S1" >&2
  exit 1
fi
val_s1=$(echo "$out_s1" | sed -n 's/.*MyIngress.feature_mask_reg\[0\]= *//p' | head -n1)

tail_port=$((BASE_THRIFT_PORT + N_SWITCHES - 1))
out_tail=$(echo 'register_read MyIngress.threshold_reg 0' | simple_switch_CLI --thrift-port "$tail_port" 2>/dev/null || true)
if ! echo "$out_tail" | grep -q "MyIngress.threshold_reg\[0\]="; then
  echo "FAIL: could not read threshold_reg on SN" >&2
  exit 1
fi
val_tail=$(echo "$out_tail" | sed -n 's/.*MyIngress.threshold_reg\[0\]= *//p' | head -n1)

echo "  S1 (thrift ${BASE_THRIFT_PORT}): feature_mask=${val_s1}"
echo "  SN (thrift ${tail_port}): threshold=${val_tail}"

if [ "$MODEL_PROFILE" = "one_hidden" ]; then
  echo "[smoke] Reading active_local_neuron_count_reg on S2..SN (S1 is fixed-width)"
  for ((i=2; i<=N_SWITCHES; i++)); do
    thrift_port=$((BASE_THRIFT_PORT + i - 1))
    out=$(echo 'register_read MyIngress.active_local_neuron_count_reg 0' | simple_switch_CLI --thrift-port "$thrift_port" 2>/dev/null || true)
    if ! echo "$out" | grep -q "MyIngress.active_local_neuron_count_reg\[0\]="; then
      echo "FAIL: could not read active_local_neuron_count_reg on switch S${i} (port ${thrift_port})" >&2
      exit 1
    fi
    val=$(echo "$out" | sed -n 's/.*MyIngress.active_local_neuron_count_reg\[0\]= *//p' | head -n1)
    echo "  S${i} (thrift ${thrift_port}): active_local_neuron_count=${val}"
  done
fi

echo "PASS: dynamic multi-switch smoke test succeeded"
