#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Prefer active venv
if [ -n "${VIRTUAL_ENV:-}" ]; then
  PYTHON_EXEC="${VIRTUAL_ENV}/bin/python3"
else
  PYTHON_EXEC=$(which python3)
fi

N_SWITCHES=${N_SWITCHES:-4}
MODEL_JSON=${MODEL_JSON:-9_32_1/single_switch/python/output/ptq_model.json}
MODEL_PROFILE=${MODEL_PROFILE:-auto}
BASE_THRIFT_PORT=${BASE_THRIFT_PORT:-9090}
SKIP_DEPLOY=${SKIP_DEPLOY:-no}
NO_RECIPROCAL_INIT=${NO_RECIPROCAL_INIT:-no}
COMPILE_TMP_LOG="$(mktemp "/tmp/dyn_multi_p4c_XXXX.log")"
SW_LOG_DIR="${SW_LOG_DIR:-/tmp/p4nn_multi_switch_logs}"

cleanup() {
  rm -f "$COMPILE_TMP_LOG" 2>/dev/null || true
}
trap cleanup EXIT

if ! [[ "$N_SWITCHES" =~ ^[0-9]+$ ]]; then
  echo "Error: N_SWITCHES must be an integer >= 2" >&2
  exit 1
fi
if [ "$N_SWITCHES" -lt 2 ]; then
  echo "Error: N_SWITCHES must be >= 2" >&2
  exit 1
fi

if [ ! -f "$MODEL_JSON" ]; then
  echo "Error: MODEL_JSON not found: $MODEL_JSON" >&2
  exit 1
fi

if [[ ! "$MODEL_PROFILE" =~ ^(auto|one_hidden|two_hidden)$ ]]; then
  echo "Error: MODEL_PROFILE must be one of: auto, one_hidden, two_hidden" >&2
  exit 1
fi

if [ "$MODEL_PROFILE" = "auto" ]; then
  MODEL_PROFILE=$(
    "$PYTHON_EXEC" - "$MODEL_JSON" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, "r", encoding="utf-8") as f:
    d = json.load(f)
print("two_hidden" if "layer_2" in d else "one_hidden")
PY
  )
fi

if [ "$MODEL_PROFILE" = "two_hidden" ] && [ "$N_SWITCHES" -ne 4 ]; then
  echo "Error: two_hidden profile uses the earlier fixed split and requires N_SWITCHES=4" >&2
  exit 1
fi

mac_switch() {
  local idx="$1"
  local side="$2"
  printf "00:aa:00:00:%02x:%02x" "$idx" "$side"
}

print_header() {
  echo "========================================="
  echo "DYNAMIC N-SWITCH BMV2 NN IDS DEPLOYMENT"
  echo "========================================="
  echo "N_SWITCHES      : $N_SWITCHES"
  echo "MODEL_JSON      : $MODEL_JSON"
  echo "MODEL_PROFILE   : $MODEL_PROFILE"
  echo "BASE_THRIFT_PORT: $BASE_THRIFT_PORT"
  echo "SKIP_DEPLOY     : $SKIP_DEPLOY"
  echo "========================================="
}

print_header

echo "[1/7] Generating stage P4 files for profile=$MODEL_PROFILE"
"$PYTHON_EXEC" "$ROOT_DIR/tools/generate_n_switch_p4.py" \
  --profile "$MODEL_PROFILE" \
  --num-switches "$N_SWITCHES" \
  --output-dir "$ROOT_DIR/p4"

echo "[2/7] Compiling stage programs"
mkdir -p "$ROOT_DIR/output"
: > "$COMPILE_TMP_LOG"
for ((i=1; i<=N_SWITCHES; i++)); do
  {
    echo "===== switch s${i} compile ====="
    if ! p4c-bm2-ss --arch v1model \
      -o "$ROOT_DIR/output/ids_nn_dynamic_s${i}.json" \
      "$ROOT_DIR/p4/ids_nn_dynamic_s${i}.p4"; then
      echo "ERROR: compilation failed for switch s${i}" >&2
      exit 1
    fi
    echo
  } >> "$COMPILE_TMP_LOG" 2>&1 || {
    echo "Error: multi-switch P4 compilation failed" >&2
    echo ""
    echo "--- Multi-switch compile log ---"
    cat "$COMPILE_TMP_LOG"
    echo "--- End multi-switch compile log ---"
    exit 1
  }
done

echo "[3/7] Generating CLI commands"
GEN_ARGS=(
  --model-json "$MODEL_JSON"
  --profile "$MODEL_PROFILE"
  --num-switches "$N_SWITCHES"
  --output-dir "$ROOT_DIR"
)
if [[ "$NO_RECIPROCAL_INIT" =~ ^[Yy][Ee]?[Ss]$|^1$|^true$|^TRUE$ ]]; then
  GEN_ARGS+=(--no-reciprocal-init)
fi
"$PYTHON_EXEC" "$ROOT_DIR/scripts/generate_multi_commands.py" "${GEN_ARGS[@]}"

if [[ "$SKIP_DEPLOY" =~ ^[Yy][Ee]?[Ss]$|^1$|^true$|^TRUE$ ]]; then
  echo "[4/7] SKIP_DEPLOY is enabled: skipping topology/switch startup/CLI load"
  echo "DONE (compile + command generation only)"
  exit 0
fi

echo "[4/7] Cleaning old processes/interfaces"
N_SWITCHES="$N_SWITCHES" "$ROOT_DIR/stop_and_cleanup_multi.sh"

echo "[5/7] Building linear topology"
# Host link
sudo ip link add veth_h1 type veth peer name veth_s1l

# Inter-switch links
for ((i=1; i<N_SWITCHES; i++)); do
  j=$((i + 1))
  sudo ip link add "veth_s${i}r" type veth peer name "veth_s${j}l"
done

# Final host link
sudo ip link add "veth_s${N_SWITCHES}r" type veth peer name veth_h2

# Bring links up
sudo ip link set veth_h1 up
sudo ip link set veth_h2 up
sudo ip link set veth_h1 mtu 2000
sudo ip link set veth_h2 mtu 2000
for ((i=1; i<=N_SWITCHES; i++)); do
  sudo ip link set "veth_s${i}l" up
  sudo ip link set "veth_s${i}r" up
  sudo ip link set "veth_s${i}l" mtu 2000
  sudo ip link set "veth_s${i}r" mtu 2000
done

# Host IPs and MACs
sudo ip addr flush dev veth_h1 || true
sudo ip addr flush dev veth_h2 || true
sudo ip addr add 10.0.0.1/24 dev veth_h1
sudo ip addr add 10.0.0.2/24 dev veth_h2
sudo ip link set dev veth_h1 address 00:aa:00:00:10:01
sudo ip link set dev veth_h2 address 00:aa:00:00:10:02

# Switch MACs
for ((i=1; i<=N_SWITCHES; i++)); do
  mac_l=$(mac_switch "$i" 1)
  mac_r=$(mac_switch "$i" 2)
  sudo ip link set dev "veth_s${i}l" address "$mac_l"
  sudo ip link set dev "veth_s${i}r" address "$mac_r"
done

echo "[6/7] Starting $N_SWITCHES BMv2 switches"
sudo mkdir -p "$SW_LOG_DIR"
sudo rm -f "$SW_LOG_DIR"/s*.log 2>/dev/null || true
for ((i=1; i<=N_SWITCHES; i++)); do
  dev_id=$((i - 1))
  thrift_port=$((BASE_THRIFT_PORT + i - 1))
  notif="ipc:///tmp/bmv2-${dev_id}-notifications.ipc"
  log_file="$SW_LOG_DIR/s${i}.log"
  json_file="$ROOT_DIR/output/ids_nn_dynamic_s${i}.json"

  sudo simple_switch \
    --device-id "$dev_id" \
    --thrift-port "$thrift_port" \
    --notifications-addr "$notif" \
    --log-file "$log_file" \
    -i 0@"veth_s${i}l" \
    -i 1@"veth_s${i}r" \
    "$json_file" &
done
sleep 3

echo "[7/7] Loading tables/registers"
for ((i=1; i<=N_SWITCHES; i++)); do
  thrift_port=$((BASE_THRIFT_PORT + i - 1))
  cmd_file="$ROOT_DIR/commands_s${i}.txt"
  if [ ! -f "$cmd_file" ]; then
    echo "Error: missing command file $cmd_file" >&2
    exit 1
  fi
  simple_switch_CLI --thrift-port "$thrift_port" < "$cmd_file" > /dev/null
done

echo "========================================="
echo "DONE: N-switch deployment complete"
echo "  - Profile      : $MODEL_PROFILE"
echo "  - Switches     : $N_SWITCHES"
echo "  - Thrift ports : ${BASE_THRIFT_PORT}..$((BASE_THRIFT_PORT + N_SWITCHES - 1))"
echo "  - Model        : $MODEL_JSON"
echo "========================================="
