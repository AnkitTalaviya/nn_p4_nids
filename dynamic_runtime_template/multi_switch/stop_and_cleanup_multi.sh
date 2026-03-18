#!/bin/bash
set -euo pipefail

N_SWITCHES=${N_SWITCHES:-4}
REMOVE_ALL_IPC=${REMOVE_ALL_IPC:-yes}
KILL_ALL_SWITCHES=${KILL_ALL_SWITCHES:-yes}

if ! [[ "$N_SWITCHES" =~ ^[0-9]+$ ]]; then
  echo "Error: N_SWITCHES must be an integer >= 2" >&2
  exit 1
fi
if [ "$N_SWITCHES" -lt 2 ]; then
  echo "Error: N_SWITCHES must be >= 2" >&2
  exit 1
fi

echo "========================================="
echo "DYNAMIC N-SWITCH CLEANUP"
echo "========================================="
echo "N_SWITCHES      : $N_SWITCHES"
echo "KILL_ALL_SWITCH : $KILL_ALL_SWITCHES"
echo "REMOVE_ALL_IPC  : $REMOVE_ALL_IPC"
echo "========================================="

if [[ "$KILL_ALL_SWITCHES" =~ ^[Yy][Ee]?[Ss]$|^1$|^true$|^TRUE$ ]]; then
  echo "[1/3] Stopping BMv2 processes"
  sudo killall -9 simple_switch 2>/dev/null || true
  sleep 1
else
  echo "[1/3] Skipping process kill"
fi

echo "[2/3] Removing BMv2 IPC files"
for ((i=0; i<N_SWITCHES; i++)); do
  sudo rm -f "/tmp/bmv2-${i}-notifications.ipc"
done
if [[ "$REMOVE_ALL_IPC" =~ ^[Yy][Ee]?[Ss]$|^1$|^true$|^TRUE$ ]]; then
  sudo rm -f /tmp/bmv2-*-notifications.ipc 2>/dev/null || true
fi

echo "[3/3] Removing topology interfaces"
sudo ip link del veth_h1 2>/dev/null || true
sudo ip link del veth_h2 2>/dev/null || true

while read -r ifn; do
  [ -z "$ifn" ] && continue
  sudo ip link del "$ifn" 2>/dev/null || true
done < <(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^veth_s[0-9]+[lr]$' || true)

echo "========================================="
echo "DONE: cleanup complete"
echo "========================================="
