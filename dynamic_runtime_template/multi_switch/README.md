# Dynamic Runtime Template: Multi-Switch

This document explains the dynamic multi-switch deployment framework in `dynamic_runtime_template/multi_switch/`.

It covers:

- profile-aware stage P4 generation
- per-switch CLI command generation
- BMv2 topology bring-up
- smoke validation and cleanup

---

## 1) Folder Layout

Key files:

- `reset_and_run_multi.sh`
- `scripts/generate_multi_commands.py`
- `tools/generate_n_switch_p4.py`
- `test_smoke_multi.sh`
- `stop_and_cleanup_multi.sh`
- `commands_s1.txt` ... `commands_sN.txt` (generated)
- `p4/ids_nn_dynamic_s*.p4` (generated)
- `output/ids_nn_dynamic_s*.json` (compiled BMv2 JSON)
- `templates/two_hidden/ids_nn_dynamic_s1.p4` ... `ids_nn_dynamic_s4.p4` (source templates for two-hidden profile)

---

## 2) Profiles and Switch Count Rules

Supported profiles:

- `one_hidden`
- `two_hidden`

Selection modes:

- explicit: set `MODEL_PROFILE=one_hidden` or `MODEL_PROFILE=two_hidden`
- automatic: `MODEL_PROFILE=auto` (detects `layer_2` in model JSON)

Switch-count constraints:

- `one_hidden`: `N_SWITCHES >= 2`
- `two_hidden`: fixed `N_SWITCHES=4`

If `two_hidden` is requested with any other switch count, scripts exit with an error.

---

## 3) End-to-End Deployment Script

Main orchestrator:

- `reset_and_run_multi.sh`

### 3.1 Environment variables

- `N_SWITCHES` (default: `4`)
- `MODEL_JSON` (default: `9_32_1/single_switch/python/output/ptq_model.json`)
- `MODEL_PROFILE` (default: `auto`)
- `BASE_THRIFT_PORT` (default: `9090`)
- `SKIP_DEPLOY` (default: `no`)
- `NO_RECIPROCAL_INIT` (default: `no`)
- `SW_LOG_DIR` (default: `/tmp/p4nn_multi_switch_logs`)

### 3.2 Deployment stages performed

`reset_and_run_multi.sh` runs these steps:

1. Generate stage P4 files (`tools/generate_n_switch_p4.py`)
2. Compile each stage via `p4c-bm2-ss` into `output/ids_nn_dynamic_sX.json`
3. Generate per-switch command files (`scripts/generate_multi_commands.py`)
4. Cleanup old BMv2 and interfaces (`stop_and_cleanup_multi.sh`)
5. Build linear topology (`veth_h1 <-> s1 <-> ... <-> sN <-> veth_h2`)
6. Start `simple_switch` processes for all stages
7. Load `commands_sX.txt` into each switch with `simple_switch_CLI`

If `SKIP_DEPLOY=yes`, it stops after compile + command generation.

---

## 4) Stage P4 Generation

Script:

- `tools/generate_n_switch_p4.py`

### 4.1 one_hidden profile behavior

- supports variable `--num-switches >= 2`
- S1 is fixed to hidden neurons `0..7`
- remaining neurons (`8..31`) are chunked across `S2..SN`
- final switch uses the output-stage variant
- writes stage layout manifest: `p4/switch_layout.json`

### 4.2 two_hidden profile behavior

- supports exactly `--num-switches 4`
- uses `templates/two_hidden/ids_nn_dynamic_s1..s4.p4`
- preserves existing fixed split semantics:
  - H1 ranges: `0..7`, `8..15`, `16..23`, `24..31`
  - H2 ranges: `0..3`, `4..7`, `8..11`, `12..15`

### 4.3 Example

```bash
python3 dynamic_runtime_template/multi_switch/tools/generate_n_switch_p4.py \
  --profile one_hidden \
  --num-switches 6 \
  --output-dir dynamic_runtime_template/multi_switch/p4
```

---

## 5) Multi-Switch Command Generation

Script:

- `scripts/generate_multi_commands.py`

Output:

- `commands_s1.txt` ... `commands_sN.txt`

Generated content includes:

- route entries per stage (`ipv4_lpm`)
- feature map/mask and reciprocal setup on S1
- stage-local neuron tables and biases
- threshold register write on final stage
- stage active-neuron registers

### 5.1 one_hidden command distribution

- S1 keeps fixed behavior and writes H1 neurons `0..7`
- H1 neurons `8..31` distributed across `S2..SN`
- each stage gets local active neuron count register

### 5.2 two_hidden command distribution

- default split follows historical fixed 4-stage mapping
- script can use low-neuron balancing mode internally for sparse models
- validates stage-local dependency constraints for H2 when fixed mode is active

### 5.3 Example

```bash
python3 dynamic_runtime_template/multi_switch/scripts/generate_multi_commands.py \
  --model-json 9_32_16_1/single_switch/python/output/ptq_model.json \
  --profile two_hidden \
  --num-switches 4 \
  --output-dir dynamic_runtime_template/multi_switch
```

---

## 6) Smoke Test

Script:

- `test_smoke_multi.sh`

What it validates:

1. deployment starts expected number of `simple_switch` processes
2. all `commands_sX.txt` files exist and are non-empty
3. register read sanity checks:
   - S1: `MyIngress.feature_mask_reg[0]`
   - SN: `MyIngress.threshold_reg[0]`
4. for `one_hidden`, reads `active_local_neuron_count_reg` on S2..SN

Example:

```bash
N_SWITCHES=4 MODEL_PROFILE=auto MODEL_JSON=9_32_1/single_switch/python/output/ptq_model.json \
  dynamic_runtime_template/multi_switch/test_smoke_multi.sh
```

---

## 7) Cleanup

Script:

- `stop_and_cleanup_multi.sh`

Actions:

- kill `simple_switch` processes (configurable)
- remove BMv2 notification IPC files
- delete host and inter-switch `veth_*` interfaces

Config variables:

- `N_SWITCHES` (default `4`)
- `REMOVE_ALL_IPC` (default `yes`)
- `KILL_ALL_SWITCHES` (default `yes`)

---

## 8) Typical Usage Recipes

### 8.1 one_hidden with variable N

```bash
cd dynamic_runtime_template/multi_switch
N_SWITCHES=6 \
MODEL_PROFILE=one_hidden \
MODEL_JSON=../../9_32_1/single_switch/python/output/ptq_model.json \
./reset_and_run_multi.sh
```

### 8.2 two_hidden fixed 4-switch pipeline

```bash
cd dynamic_runtime_template/multi_switch
N_SWITCHES=4 \
MODEL_PROFILE=two_hidden \
MODEL_JSON=../../9_32_16_1/single_switch/python/output/ptq_model.json \
./reset_and_run_multi.sh
```

### 8.3 compile and generate only (no deployment)

```bash
cd dynamic_runtime_template/multi_switch
N_SWITCHES=4 MODEL_PROFILE=auto SKIP_DEPLOY=yes ./reset_and_run_multi.sh
```

---

## 9) Troubleshooting

- Error: `MODEL_JSON not found`
  - fix model path relative to current working directory
- Error: `N_SWITCHES must be >= 2`
  - use at least 2 switches
- Error: `two_hidden ... requires N_SWITCHES=4`
  - set `N_SWITCHES=4` for two-hidden profile
- Compile failure in stage `sX`
  - inspect printed compile log from `reset_and_run_multi.sh`
- Missing `commands_sX.txt`
  - rerun `generate_multi_commands.py` and verify model/profile compatibility

---

## 10) Notes

- The deployment scripts assume Linux networking tools (`ip`, `sudo`) and BMv2 binaries (`simple_switch`, `simple_switch_CLI`, `p4c-bm2-ss`) are installed.
- Command generation can run independently from switch deployment, which is useful for CI artifact validation.
