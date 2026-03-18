# 9_32_1 Model: Dynamic IDS in P4 (Single-Switch + Multi-Switch)

This document is a full technical reference for the `9_32_1` pipeline in this repository.

It covers:

- Model representation and runtime profile
- Feature pipeline used during packet replay
- Dynamic command generation and switch deployment flow
- Single-switch and 4-switch execution behavior
- All recorded result metrics available in repository artifacts

---

## 1) Model Summary

`9_32_1` denotes a neural network with:

- 9 selected input features
- 32 hidden neurons (single hidden layer)
- 1 output neuron

In this project, the model is deployed through dynamic P4 templates and executed on BMv2.

Primary model file:

- `single_switch/python/output/ptq_model.json`

Current JSON fields present in this file:

- `selected_features`
- `feature_map`
- `feature_mask`
- `layer_0`
- `layer_1`
- `decision`

Note: unlike `5-4-1` offline JSONs, this `ptq_model.json` does not include explicit `architecture`, `quantization_scale`, or offline metric blocks.

---

## 2) Folder Layout

### 2.1 Single-switch path

- `single_switch/reset_and_run.sh`
- `single_switch/generate_cmd.py`
- `single_switch/final_switch_test.py`
- `single_switch/commands.txt`
- `single_switch/p4/output/ids_neuralnet_dynamic_9_32_1.json`
- `single_switch/python/output/ptq_model.json`
- `single_switch/python/output/final_switch_test.log`
- `single_switch/python/output/final_switch_results.csv`
- `single_switch/python/code/md_train_model.ipynb`

### 2.2 Multi-switch path

- `multi_switch/reset_and_run_multi.sh`
- `multi_switch/generate_multi_cmd.py`
- `multi_switch/final_multi_switch_accuracy_test.py`
- `multi_switch/tools/gen_multi_switch_p4.py`
- `multi_switch/python/output/final_multi_switch_test.log`
- `multi_switch/python/output/final_multi_switch_results.csv`

---

## 3) Model Artifact Details

From `single_switch/python/output/ptq_model.json`:

- Selected feature order used at runtime:
  1. `dur`
  2. `rate`
  3. `proto`
  4. `dpkts`
  5. `sttl`
  6. `dwin`
  7. `dttl`
  8. `smean`
  9. `sbytes`

- `feature_map`: `[8, 9, 0, 5, 1, 14, 12, 10, 2]`
- `feature_mask`: `511`
- Decision threshold: `-420650`

Weights/biases:

- `layer_0.weights`: 9 x 32 matrix
- `layer_0.biases`: 32 values
- `layer_1.weights`: 32 x 1 (stored as list/vector)
- `layer_1.biases`: output bias

This is the model consumed by both single-switch and multi-switch wrappers.

---

## 4) Feature Engineering Used During Accuracy Tests

Both `single_switch/final_switch_test.py` and `multi_switch/final_multi_switch_accuracy_test.py` build per-flow scaled integer features before switch decision checks.

Key constants:

- `MAX_DEN = 512`
- `DUR_SCALE = 0.001`
- `DUR_SHIFT = 20`
- `RATE_SHIFT = 10`
- `RECIP_SHIFT = 16`
- `MAX_PKTS_PER_FLOW = 200` (default)

### 4.1 Core mappings

- `proto` string -> numeric:
  - `tcp -> 6`
  - `udp -> 17`
  - `icmp -> 1`
  - fallback -> `255`

### 4.2 Scaled feature formulas (as implemented)

- `proto_scaled = min(proto << 4, 512)`
- `sttl_scaled = min(sttl << 1, 512)`
- `dttl_scaled = min(dttl << 1, 512)`
- `sbytes_scaled = min((sbytes - 24) >> 6, 512)` if `sbytes > 24` else 0
- `dbytes_scaled = min((dbytes - 24) >> 6, 512)` if `dbytes > 24` else 0
- `swin_scaled = min(swin >> 7, 512)` (TCP only)
- `dwin_scaled = min(dwin >> 7, 512)` (TCP only)
- `spkts_scaled = min((spkts - 1) << 2, 512)` if `spkts > 0` else 0
- `dpkts_scaled = min((dpkts - 1) << 2, 512)` if `dpkts > 0` else 0
- `totpkts_scaled = min((total_pkts - 1) << 2, 512)` if `total_pkts > 0` else 0
- `totbytes_scaled = min((total_bytes - 24) >> 6, 512)` if `total_bytes > 24` else 0

Flow-derived:

- `dur_scaled` from duration ns with `DUR_SCALE` and `DUR_SHIFT`, capped to 512
- `rate_scaled` via reciprocal lookup table, capped to 512
- `smean` and `dmean` via reciprocal packet-count tables, then:
  - `smean_scaled = min((smean - 24) >> 1, 512)` if `smean > 24` else 0
  - `dmean_scaled = min((dmean - 24) >> 1, 512)` if `dmean > 24` else 0

Runtime test ordering then selects the 9 values based on `selected_features` from model JSON.

---

## 5) Online Single-Switch Deployment

Entry script:

- `single_switch/reset_and_run.sh`

### 5.1 What the script does

1. Resolves Python interpreter from venv or `python3`
2. Uses model JSON at `single_switch/python/output/ptq_model.json`
3. Generates CLI commands with dynamic generator profile `one_hidden`
4. Compiles P4 source:
   - `dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4`
5. Resets old BMv2 process and veth interfaces
6. Starts `simple_switch`
7. Waits for thrift readiness (`9090`)
8. Loads `commands.txt` through `simple_switch_CLI`
9. Runs `single_switch/final_switch_test.py`

### 5.2 Generated command count (recorded)

From log:

- `Generated 1104 commands` into `single_switch/commands.txt`

### 5.3 Runtime defaults used

- `SAMPLE_COUNT = 5000` (in `final_switch_test.py`)
- `POST_SEND_SLEEP_MS = 50`
- `IFACE_IN = veth0_host`
- Output CSV via env `OUTPUT_CSV`

---

## 6) Online Multi-Switch Deployment (4 Switches)

Entry script:

- `multi_switch/reset_and_run_multi.sh`

### 6.1 What the script does

1. Calls dynamic template deploy script:
   - `dynamic_runtime_template/multi_switch/reset_and_run_multi.sh`
2. Uses:
   - `N_SWITCHES=4`
   - `MODEL_PROFILE=one_hidden`
   - `MODEL_JSON=9_32_1/single_switch/python/output/ptq_model.json`
3. Deploys multi-switch chain and loads per-switch command files
4. Runs `multi_switch/final_multi_switch_accuracy_test.py`
5. Writes log + CSV under `multi_switch/python/output`

### 6.2 Stage layout recorded in log

For 4-switch profile `one_hidden`:

- S1: hidden neurons 0..7
- S2: hidden neurons 8..15
- S3: hidden neurons 16..23
- S4: hidden neurons 24..31

Layout manifest path:

- `dynamic_runtime_template/multi_switch/p4/switch_layout.json`

### 6.3 Command counts recorded

- S1: `1054` commands
- S2: `19` commands
- S3: `19` commands
- S4: `22` commands

Thrift ports in deployment summary:

- `9090..9093`

Accuracy script reads final decision/debug registers from S4 thrift port (`THRIFT_S4`, default `9093`).

---

## 7) Online Results: Single-Switch

Sources:

- `single_switch/python/output/final_switch_test.log`
- `single_switch/python/output/final_switch_results.csv`

### 7.1 Test scope

- Samples tested: `5,000`
- Dataset selection message: `Selecting 5,000 random rows from 5,000 total entries`

### 7.2 Confusion matrix

- TP (Attack -> Blocked): `3276`
- FN (Attack -> Allowed): `124`
- FP (Normal -> Blocked): `563`
- TN (Normal -> Allowed): `1037`

### 7.3 Metrics

- Accuracy: `86.26%`
- Precision: `85.33%`
- Recall: `96.35%`
- F1 Score: `90.51%`

### 7.4 Threshold used at runtime

- Switch Threshold: `-420,650`

CSV-derived recomputation matches log:

- rows `5000`, TP `3276`, TN `1037`, FP `563`, FN `124`
- accuracy `0.8626`, precision `0.853347...`, recall `0.963529...`, f1 `0.905097...`

---

## 8) Online Results: Multi-Switch (4 Switches)

Sources:

- `multi_switch/python/output/final_multi_switch_test.log`
- `multi_switch/python/output/final_multi_switch_results.csv`

### 8.1 Test scope

- Samples tested: `5,000`
- Dataset selection message: `Selecting 5,000 random rows from 5,000 total entries`

### 8.2 Confusion matrix

- TP (Attack -> Blocked): `2584`
- FN (Attack -> Allowed): `816`
- FP (Normal -> Blocked): `416`
- TN (Normal -> Allowed): `1184`

### 8.3 Metrics

- Accuracy: `75.36%`
- Precision: `86.13%`
- Recall: `76.00%`
- F1 Score: `80.75%`

### 8.4 Threshold observed on final switch

- Switch Threshold (S4): `-420,650`

CSV-derived recomputation matches log:

- rows `5000`, TP `2584`, TN `1184`, FP `416`, FN `816`
- accuracy `0.7536`, precision `0.861333...`, recall `0.7600`, f1 `0.8075`

---

## 9) Single vs Multi Snapshot

On the recorded 5,000-row evaluation runs:

- Accuracy dropped from `86.26%` (single) to `75.36%` (multi)
- Precision increased slightly from `85.33%` to `86.13%`
- Recall dropped significantly from `96.35%` to `76.00%`
- FN increased from `124` to `816`

Interpretation based on these logs: multi-switch run is more conservative in blocking under this setup, causing higher misses (FN).

---

## 10) Reproduction

### 10.1 Single-switch

From repo root:

```bash
cd 9_32_1/single_switch
./reset_and_run.sh
```

Primary outputs:

- `9_32_1/single_switch/commands.txt`
- `9_32_1/single_switch/p4/output/ids_neuralnet_dynamic_9_32_1.json`
- `9_32_1/single_switch/python/output/final_switch_test.log`
- `9_32_1/single_switch/python/output/final_switch_results.csv`

### 10.2 Multi-switch

From repo root:

```bash
cd 9_32_1/multi_switch
./reset_and_run_multi.sh
```

Primary outputs:

- `9_32_1/multi_switch/python/output/final_multi_switch_test.log`
- `9_32_1/multi_switch/python/output/final_multi_switch_results.csv`
- Dynamic stage files and commands in `dynamic_runtime_template/multi_switch/`

---

## 11) Environment Variables

### 11.1 `single_switch/final_switch_test.py`

- `CSV_FILE` (default `../../data/newDataSet.csv`)
- `IFACE_IN` (default `veth0_host`)
- `SAMPLE_COUNT` (default `5000`)
- `MAX_PKTS_PER_FLOW` (default `200`)
- `DUR_SCALE` (default `0.001`)
- `POST_SEND_SLEEP_MS` (default `50`)
- `OUTPUT_CSV` (optional output path)
- `MODEL_FILE` (default `python/output/ptq_model.json`)

### 11.2 `multi_switch/final_multi_switch_accuracy_test.py`

- `CSV_FILE` (default `../../data/newDataSet.csv`)
- `MODEL_FILE` (default `../single_switch/python/output/ptq_model.json`)
- `IFACE_IN` (default `veth_h1`)
- `SAMPLE_COUNT` (default `5000`)
- `POST_SEND_SLEEP_MS` (default `50`)
- `THRIFT_S4` (default `9093`)
- `OUTPUT_CSV` (optional output path)
- `MAX_PKTS_PER_FLOW` (default `200`)
- `DUR_SCALE` (default `0.001`)

---

## 12) Integration Notes

- Single-switch wrapper uses dynamic profile `one_hidden` against shared P4 source:
  - `dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4`
- Multi-switch wrapper uses dynamic stage generation and compilation pipeline under:
  - `dynamic_runtime_template/multi_switch/`
- Stage neuron partitioning in 4-switch setup is contiguous and even (8 neurons per stage).
- Final drop/allow decision in multi-switch evaluation is read from last stage switch (S4).

---

## 13) Artifact Index

### Model + generated runtime files

- `9_32_1/single_switch/python/output/ptq_model.json`
- `9_32_1/single_switch/commands.txt`
- `9_32_1/single_switch/p4/output/ids_neuralnet_dynamic_9_32_1.json`
- `dynamic_runtime_template/multi_switch/commands_s1.txt`
- `dynamic_runtime_template/multi_switch/commands_s2.txt`
- `dynamic_runtime_template/multi_switch/commands_s3.txt`
- `dynamic_runtime_template/multi_switch/commands_s4.txt`

### Result logs + CSVs

- `9_32_1/single_switch/python/output/final_switch_test.log`
- `9_32_1/single_switch/python/output/final_switch_results.csv`
- `9_32_1/multi_switch/python/output/final_multi_switch_test.log`
- `9_32_1/multi_switch/python/output/final_multi_switch_results.csv`

### Entrypoints

- `9_32_1/single_switch/reset_and_run.sh`
- `9_32_1/multi_switch/reset_and_run_multi.sh`

---

## 14) Practical Notes

- For the recorded runs in this repository, single-switch deployment gives substantially higher overall detection quality than the current 4-switch flow-reconstruction deployment.
- Multi-switch keeps reasonably high precision but loses recall (higher misses), which is the dominant driver of performance drop.
- Both setups use the same model threshold (`-420650`), so differences are likely due to distributed pipeline behavior, flow state timing, or stage-wise feature/decision synchronization effects.
