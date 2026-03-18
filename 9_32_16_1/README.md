# 9_32_16_1 Model: Dynamic IDS in P4 (Single-Switch + 4-Switch)

This README is the detailed technical reference for the 9_32_16_1 model pipeline in this repository.

It covers:

- Model structure and serialized parameters
- Runtime feature engineering used by accuracy scripts
- Single-switch deployment flow
- Multi-switch deployment flow and stage partitioning
- Recorded metrics and confusion matrices from logs and CSV outputs
- Reproduction paths and generated artifacts

---

## 1) Model Summary

The model is a quantized two-hidden-layer network deployed into dynamic P4 templates.

Primary model artifact:

- single_switch/python/output/ptq_model.json

From model metadata in that file:

- Name: p4_neural_network_ids
- Date: 2026-02-11
- Architecture: 9-32-16-1
- Quantization scale: 512
- Total parameters: 865
- Hidden bias scale: 512
- Output bias scale: 262144
- Partial-flow augmentation:
  - enabled: true
  - samples_per_flow: 1
  - frac_min: 0.2
  - frac_max: 0.9

Selected runtime features:

1. dur
2. rate
3. proto
4. dpkts
5. sttl
6. dwin
7. dttl
8. smean
9. sbytes

Feature control values:

- feature_map: [8, 9, 0, 5, 1, 14, 12, 10, 2]
- feature_mask: 511

Decision rule from model JSON:

- type: threshold
- threshold: -420650
- rule: z3 >= threshold ? ATTACK : NORMAL

Layer definitions from model JSON:

- layer_0: dense, input_size 9, output_size 32, activation relu
- layer_1: dense, input_size 32, output_size 16, activation relu
- layer_2: dense, input_size 16, output_size 1, activation linear

Embedded model performance block:

- test_accuracy: 0.8819557319736969
- test_precision: 0.9470888439678381
- test_recall: 0.8754744806897881
- test_f1: 0.9098746832246208

---

## 2) Folder Layout

### 2.1 Single-switch path

- single_switch/reset_and_run.sh
- single_switch/generate_cmd.py
- single_switch/final_switch_test.py
- single_switch/commands.txt
- single_switch/p4/output/ids_neuralnet_dynamic_9_32_16_1.json
- single_switch/python/output/ptq_model.json
- single_switch/python/output/final_switch_test.log
- single_switch/python/output/final_switch_results.csv
- single_switch/python/code/md_train_model.ipynb

### 2.2 Multi-switch path

- multi_switch/reset_and_run_multi.sh
- multi_switch/generate_multi_cmd.py
- multi_switch/final_multi_switch_accuracy_test.py
- multi_switch/tools/gen_multi_switch_p4.py
- multi_switch/python/output/final_multi_switch_test.log
- multi_switch/python/output/final_multi_switch_results.csv

---

## 3) Runtime Feature Engineering

Both evaluation scripts:

- single_switch/final_switch_test.py
- multi_switch/final_multi_switch_accuracy_test.py

use the same scaled integer flow-feature derivation.

Core constants:

- MAX_DEN = 512
- DUR_SCALE = 0.001
- DUR_SHIFT = 20
- RATE_SHIFT = 10
- RECIP_SHIFT = 16
- MAX_PKTS_PER_FLOW = 200 (default)

Protocol mapping:

- tcp -> 6
- udp -> 17
- icmp -> 1
- fallback -> 255

Main transforms (capped at 512 where applicable):

- proto_scaled = proto << 4
- sttl_scaled = sttl << 1
- dttl_scaled = dttl << 1
- sbytes_scaled = (sbytes - 24) >> 6 if sbytes > 24 else 0
- dbytes_scaled = (dbytes - 24) >> 6 if dbytes > 24 else 0
- swin_scaled = swin >> 7 for TCP else 0
- dwin_scaled = dwin >> 7 for TCP else 0
- spkts_scaled = (spkts - 1) << 2 if spkts > 0 else 0
- dpkts_scaled = (dpkts - 1) << 2 if dpkts > 0 else 0
- totpkts_scaled = (total_pkts - 1) << 2 if total_pkts > 0 else 0
- totbytes_scaled = (total_bytes - 24) >> 6 if total_bytes > 24 else 0

Flow-derived values:

- dur_scaled from nanoseconds and DUR_SHIFT
- rate_scaled from reciprocal duration table
- smean and dmean from reciprocal packet-count tables
- smean_scaled = (smean - 24) >> 1 if smean > 24 else 0
- dmean_scaled = (dmean - 24) >> 1 if dmean > 24 else 0

Finally, the scripts pick the 9 values in the exact order listed by selected_features in model JSON.

---

## 4) Online Single-Switch Deployment

Entrypoint:

- single_switch/reset_and_run.sh

What it does:

1. Resolves Python executable (venv preferred)
2. Uses model JSON at single_switch/python/output/ptq_model.json
3. Calls dynamic command generator with profile two_hidden
4. Compiles dynamic P4 source:
   - dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_16_1.p4
5. Kills existing switch and rebuilds veth links
6. Starts BMv2 simple_switch
7. Waits for thrift on port 9090
8. Loads commands via simple_switch_CLI
9. Runs final accuracy test script and stores CSV/log outputs

Recorded header information from run log:

- Detected architecture: 9-32-16-1
- Profile: two_hidden
- Generated commands: 1137
- Evaluation sample size: 5000 rows

---

## 5) Online Multi-Switch Deployment (4 Switches)

Entrypoint:

- multi_switch/reset_and_run_multi.sh

What it does:

1. Invokes dynamic multi-switch deploy script in dynamic runtime template
2. Uses N_SWITCHES = 4
3. Uses MODEL_PROFILE = two_hidden
4. Uses model JSON from single_switch/python/output/ptq_model.json
5. Deploys compiled stage programs and per-switch commands
6. Runs final multi-switch accuracy script

Recorded generation/deploy details from log:

- Profile: two_hidden
- Distribution mode: legacy_fixed_split
- Stage layout:
  - S1: H1 0..7 and H2 0..3
  - S2: H1 8..15 and H2 4..7
  - S3: H1 16..23 and H2 8..11
  - S4: H1 24..31 and H2 12..15
- Thrift ports: 9090..9093
- Final decision read from S4 during evaluation

Recorded command counts:

- commands_s1.txt: 1064
- commands_s2.txt: 28
- commands_s3.txt: 28
- commands_s4.txt: 31

---

## 6) Online Results: Single-Switch

Sources:

- single_switch/python/output/final_switch_test.log
- single_switch/python/output/final_switch_results.csv

Test scope:

- Samples tested: 5000

Confusion matrix:

- TP: 3331
- FN: 69
- FP: 683
- TN: 917

Metrics:

- Accuracy: 84.96%
- Precision: 82.98%
- Recall: 97.97%
- F1 Score: 89.86%

Threshold observed in log:

- Switch Threshold: -420,650

CSV recomputation confirms the same counts and proportions:

- rows: 5000
- accuracy: 0.8496
- precision: 0.8298455406078724
- recall: 0.9797058823529412
- f1: 0.8985702724575128

---

## 7) Online Results: Multi-Switch (4-Switch)

Sources:

- multi_switch/python/output/final_multi_switch_test.log
- multi_switch/python/output/final_multi_switch_results.csv

Test scope:

- Samples tested: 5000

Confusion matrix:

- TP: 2676
- FN: 724
- FP: 497
- TN: 1103

Metrics:

- Accuracy: 75.58%
- Precision: 84.34%
- Recall: 78.71%
- F1 Score: 81.42%

Threshold observed in log:

- Switch Threshold (S4): -420,650

CSV recomputation confirms the same counts and proportions:

- rows: 5000
- accuracy: 0.7558
- precision: 0.8433658997793886
- recall: 0.7870588235294118
- f1: 0.8142400730260154

---

## 8) Single vs Multi Snapshot

Comparing recorded runs on 5000 samples:

- Accuracy: 84.96% -> 75.58% (down 9.38 points)
- Precision: 82.98% -> 84.34% (up 1.36 points)
- Recall: 97.97% -> 78.71% (down 19.26 points)
- F1: 89.86% -> 81.42% (down 8.44 points)
- FN: 69 -> 724 (large increase)
- FP: 683 -> 497 (decrease)

Current behavior suggests multi-switch flow is more conservative for positives in this setup, producing fewer false alarms but notably more misses.

---

## 9) Reproduction

### 9.1 Reproduce single-switch run

From repository root:

- cd 9_32_16_1/single_switch
- ./reset_and_run.sh

Expected artifacts:

- 9_32_16_1/single_switch/commands.txt
- 9_32_16_1/single_switch/p4/output/ids_neuralnet_dynamic_9_32_16_1.json
- 9_32_16_1/single_switch/python/output/final_switch_test.log
- 9_32_16_1/single_switch/python/output/final_switch_results.csv

### 9.2 Reproduce multi-switch run

From repository root:

- cd 9_32_16_1/multi_switch
- ./reset_and_run_multi.sh

Expected artifacts:

- 9_32_16_1/multi_switch/python/output/final_multi_switch_test.log
- 9_32_16_1/multi_switch/python/output/final_multi_switch_results.csv
- dynamic_runtime_template/multi_switch/commands_s1.txt
- dynamic_runtime_template/multi_switch/commands_s2.txt
- dynamic_runtime_template/multi_switch/commands_s3.txt
- dynamic_runtime_template/multi_switch/commands_s4.txt

---

## 10) Environment Variables

Single-switch script variables (final_switch_test.py):

- CSV_FILE (default ../../data/newDataSet.csv)
- IFACE_IN (default veth0_host)
- SAMPLE_COUNT (default 5000)
- MAX_PKTS_PER_FLOW (default 200)
- DUR_SCALE (default 0.001)
- POST_SEND_SLEEP_MS (default 50)
- OUTPUT_CSV (optional)
- MODEL_FILE (default python/output/ptq_model.json)

Multi-switch script variables (final_multi_switch_accuracy_test.py):

- CSV_FILE (default ../../data/newDataSet.csv)
- MODEL_FILE (default ../single_switch/python/output/ptq_model.json)
- IFACE_IN (default veth_h1)
- SAMPLE_COUNT (default 5000)
- POST_SEND_SLEEP_MS (default 50)
- THRIFT_S4 (default 9093)
- OUTPUT_CSV (optional)
- MAX_PKTS_PER_FLOW (default 200)
- DUR_SCALE (default 0.001)

---

## 11) Artifact Index

Model and compiled/runtime artifacts:

- 9_32_16_1/single_switch/python/output/ptq_model.json
- 9_32_16_1/single_switch/commands.txt
- 9_32_16_1/single_switch/p4/output/ids_neuralnet_dynamic_9_32_16_1.json
- dynamic_runtime_template/multi_switch/commands_s1.txt
- dynamic_runtime_template/multi_switch/commands_s2.txt
- dynamic_runtime_template/multi_switch/commands_s3.txt
- dynamic_runtime_template/multi_switch/commands_s4.txt

Result artifacts:

- 9_32_16_1/single_switch/python/output/final_switch_test.log
- 9_32_16_1/single_switch/python/output/final_switch_results.csv
- 9_32_16_1/multi_switch/python/output/final_multi_switch_test.log
- 9_32_16_1/multi_switch/python/output/final_multi_switch_results.csv

Entrypoints:

- 9_32_16_1/single_switch/reset_and_run.sh
- 9_32_16_1/multi_switch/reset_and_run_multi.sh

---

## 12) Practical Notes

- The two-hidden profile uses the dedicated dynamic P4 program for 9-32-16-1 and stage-splitting logic for 4 switches.
- Both single and multi runs use the same threshold value (-420650), so observed differences primarily reflect runtime pipeline behavior rather than decision-threshold differences.
- If strict attack catch rate is priority, the recorded single-switch run currently performs better on recall.
- If reducing false positives is priority, the recorded multi-switch run shows fewer FP but at the cost of significantly higher FN.
