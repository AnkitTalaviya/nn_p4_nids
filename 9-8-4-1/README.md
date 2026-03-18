# 9-8-4-1 Model: In-Network IDS (UNSW-NB15)

This README is a complete technical reference for the 9-8-4-1 model pipeline in this repository.

It covers:

- Offline training and quantization
- Exported model format and preprocessing
- Online single-switch BMv2 flow
- Online multi-switch BMv2 flow
- Verified metrics from logs and CSV outputs

---

## 1) Model Summary

- Model name: unsw_nb15_9_8_4_1_offline
- Architecture: 9 -> 8 -> 4 -> 1
- Hidden activations: ReLU, ReLU
- Output: logit with threshold decision
- Decision rule: attack_if_nn_result_gt_threshold
- Threshold: 70518
- Quantization scale: 512

Selected features:

1. proto
2. sttl
3. dttl
4. swin
5. dwin
6. service
7. state
8. sbytes
9. dbytes

Feature controls:

- feature_mask: 511
- feature_map: [0, 1, 2, 3, 4, 5, 6, 7, 8]

---

## 2) Folder Layout

### 2.1 Offline pipeline

- offline/python/code/train_9_8_4_1_offline.py
- offline/python/code/md_train_model_9_8_4_1.ipynb

### 2.2 Offline artifacts

- offline/python/output/ptq_model_9_8_4_1.json
- offline/python/output/offline_metrics_9_8_4_1.json
- offline/python/output/offline_test_predictions_9_8_4_1.csv

### 2.3 Online single-switch path

- online/single_switch/reset_and_run.sh
- online/single_switch/generate_cmd.py
- online/single_switch/final_switch_test.py
- online/single_switch/commands.txt
- online/single_switch/output/ids_neuralnet_dynamic_9_32_16_1.json
- online/single_switch/output/final_switch_test_9_8_4_1.log
- online/single_switch/output/final_switch_results_9_8_4_1.csv

### 2.4 Online multi-switch path

- online/multi_switch/reset_and_run_multi.sh
- online/multi_switch/generate_multi_cmd.py
- online/multi_switch/final_multi_switch_accuracy_test.py
- online/multi_switch/python/output/final_multi_switch_test.log
- online/multi_switch/python/output/final_multi_switch_results.csv

---

## 3) Offline Training and Quantization

Script:

- offline/python/code/train_9_8_4_1_offline.py

Pipeline behavior:

1. Load UNSW-NB15 train/test CSV files.
2. Encode categorical columns proto, service, state.
3. Fill missing values from train medians.
4. Standardize selected features.
5. Train MLPClassifier with hidden layers (8, 4).
6. Quantize layer weights/biases for integer inference path.
7. Calibrate integer threshold on validation logits.
8. Export model JSON, metrics JSON, prediction CSV.

Integer inference structure in training script:

- Layer 1 int MAC + ReLU + right shift 9
- Layer 2 int MAC + ReLU + right shift 9
- Output int MAC + threshold comparison

---

## 4) Exported Model Structure

File:

- offline/python/output/ptq_model_9_8_4_1.json

Includes:

- architecture block (input 9, hidden [8,4], output 1)
- selected_features, candidate_features, feature_map, feature_mask
- layer_0: 9x8 weights + 8 biases
- layer_1: 8x4 weights + 4 biases
- layer_2: 4x1 weights + output bias
- decision threshold block
- preprocessing:
  - category mappings for proto/service/state
  - scaler_mean/scaler_scale
  - train_feature_medians
- embedded metrics section

This offline export is the runtime source for both single and multi online flows.

---

## 5) Online Single-Switch Deployment

Entrypoint:

- online/single_switch/reset_and_run.sh

Main flow:

1. Generate commands using dynamic wrapper (profile two_hidden)
2. Compile dynamic P4 source:
   - dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_16_1.p4
3. Reset switch/interfaces and create veth pairs
4. Start BMv2 simple_switch
5. Load commands.txt via simple_switch_CLI
6. Run final_switch_test.py

Recorded details from log:

- Detected architecture: 9-8-4-1
- Profile: two_hidden
- Generated commands: 1137
- Dataset rows tested: 1000
- Model threshold: 70518
- Switch threshold: 70518

---

## 6) Online Multi-Switch Deployment

Entrypoint:

- online/multi_switch/reset_and_run_multi.sh

Main flow:

1. Call dynamic multi-switch deploy script with profile two_hidden
2. Generate/compile stage P4 programs in dynamic runtime template
3. Load per-switch command files
4. Run final_multi_switch_accuracy_test.py on tail switch thrift port

Recorded stage layout from log:

- Profile: two_hidden
- Stage generation summary:
  - S1: H1 0..7 and H2 0..3
  - S2: H1 8..15 and H2 4..7
  - S3: H1 16..23 and H2 8..11
  - S4: H1 24..31 and H2 12..15
- Runtime stage layout detail:
  - distribution_mode = low_neuron_partial_accumulate
  - S1 active: H1=2, H2=4
  - S2 active: H1=2, H2=4
  - S3 active: H1=2, H2=4
  - S4 active: H1=2, H2=4

Recorded command counts:

- commands_s1.txt: 1064
- commands_s2.txt: 28
- commands_s3.txt: 28
- commands_s4.txt: 31

Thrift range shown in deployment log:

- 9090..9093

---

## 7) Offline Results (Full Test Set)

Source:

- offline/python/output/offline_metrics_9_8_4_1.json

Dataset sizes:

- train_samples: 65865
- val_samples: 16467
- test_samples: 175341

### 7.1 Float model metrics

- Accuracy: 0.8717584592308701 (87.1758%)
- Precision: 0.9571435314107708 (95.7144%)
- Recall: 0.8496241861556381 (84.9624%)
- F1: 0.9001846623697154 (90.0185%)
- Confusion matrix:
  - TN: 51460
  - FP: 4540
  - FN: 17946
  - TP: 101395

### 7.2 Quantized model metrics

- Accuracy: 0.8638082365219771 (86.3808%)
- Precision: 0.9662228820926575 (96.6223%)
- Recall: 0.8288769157288778 (82.8877%)
- F1: 0.8922956187589641 (89.2296%)
- Confusion matrix:
  - TN: 52542
  - FP: 3458
  - FN: 20422
  - TP: 98919

### 7.3 Additional calibration data

- Logit correlation (float vs quantized): 0.9999381015985479
- Threshold: 70518
- Iterations: 40

---

## 8) Online Results: Single-Switch

Sources:

- online/single_switch/output/final_switch_test_9_8_4_1.log
- online/single_switch/output/final_switch_results_9_8_4_1.csv

Confusion matrix:

- TP: 564
- FN: 126
- FP: 22
- TN: 288

Metrics:

- Accuracy: 85.2000%
- Precision: 96.2457%
- Recall: 81.7391%
- F1-score: 88.4013%

CSV recomputation confirms:

- rows: 1000
- accuracy: 0.852
- precision: 0.962457337883959
- recall: 0.8173913043478261
- f1: 0.884012539184953

---

## 9) Online Results: Multi-Switch

Sources:

- online/multi_switch/python/output/final_multi_switch_test.log
- online/multi_switch/python/output/final_multi_switch_results.csv

Confusion matrix:

- TP: 564
- FN: 126
- FP: 22
- TN: 288

Metrics:

- Accuracy: 85.2000%
- Precision: 96.2457%
- Recall: 81.7391%
- F1-score: 88.4013%

CSV recomputation confirms:

- rows: 1000
- accuracy: 0.852
- precision: 0.962457337883959
- recall: 0.8173913043478261
- f1: 0.884012539184953

Important observed note for this recorded run:

- Single-switch and multi-switch final metrics are identical in the saved outputs.

---

## 10) Offline vs Online Snapshot

Quantized offline vs online runtime (single/multi recorded):

- Accuracy: 86.38% vs 85.20%
- Precision: 96.62% vs 96.25%
- Recall: 82.89% vs 81.74%
- F1: 89.23% vs 88.40%

Observed online behavior is close to offline quantized behavior, with a small drop.

---

## 11) Reproduction

### 11.1 Single-switch

From repository root:

- cd 9-8-4-1/online/single_switch
- ./reset_and_run.sh

Expected main outputs:

- 9-8-4-1/online/single_switch/commands.txt
- 9-8-4-1/online/single_switch/output/ids_neuralnet_dynamic_9_32_16_1.json
- 9-8-4-1/online/single_switch/output/final_switch_test_9_8_4_1.log
- 9-8-4-1/online/single_switch/output/final_switch_results_9_8_4_1.csv

### 11.2 Multi-switch

From repository root:

- cd 9-8-4-1/online/multi_switch
- ./reset_and_run_multi.sh

Expected main outputs:

- 9-8-4-1/online/multi_switch/python/output/final_multi_switch_test.log
- 9-8-4-1/online/multi_switch/python/output/final_multi_switch_results.csv
- dynamic_runtime_template/multi_switch/commands_s1.txt
- dynamic_runtime_template/multi_switch/commands_s2.txt
- dynamic_runtime_template/multi_switch/commands_s3.txt
- dynamic_runtime_template/multi_switch/commands_s4.txt

---

## 12) Notes

- The 9-8-4-1 model uses the two_hidden dynamic runtime profile for both single-switch and multi-switch modes.
- Multi-switch deployment log shows low_neuron_partial_accumulate stage mode for this model.
- Online test scripts transmit quantized 9-feature payloads and classify by reading switch debug registers.
- Recorded logs show model threshold and switch threshold aligned at 70518.
