# 9-4-1 Model: In-Network IDS (UNSW-NB15)

This README documents the complete 9-4-1 workflow and recorded results in this repository.

It includes:

- Offline training and quantization pipeline
- Exported model structure and preprocessing metadata
- Online single-switch BMv2 deployment flow
- Verified offline and online performance metrics

---

## 1) Model Summary

- Model name: unsw_nb15_9_4_1_offline
- Architecture: 9 -> 4 -> 1
- Hidden activation: ReLU
- Output: logit with threshold decision
- Decision rule: attack_if_nn_result_gt_threshold
- Threshold: 113648
- Quantization scale: 512

Selected 9 features:

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

- offline/python/code/train_9_4_1_offline.py
- offline/python/code/md_train_model_9_4_1.ipynb

### 2.2 Offline artifacts

- offline/python/output/ptq_model_9_4_1.json
- offline/python/output/offline_metrics_9_4_1.json
- offline/python/output/offline_test_predictions_9_4_1.csv

### 2.3 Online single-switch runtime

- online/single_switch/reset_and_run.sh
- online/single_switch/generate_cmd.py
- online/single_switch/final_switch_test.py
- online/single_switch/commands.txt
- online/single_switch/output/ids_neuralnet_dynamic_9_32_1.json
- online/single_switch/output/final_switch_test_9_4_1.log
- online/single_switch/output/final_switch_results_9_4_1.csv

---

## 3) Offline Training and Quantization Pipeline

Script:

- offline/python/code/train_9_4_1_offline.py

What the pipeline does:

1. Loads UNSW-NB15 train and test CSVs.
2. Encodes categorical features:
   - proto
   - service
   - state
3. Fills missing feature values with train medians.
4. Standardizes all selected features with StandardScaler.
5. Trains compact MLPClassifier with hidden size 4.
6. Quantizes weights, biases, and scaled features to integer formats compatible with P4 path.
7. Searches threshold on validation logits to maximize F1 (tie-break by accuracy).
8. Exports metrics, predictions, and full quantized model JSON.

Key integer inference behavior:

- Hidden MAC uses int32 accumulators with SCALE compensation.
- Hidden output uses ReLU then right shift by 9.
- Final output is integer logit used with threshold comparison.

---

## 4) Exported Model Artifact Details

File:

- offline/python/output/ptq_model_9_4_1.json

Contains:

- model metadata and architecture
- selected_features, candidate_features, feature_map, feature_mask
- layer_0 (9x4 weights + 4 biases)
- layer_1 (4x1 weights + output bias)
- decision threshold and rule
- preprocessing block:
  - category mappings for proto, service, state
  - scaler mean and scale arrays
  - train_feature_medians
- embedded offline metric block

This is the source of truth used by online command generation.

---

## 5) Online Single-Switch Deployment Flow

Script:

- online/single_switch/reset_and_run.sh

Execution flow:

1. Resolves Python executable.
2. Uses model JSON from offline output.
3. Generates commands.txt via generate_cmd.py.
4. Compiles shared dynamic P4 pipeline:
   - dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4
5. Cleans old switch and interfaces.
6. Builds veth pairs and starts BMv2 simple_switch.
7. Loads table/register commands.
8. Runs final_switch_test.py for live confusion matrix and metric reporting.
9. Stores log and CSV outputs in online/single_switch/output.

Recorded command generation count:

- 78 commands

Recorded runtime defaults from script:

- Dataset: data/UNSW_NB15_testing-set.csv
- Sample count: 1000
- Thrift port: 9090
- Post-send sleep: 8 ms

---

## 6) Offline Results (Full Test Set)

Source:

- offline/python/output/offline_metrics_9_4_1.json

Dataset size:

- test_samples: 175341
- train_samples: 65865
- val_samples: 16467

### 6.1 Float model metrics

- Accuracy: 0.8695342218876361 (86.9534%)
- Precision: 0.957288456980327 (95.7288%)
- Recall: 0.8460629624353743 (84.6063%)
- F1: 0.8982456764643086 (89.8246%)
- Confusion matrix:
  - TN: 51495
  - FP: 4505
  - FN: 18371
  - TP: 100970

### 6.2 Quantized model metrics

- Accuracy: 0.8602950821542024 (86.0295%)
- Precision: 0.9664034147348958 (96.6403%)
- Recall: 0.8233633034749164 (82.3363%)
- F1: 0.889167398130469 (88.9167%)
- Confusion matrix:
  - TN: 52584
  - FP: 3416
  - FN: 21080
  - TP: 98261

### 6.3 Alignment and threshold

- Logit correlation (float vs quantized): 0.9999125298498237
- Decision threshold: 113648
- Iterations: 29

---

## 7) Online BMv2 Results (Single-Switch)

Sources:

- online/single_switch/output/final_switch_test_9_4_1.log
- online/single_switch/output/final_switch_results_9_4_1.csv

Run summary:

- Dataset rows tested: 1000
- Model threshold: 113648
- Switch threshold: 113648

Confusion matrix (final):

- TP: 562
- FN: 128
- FP: 21
- TN: 289

Metrics:

- Accuracy: 85.1000%
- Precision: 96.3979%
- Recall: 81.4493%
- F1-score: 88.2954%

CSV recomputation confirms exact values:

- rows: 1000
- accuracy: 0.851
- precision: 0.9639794168096055
- recall: 0.8144927536231884
- f1: 0.8829536527886882

---

## 8) Offline vs Online Snapshot

Comparing quantized offline vs BMv2 online reported runs:

- Quantized offline accuracy: 86.03%
- Online BMv2 accuracy: 85.10%

- Quantized offline precision: 96.64%
- Online BMv2 precision: 96.40%

- Quantized offline recall: 82.34%
- Online BMv2 recall: 81.45%

- Quantized offline F1: 88.92%
- Online BMv2 F1: 88.30%

This indicates close behavior between offline quantized inference and online BMv2 decision path for this model.

---

## 9) Reproduction

From repository root:

- cd 9-4-1/online/single_switch
- ./reset_and_run.sh

Expected output files:

- 9-4-1/online/single_switch/commands.txt
- 9-4-1/online/single_switch/output/ids_neuralnet_dynamic_9_32_1.json
- 9-4-1/online/single_switch/output/final_switch_test_9_4_1.log
- 9-4-1/online/single_switch/output/final_switch_results_9_4_1.csv

---

## 10) Notes

- This 9-4-1 profile uses all 9 feature input slots directly, unlike compact 5-feature models that pad to 9 slots.
- Runtime test script sends quantized feature vectors as 9 x 16-bit words over UDP and reads decision/debug registers from BMv2 thrift.
- The same threshold value is present in model JSON and observed at switch register during the recorded run.
