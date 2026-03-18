# 9-8-1 Model: In-Network IDS (UNSW-NB15)

This README documents the full 9-8-1 workflow and measured results available in this repository.

It includes:

- Offline training and quantization pipeline
- Exported model structure and preprocessing metadata
- Online BMv2 single-switch deployment flow
- Verified offline and online metrics with confusion matrices

---

## 1) Model Summary

- Model name: unsw_nb15_9_8_1_offline
- Architecture: 9 -> 8 -> 1
- Hidden activation: ReLU
- Output: logit threshold decision
- Decision rule: attack_if_nn_result_gt_threshold
- Threshold: -104198
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

### 2.1 Offline

- offline/python/code/train_9_8_1_offline.py
- offline/python/code/md_train_model_9_8_1.ipynb

### 2.2 Offline outputs

- offline/python/output/ptq_model_9_8_1.json
- offline/python/output/offline_metrics_9_8_1.json
- offline/python/output/offline_test_predictions_9_8_1.csv

### 2.3 Online single-switch runtime

- online/single_switch/reset_and_run.sh
- online/single_switch/generate_cmd.py
- online/single_switch/final_switch_test.py
- online/single_switch/commands.txt
- online/single_switch/output/ids_neuralnet_dynamic_9_32_1.json
- online/single_switch/output/final_switch_test_9_8_1.log
- online/single_switch/output/final_switch_results_9_8_1.csv

---

## 3) Offline Pipeline

Script:

- offline/python/code/train_9_8_1_offline.py

Pipeline steps:

1. Read UNSW-NB15 training/testing CSV data.
2. Encode categorical columns: proto, service, state.
3. Fill missing values from train medians.
4. Scale features with StandardScaler.
5. Train compact MLPClassifier with 8 hidden units.
6. Quantize parameters and scaled features for P4-compatible integer inference.
7. Find best integer threshold on validation logits (F1-first strategy).
8. Export metrics, predictions, and quantized model JSON.

Integer forward-pass characteristics:

- Hidden layer accumulation in int32
- Hidden output ReLU and right-shift by 9
- Output integer logit compared with threshold

---

## 4) Exported Model Artifact

File:

- offline/python/output/ptq_model_9_8_1.json

Contains:

- model_name and architecture block
- selected_features and candidate_features
- feature_mask and feature_map
- layer_0 (9x8) quantized weights + 8 biases
- layer_1 (8x1) quantized weights + output bias
- decision threshold block
- preprocessing:
  - category mappings for proto/service/state
  - scaler_mean and scaler_scale arrays
  - train_feature_medians
- embedded metric snapshot

This model JSON is consumed by online command generation.

---

## 5) Online Single-Switch Deployment

Script:

- online/single_switch/reset_and_run.sh

What it does:

1. Resolve Python executable.
2. Use model JSON from offline output.
3. Generate commands via generate_cmd.py.
4. Compile shared dynamic P4 source:
   - dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4
5. Clean old switch and interfaces.
6. Setup veth links and start BMv2 simple_switch.
7. Load table/register commands.
8. Run final_switch_test.py and store log/CSV.

Recorded command count:

- 78 commands generated

Default runtime values in script:

- dataset: data/UNSW_NB15_testing-set.csv
- sample_count: 1000
- thrift_port: 9090
- post_send_sleep_ms: 8

---

## 6) Offline Results (Full Test Set)

Source:

- offline/python/output/offline_metrics_9_8_1.json

Dataset sizes:

- train_samples: 65865
- val_samples: 16467
- test_samples: 175341

### 6.1 Float model

- Accuracy: 0.8709771245744007 (87.0977%)
- Precision: 0.9573906628329297 (95.7391%)
- Recall: 0.8481829379676725 (84.8183%)
- F1: 0.899484158191488 (89.9484%)
- Confusion matrix:
  - TN: 51495
  - FP: 4505
  - FN: 18118
  - TP: 101223

### 6.2 Quantized model

- Accuracy: 0.8902595513884374 (89.0260%)
- Precision: 0.9512338054581354 (95.1234%)
- Recall: 0.8840884524178614 (88.4088%)
- F1: 0.9164328709534522 (91.6433%)
- Confusion matrix:
  - TN: 50591
  - FP: 5409
  - FN: 13833
  - TP: 105508

### 6.3 Additional

- Logit correlation (float vs quantized): 0.9999920612241445
- Threshold: -104198
- Iterations: 44

---

## 7) Online BMv2 Results (Single-Switch)

Sources:

- online/single_switch/output/final_switch_test_9_8_1.log
- online/single_switch/output/final_switch_results_9_8_1.csv

Run summary:

- Dataset rows tested: 1000
- Model threshold: -104198
- Switch threshold: -104198

Confusion matrix:

- TP: 602
- FN: 88
- FP: 30
- TN: 280

Metrics:

- Accuracy: 88.2000%
- Precision: 95.2532%
- Recall: 87.2464%
- F1-score: 91.0741%

CSV recomputation confirms:

- rows: 1000
- accuracy: 0.882
- precision: 0.9525316455696202
- recall: 0.8724637681159421
- f1: 0.9107413010590016

---

## 8) Offline vs Online Snapshot

Quantized offline vs online BMv2:

- Accuracy: 89.03% vs 88.20%
- Precision: 95.12% vs 95.25%
- Recall: 88.41% vs 87.25%
- F1: 91.64% vs 91.07%

Overall, online behavior is close to quantized offline behavior for this model on the recorded run settings.

---

## 9) How To Reproduce

From repository root:

- cd 9-8-1/online/single_switch
- ./reset_and_run.sh

Expected outputs:

- 9-8-1/online/single_switch/commands.txt
- 9-8-1/online/single_switch/output/ids_neuralnet_dynamic_9_32_1.json
- 9-8-1/online/single_switch/output/final_switch_test_9_8_1.log
- 9-8-1/online/single_switch/output/final_switch_results_9_8_1.csv

---

## 10) Notes

- This profile uses all 9 feature slots directly and does not rely on feature-slot padding.
- Online test script injects quantized 9-word feature payloads over UDP and reads debug/decision registers through thrift for per-row classification accounting.
- Recorded log confirms the threshold loaded in switch matches the threshold stored in model JSON.
