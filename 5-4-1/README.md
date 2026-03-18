# 5-4-1 Model: In-Network IDS (UNSW-NB15)

This README documents the full workflow and recorded results for the `5-4-1` neural-network IDS model in this repository.

## 1) Model Summary

- Model name: `unsw_nb15_5_4_1_offline`
- Architecture: `5 -> 4 -> 1` (ReLU hidden layer, logit output)
- Decision rule: attack if `nn_result > threshold`
- Threshold: `-260628`
- Quantization scale: `512`
- Input features:
  - `proto`
  - `sttl`
  - `dttl`
  - `swin`
  - `dwin`

## 2) Folder Layout

- Offline training and export:
  - `offline/python/code/train_5_4_1_offline.py`
  - `offline/python/code/md_train_model_5_4_1.ipynb`
- Offline artifacts:
  - `offline/python/output/ptq_model_5_4_1.json`
  - `offline/python/output/offline_metrics_5_4_1.json`
  - `offline/python/output/offline_test_predictions_5_4_1.csv`
- Online single-switch runtime:
  - `online/single_switch/generate_cmd.py`
  - `online/single_switch/final_switch_test.py`
  - `online/single_switch/reset_and_run.sh`
  - `online/single_switch/commands.txt`
  - `online/single_switch/output/final_switch_test_5_4_1.log`
  - `online/single_switch/output/final_switch_results_5_4_1.csv`

## 3) Offline Pipeline (Python)

The offline script does the following:

1. Loads UNSW-NB15 train/test CSV files.
2. Maps categorical feature `proto` to integer IDs.
3. Fills missing values using train medians.
4. Standardizes features with `StandardScaler`.
5. Trains an `MLPClassifier` with one hidden layer of 4 neurons.
6. Quantizes parameters and inputs to integer formats used by P4/BMv2.
7. Finds an integer threshold on validation logits (`f_beta`, beta = 1.0).
8. Exports model JSON + metrics + detailed predictions.

## 4) Exported Quantized Model Details

From `offline/python/output/ptq_model_5_4_1.json`:

- `feature_mask`: `31`
- `feature_map`: `[0, 1, 2, 3, 4]`
- Layer 0 (5x4) quantized weights and 4 biases
- Layer 1 (4x1) quantized weights and output bias
- Decision threshold persisted as `-260628`

This JSON is consumed by online command generation and BMv2 testing.

## 5) Online Single-Switch Flow (BMv2)

`online/single_switch/reset_and_run.sh` performs end-to-end runtime:

1. Generates `commands.txt` from model JSON (`generate_cmd.py`).
2. Compiles shared P4 pipeline to BMv2 JSON.
3. Resets old switch/interfaces and creates veth pairs.
4. Starts `simple_switch`.
5. Loads table/register commands with `simple_switch_CLI`.
6. Runs `final_switch_test.py` for accuracy/confusion matrix.
7. Writes log and CSV outputs.

Default runtime parameters in this script include:

- Dataset: `data/newDataSet.csv`
- Sample count: `500`
- Thrift port: `9090`
- Post-send sleep: `8 ms`

## 6) Recorded Results

### 6.1 Offline Results (Full test set)

Source: `offline/python/output/offline_metrics_5_4_1.json`

- Test samples: `175341`

Float model metrics:

- Accuracy: `0.8238974341` (82.3897%)
- Precision: `0.9499964392` (94.9996%)
- Recall: `0.7824469378` (78.2447%)
- F1: `0.8581195953` (85.8120%)
- Confusion matrix: TN `51085`, FP `4915`, FN `25963`, TP `93378`

Quantized model metrics:

- Accuracy: `0.9259956314` (92.5996%)
- Precision: `0.9045373293` (90.4537%)
- Recall: `0.9964303969` (99.6430%)
- F1: `0.9482628007` (94.8263%)
- Confusion matrix: TN `43450`, FP `12550`, FN `426`, TP `118915`

Additional calibration details:

- Logit correlation (float vs quantized): `0.9999996995`
- Threshold objective: `f_beta`
- Beta: `1.0`
- Validation threshold stats:
  - Precision: `0.7235778862`
  - Recall: `0.9974633286`
  - F1: `0.8387276268`
  - Accuracy: `0.7887897006`

### 6.2 Online BMv2 Results (Single-switch)

Sources:

- `online/single_switch/output/final_switch_test_5_4_1.log`
- `online/single_switch/output/final_switch_results_5_4_1.csv`

Run summary:

- Dataset rows tested: `500`
- Generated runtime commands: `78`
- Threshold in model and switch: `-260628`

Confusion matrix:

- TP: `335`
- TN: `132`
- FP: `31`
- FN: `2`

Metrics:

- Accuracy: `93.4000%`
- Precision: `91.5301%`
- Recall: `99.4065%`
- F1-score: `95.3058%`

These CSV-derived metrics match the printed test log values.

## 7) How To Reproduce 5-4-1 Results

From repository root:

```bash
cd 5-4-1/online/single_switch
./reset_and_run.sh
```

Expected outputs:

- `online/single_switch/commands.txt`
- `online/single_switch/output/ids_neuralnet_dynamic_9_32_1.json`
- `online/single_switch/output/final_switch_test_5_4_1.log`
- `online/single_switch/output/final_switch_results_5_4_1.csv`

## 8) Notes

- The 5-4-1 model uses 5 active inputs, while the shared dynamic P4 template supports up to 9 input slots; unused slots are padded/disabled through feature mapping and mask.
- `final_switch_test.py` sends feature-encoded packets and reads debug registers from BMv2 to compute live confusion matrix metrics.
