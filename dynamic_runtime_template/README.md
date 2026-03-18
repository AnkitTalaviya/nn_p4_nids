# Dynamic Runtime Template

This directory contains reusable runtime templates for deploying quantized IDS neural networks in BMv2/P4 without hardcoding one model per program.

The template currently supports two profile families:

- `one_hidden`: up to `9-32-1`
- `two_hidden`: up to `9-32-16-1`

It provides:

- dynamic P4 templates for single-switch execution
- command generation from model JSON
- multi-switch orchestration under `multi_switch/`

---

## 1) Directory Layout

- `p4/`
  - `ids_neuralnet_dynamic_9_32_1.p4`
  - `ids_neuralnet_dynamic_9_32_16_1.p4`
- `scripts/`
  - `generate_commands.py`
- `multi_switch/`
  - stage P4 generation, per-switch command generation, deployment, smoke test, cleanup

---

## 2) What This Template Solves

Traditional static deployment in this repo couples one P4 program to one fixed NN architecture. This template decouples that by:

1. detecting or selecting a profile (`one_hidden` or `two_hidden`)
2. parsing model JSON (with small schema variations)
3. emitting BMv2 CLI commands for weights, biases, thresholds, and feature tables
4. reusing max-capacity P4 templates where inactive neurons are zeroed via command defaults

This allows multiple trained models (within profile limits) to run on the same runtime P4 family.

---

## 3) Single-Switch Command Generation

Script:

- `scripts/generate_commands.py`

### 3.1 Supported profiles and target P4

From `PROFILE_P4` mapping in the script:

- `one_hidden` -> `dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4`
- `two_hidden` -> `dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_16_1.p4`

### 3.2 Input assumptions

The generator expects a quantized model JSON with layer blocks and decision threshold. It supports profile auto-detection and tolerates layer matrix orientation differences (it normalizes matrices internally).

Capacity constraints:

- input features: max 9
- hidden layer 1: max 32
- hidden layer 2 (two-hidden profile): max 16

### 3.3 Command generated

The script emits BMv2 CLI defaults and register writes for:

- feature map and feature mask
- optional reciprocal table initialization
- per-neuron bias and weight tables
- output layer bias and weights
- decision threshold register
- active-neuron count registers (profile dependent)

### 3.4 CLI usage

From repository root:

```bash
python3 dynamic_runtime_template/scripts/generate_commands.py \
  --model-json 9_32_1/single_switch/python/output/ptq_model.json \
  --profile auto \
  --output dynamic_runtime_template/commands.txt
```

Options:

- `--model-json` (required): path to model JSON
- `--output` (optional): command file path (default: `dynamic_runtime_template/commands.txt`)
- `--profile` (optional): `auto`, `one_hidden`, `two_hidden` (default: `auto`)
- `--no-reciprocal-init` (optional): skip reciprocal LUT initialization

---

## 4) Profile Selection Behavior

`--profile auto` resolves profile from model content:

- if `layer_2` exists -> `two_hidden`
- otherwise -> `one_hidden`

If explicit profile is provided, validation enforces profile limits and layer dimensions.

---

## 5) Feature Mapping and Quantization Notes

The generator includes candidate feature names and applies the same 9-feature runtime mapping model used across this project.

Important constants in command generation logic:

- `MAX_DEN = 512`
- `RECIP_SHIFT = 16`
- `RATE_SHIFT = 10`

Default feature map fallback:

- `[0, 1, 2, 3, 5, 8, 9, 10, 11]`

This fallback is used when model metadata does not include explicit `feature_map` or cannot derive from `selected_features`.

---

## 6) Integration Pattern

A typical single-switch pipeline reuses this template in three steps:

1. compile one of the two dynamic P4 files in `dynamic_runtime_template/p4/`
2. generate `commands.txt` from model JSON using `scripts/generate_commands.py`
3. load commands through `simple_switch_CLI`

The deployment shell wrappers that do end-to-end startup exist in model-specific directories (for example under `9_32_1/single_switch/` and `9_32_16_1/single_switch/`), while this folder provides reusable generation primitives.

---

## 7) Multi-Switch Documentation

For dynamic stage generation, N-switch deployment, smoke tests, and cleanup, see:

- `dynamic_runtime_template/multi_switch/README.md`

---

## 8) Quick Checks

After generating commands, verify:

- command file is non-empty
- profile printed by generator matches your model
- selected dynamic P4 file matches profile (`9_32_1` vs `9_32_16_1` runtime template)

If command generation fails, the script exits with a clear `Error: ...` message showing field/shape mismatch details.
