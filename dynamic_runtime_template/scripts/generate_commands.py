#!/usr/bin/env python3
"""Generate BMv2 CLI commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List, Sequence, Tuple

MAX_INPUT = 9
MAX_H1 = 32
MAX_H2 = 16
MAX_DEN = 512
RECIP_SHIFT = 16
RATE_SHIFT = 10

PROFILE_ONE = "one_hidden"
PROFILE_TWO = "two_hidden"

PROFILE_P4 = {
    PROFILE_ONE: "dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_1.p4",
    PROFILE_TWO: "dynamic_runtime_template/p4/ids_neuralnet_dynamic_9_32_16_1.p4",
}

CANDIDATE_FEATURES = [
    "proto",
    "sttl",
    "sbytes",
    "dbytes",
    "spkts",
    "dpkts",
    "totpkts",
    "totbytes",
    "dur",
    "rate",
    "smean",
    "dmean",
    "dttl",
    "swin",
    "dwin",
]
DEFAULT_FEATURE_MAP = [0, 1, 2, 3, 5, 8, 9, 10, 11]


def to_hex_16(v: int) -> str:
    x = int(v)
    if x < 0:
        x = (1 << 16) + x
    return f"0x{x & 0xFFFF:04x}"


def to_hex_32(v: int) -> str:
    x = int(v)
    if x < 0:
        x = (1 << 32) + x
    return f"0x{x & 0xFFFFFFFF:08x}"


def to_u32(v: int) -> int:
    x = int(v)
    return x if x >= 0 else (1 << 32) + x


def flatten(items: Any) -> List[int]:
    out: List[int] = []

    def _walk(x: Any) -> None:
        if isinstance(x, (list, tuple)):
            for y in x:
                _walk(y)
        else:
            out.append(int(x))

    _walk(items)
    return out


def as_matrix(items: Any, name: str) -> List[List[int]]:
    if not isinstance(items, list) or not items or not isinstance(items[0], list):
        raise ValueError(f"{name} must be a non-empty 2D list")
    width = len(items[0])
    if width == 0:
        raise ValueError(f"{name} has empty rows")
    mat: List[List[int]] = []
    for row in items:
        if not isinstance(row, list) or len(row) != width:
            raise ValueError(f"{name} has ragged rows")
        mat.append([int(v) for v in row])
    return mat


def read_first(data: dict, *paths: Tuple[str, ...]) -> Any:
    for p in paths:
        cur: Any = data
        ok = True
        for k in p:
            if not isinstance(cur, dict) or k not in cur:
                ok = False
                break
            cur = cur[k]
        if ok:
            return cur
    raise KeyError(f"Missing required field path; tried: {paths}")


def transpose(mat: List[List[int]]) -> List[List[int]]:
    return [list(row) for row in zip(*mat)]


def normalize_w1(w1_raw: Any, h1: int) -> Tuple[List[List[int]], int]:
    w1m = as_matrix(w1_raw, "layer_0.weights")
    r, c = len(w1m), len(w1m[0])

    if c == h1 and r <= MAX_INPUT:
        input_dim = r
        w1 = w1m
    elif r == h1 and c <= MAX_INPUT:
        input_dim = c
        w1 = transpose(w1m)
    else:
        raise ValueError(
            f"Unsupported layer_0 shape {r}x{c}; expected (*x{h1}) or ({h1}x*) with input<=9"
        )

    if input_dim < 1 or input_dim > MAX_INPUT:
        raise ValueError(f"Input dimension must be 1..{MAX_INPUT}, got {input_dim}")
    return w1, input_dim


def normalize_w2_two_hidden(w2_raw: Any, h2: int) -> Tuple[List[List[int]], int]:
    w2m = as_matrix(w2_raw, "layer_1.weights")
    r, c = len(w2m), len(w2m[0])

    if c == h2 and r <= MAX_H1:
        h1 = r
        w2 = w2m
    elif r == h2 and c <= MAX_H1:
        h1 = c
        w2 = transpose(w2m)
    else:
        raise ValueError(
            f"Unsupported layer_1 shape {r}x{c}; expected (*x{h2}) or ({h2}x*) with h1<=32"
        )

    if h1 < 1 or h1 > MAX_H1:
        raise ValueError(f"Hidden-1 size must be 1..{MAX_H1}, got {h1}")
    return w2, h1


def resolve_feature_map(data: dict) -> List[int]:
    fm = data.get("feature_map")
    if isinstance(fm, list) and fm:
        out = [int(x) for x in fm]
    else:
        selected = data.get("selected_features")
        if isinstance(selected, list) and selected:
            mapped: List[int] = []
            for feat in selected:
                if feat in CANDIDATE_FEATURES:
                    mapped.append(CANDIDATE_FEATURES.index(feat))
            out = mapped if mapped else DEFAULT_FEATURE_MAP[:]
        else:
            out = DEFAULT_FEATURE_MAP[:]

    if len(out) < MAX_INPUT:
        out += [0] * (MAX_INPUT - len(out))
    return out[:MAX_INPUT]


def resolve_feature_mask(data: dict, input_dim: int) -> int:
    fm = data.get("feature_mask")
    if fm is not None:
        return int(fm)
    return (1 << input_dim) - 1


def parse_model_one_hidden(data: dict) -> dict:
    w1_raw = read_first(data, ("layer_0", "weights"), ("layer_0", "q_weights"))
    b1 = flatten(read_first(data, ("layer_0", "biases"), ("layer_0", "q_bias")))

    w2 = flatten(read_first(data, ("layer_1", "weights"), ("layer_1", "q_weights")))
    b2_vals = flatten(read_first(data, ("layer_1", "biases"), ("layer_1", "q_bias")))
    if len(b2_vals) < 1:
        raise ValueError("Missing output bias")
    b2 = int(b2_vals[0])

    h1 = len(w2)
    if h1 < 1 or h1 > MAX_H1:
        raise ValueError(f"Hidden size must be 1..{MAX_H1}, got {h1}")
    if len(b1) != h1:
        raise ValueError(f"layer_0.bias length {len(b1)} != hidden size {h1}")

    w1, input_dim = normalize_w1(w1_raw, h1)

    threshold = int(data.get("decision", {}).get("threshold", 0))
    feature_map = resolve_feature_map(data)
    feature_mask = resolve_feature_mask(data, input_dim)

    return {
        "profile": PROFILE_ONE,
        "input_dim": input_dim,
        "h1": h1,
        "w1": w1,
        "b1": [int(x) for x in b1],
        "w2": [int(x) for x in w2],
        "b2": b2,
        "threshold": threshold,
        "feature_map": feature_map,
        "feature_mask": feature_mask,
    }


def parse_model_two_hidden(data: dict) -> dict:
    w1_raw = read_first(data, ("layer_0", "weights"), ("layer_0", "q_weights"))
    b1 = flatten(read_first(data, ("layer_0", "biases"), ("layer_0", "q_bias")))

    w2_raw = read_first(data, ("layer_1", "weights"), ("layer_1", "q_weights"))
    b2 = flatten(read_first(data, ("layer_1", "biases"), ("layer_1", "q_bias")))

    w3 = flatten(read_first(data, ("layer_2", "weights"), ("layer_2", "q_weights")))
    b3_vals = flatten(read_first(data, ("layer_2", "biases"), ("layer_2", "q_bias")))
    if len(b3_vals) < 1:
        raise ValueError("Missing layer_2 bias")
    b3 = int(b3_vals[0])

    h2 = len(w3)
    if h2 < 1 or h2 > MAX_H2:
        raise ValueError(f"Hidden-2 size must be 1..{MAX_H2}, got {h2}")
    if len(b2) != h2:
        raise ValueError(f"layer_1.bias length {len(b2)} != hidden-2 size {h2}")

    w2, h1 = normalize_w2_two_hidden(w2_raw, h2)
    if len(b1) != h1:
        raise ValueError(f"layer_0.bias length {len(b1)} != hidden-1 size {h1}")

    w1, input_dim = normalize_w1(w1_raw, h1)

    threshold = int(data.get("decision", {}).get("threshold", 0))
    feature_map = resolve_feature_map(data)
    feature_mask = resolve_feature_mask(data, input_dim)

    return {
        "profile": PROFILE_TWO,
        "input_dim": input_dim,
        "h1": h1,
        "h2": h2,
        "w1": w1,
        "b1": [int(x) for x in b1],
        "w2": w2,
        "b2": [int(x) for x in b2],
        "w3": [int(x) for x in w3],
        "b3": b3,
        "threshold": threshold,
        "feature_map": feature_map,
        "feature_mask": feature_mask,
    }


def load_model(model_json: Path, profile_arg: str) -> dict:
    data = json.loads(model_json.read_text(encoding="utf-8"))
    has_layer2 = "layer_2" in data

    if profile_arg == "auto":
        profile = PROFILE_TWO if has_layer2 else PROFILE_ONE
    elif profile_arg == PROFILE_ONE:
        profile = PROFILE_ONE
    elif profile_arg == PROFILE_TWO:
        profile = PROFILE_TWO
    else:
        raise ValueError(f"Invalid profile: {profile_arg}")

    if profile == PROFILE_ONE and has_layer2:
        raise ValueError("Model has layer_2 but --profile one_hidden was requested")
    if profile == PROFILE_TWO and not has_layer2:
        raise ValueError("Model has no layer_2 but --profile two_hidden was requested")

    if profile == PROFILE_ONE:
        return parse_model_one_hidden(data)
    return parse_model_two_hidden(data)


def append_common_registers(cmds: List[str], model: dict, include_recip: bool) -> None:
    cmds.append(f"register_write MyIngress.threshold_reg 0 {to_u32(model['threshold'])}")
    cmds.append(f"register_write MyIngress.feature_mask_reg 0 {int(model['feature_mask'])}")
    for i, idx in enumerate(model["feature_map"]):
        cmds.append(f"register_write MyIngress.feature_map_reg {i} {int(idx)}")

    if include_recip:
        cmds.append("register_write MyIngress.recip_pkt_reg 0 0")
        for d in range(1, MAX_DEN + 1):
            cmds.append(f"register_write MyIngress.recip_pkt_reg {d} {(1 << RECIP_SHIFT) // d}")

        cmds.append("register_write MyIngress.recip_dur_reg 0 0")
        for d in range(1, MAX_DEN + 1):
            cmds.append(
                f"register_write MyIngress.recip_dur_reg {d} {(1 << (RECIP_SHIFT + RATE_SHIFT)) // d}"
            )


def build_commands_one_hidden(model: dict, include_recip: bool) -> List[str]:
    cmds: List[str] = []

    for i in range(MAX_H1):
        if i < model["h1"]:
            wi = [0] * MAX_INPUT
            for j in range(model["input_dim"]):
                wi[j] = int(model["w1"][j][i])
            bi = int(model["b1"][i])
        else:
            wi = [0] * MAX_INPUT
            bi = 0

        cmds.append(
            f"table_set_default MyIngress.neuron{i}_bias "
            f"MyIngress.set_bias_{i} {to_hex_32(bi)}"
        )
        cmds.append(
            f"table_set_default MyIngress.neuron{i}_weights "
            f"MyIngress.compute_neuron_{i} " + " ".join(to_hex_16(x) for x in wi)
        )

    w2_32 = [0] * MAX_H1
    for i in range(min(model["h1"], len(model["w2"]), MAX_H1)):
        w2_32[i] = int(model["w2"][i])

    cmds.append(
        f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(model['b2'])}"
    )
    cmds.append(
        "table_set_default MyIngress.output_weights MyIngress.compute_output "
        + " ".join(to_hex_16(x) for x in w2_32)
    )

    cmds.append(f"register_write MyIngress.active_hidden_count_reg 0 {model['h1']}")
    append_common_registers(cmds, model, include_recip)
    return cmds


def build_commands_two_hidden(model: dict, include_recip: bool) -> List[str]:
    cmds: List[str] = []

    for i in range(MAX_H1):
        if i < model["h1"]:
            wi = [0] * MAX_INPUT
            for j in range(model["input_dim"]):
                wi[j] = int(model["w1"][j][i])
            bi = int(model["b1"][i])
        else:
            wi = [0] * MAX_INPUT
            bi = 0

        cmds.append(
            f"table_set_default MyIngress.neuron{i}_bias "
            f"MyIngress.set_bias_{i} {to_hex_32(bi)}"
        )
        cmds.append(
            f"table_set_default MyIngress.neuron{i}_weights "
            f"MyIngress.compute_neuron_{i} " + " ".join(to_hex_16(x) for x in wi)
        )

    for i in range(MAX_H2):
        if i < model["h2"]:
            wi = [0] * MAX_H1
            for j in range(model["h1"]):
                wi[j] = int(model["w2"][j][i])
            bi = int(model["b2"][i])
        else:
            wi = [0] * MAX_H1
            bi = 0

        cmds.append(
            f"table_set_default MyIngress.neuron2_{i}_bias "
            f"MyIngress.set_bias2_{i} {to_hex_32(bi)}"
        )
        cmds.append(
            f"table_set_default MyIngress.neuron2_{i}_weights "
            f"MyIngress.compute_neuron2_{i} " + " ".join(to_hex_16(x) for x in wi)
        )

    w3_16 = [0] * MAX_H2
    for i in range(min(model["h2"], len(model["w3"]), MAX_H2)):
        w3_16[i] = int(model["w3"][i])

    cmds.append(
        f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(model['b3'])}"
    )
    cmds.append(
        "table_set_default MyIngress.output_weights MyIngress.compute_output "
        + " ".join(to_hex_16(x) for x in w3_16)
    )

    cmds.append(f"register_write MyIngress.active_hidden1_count_reg 0 {model['h1']}")
    cmds.append(f"register_write MyIngress.active_hidden2_count_reg 0 {model['h2']}")
    append_common_registers(cmds, model, include_recip)
    return cmds


def build_commands(model: dict, include_recip: bool) -> List[str]:
    if model["profile"] == PROFILE_ONE:
        return build_commands_one_hidden(model, include_recip)
    return build_commands_two_hidden(model, include_recip)


def parse_args() -> argparse.Namespace:
    default_out = Path(__file__).resolve().parents[1] / "commands.txt"
    ap = argparse.ArgumentParser(description="Generate commands for dynamic max-capacity P4 profiles")
    ap.add_argument("--model-json", type=Path, required=True, help="Path to model JSON")
    ap.add_argument("--output", type=Path, default=default_out, help="Output commands file")
    ap.add_argument(
        "--profile",
        choices=["auto", PROFILE_ONE, PROFILE_TWO],
        default="auto",
        help="Choose profile or auto-detect from model",
    )
    ap.add_argument(
        "--no-reciprocal-init",
        action="store_true",
        help="Skip reciprocal table initialization commands",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    try:
        model = load_model(args.model_json, args.profile)
        cmds = build_commands(model, include_recip=not args.no_reciprocal_init)
    except Exception as exc:
        raise SystemExit(f"Error: {exc}") from exc

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(cmds) + "\n", encoding="utf-8")

    profile = model["profile"]
    if profile == PROFILE_ONE:
        arch = f"{model['input_dim']}-{model['h1']}-1"
    else:
        arch = f"{model['input_dim']}-{model['h1']}-{model['h2']}-1"

    print(f"Model: {args.model_json}")
    print(f"Detected architecture: {arch}")
    print(f"Profile: {profile}")
    print(f"Use P4 program: {PROFILE_P4[profile]}")
    print(f"Generated {len(cmds)} commands: {args.output}")


if __name__ == "__main__":
    main()
