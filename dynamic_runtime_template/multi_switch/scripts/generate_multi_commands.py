#!/usr/bin/env python3
"""Generate BMv2 multi-switch CLI commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

MAX_INPUT = 9
MAX_H1 = 32
MAX_H2 = 16
S1_FIXED_END = 7
MAX_DEN = 512
RECIP_SHIFT = 16
RATE_SHIFT = 10

PROFILE_ONE = "one_hidden"
PROFILE_TWO = "two_hidden"

HOST_LEFT_MAC = "00:aa:00:00:10:01"
HOST_RIGHT_MAC = "00:aa:00:00:10:02"

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


def transpose(mat: List[List[int]]) -> List[List[int]]:
    return [list(row) for row in zip(*mat)]


def read_first(data: dict, *paths: Tuple[str, ...]) -> Any:
    for path in paths:
        cur: Any = data
        ok = True
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                ok = False
                break
            cur = cur[key]
        if ok:
            return cur
    raise KeyError(f"Missing required model field. Tried: {paths}")


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
    if not b2_vals:
        raise ValueError("Missing output bias in layer_1")

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
        "b2": int(b2_vals[0]),
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
    if not b3_vals:
        raise ValueError("Missing output bias in layer_2")

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
        "b3": int(b3_vals[0]),
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


def chunk_counts(total: int, buckets: int) -> List[int]:
    if buckets <= 0:
        return []
    base = total // buckets
    rem = total % buckets
    return [base + (1 if i < rem else 0) for i in range(buckets)]


def build_stage_ranges_one_hidden(num_switches: int) -> List[Tuple[int, int]]:
    if num_switches < 2:
        raise ValueError("num_switches must be >= 2")

    ranges: List[Tuple[int, int]] = [(0, S1_FIXED_END)]
    remaining = MAX_H1 - (S1_FIXED_END + 1)
    counts = chunk_counts(remaining, num_switches - 1)

    cursor = S1_FIXED_END + 1
    for count in counts:
        if count <= 0:
            ranges.append((-1, -1))
        else:
            start = cursor
            end = cursor + count - 1
            ranges.append((start, end))
            cursor = end + 1

    if cursor != MAX_H1:
        raise RuntimeError(f"Internal range generation bug: cursor={cursor}, expected={MAX_H1}")
    return ranges


def fixed_stage_ranges_two_hidden() -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    # Fixed 4-switch split
    h1_ranges = [(0, 7), (8, 15), (16, 23), (24, 31)]
    h2_ranges = [(0, 3), (4, 7), (8, 11), (12, 15)]
    return h1_ranges, h2_ranges


def mac_switch(sw_idx: int, side: int) -> str:
    if sw_idx < 1 or sw_idx > 255:
        raise ValueError(f"switch index out of range for MAC scheme: {sw_idx}")
    if side not in (1, 2):
        raise ValueError(f"side must be 1(left) or 2(right), got {side}")
    return f"00:aa:00:00:{sw_idx:02x}:{side:02x}"


def add_routes(cmds: List[str], switch_idx: int, num_switches: int) -> None:
    self_left = mac_switch(switch_idx, 1)
    self_right = mac_switch(switch_idx, 2)
    next_left = HOST_LEFT_MAC if switch_idx == 1 else mac_switch(switch_idx - 1, 2)
    next_right = HOST_RIGHT_MAC if switch_idx == num_switches else mac_switch(switch_idx + 1, 1)

    cmds.append(
        f"table_add MyIngress.ipv4_lpm MyIngress.set_nhop 10.0.0.1/32 => 0 {next_left} {self_left}"
    )
    cmds.append(
        f"table_add MyIngress.ipv4_lpm MyIngress.set_nhop 10.0.0.2/32 => 1 {next_right} {self_right}"
    )


def local_neuron_count(h1: int, stage_range: Tuple[int, int]) -> int:
    start, end = stage_range
    if start < 0 or end < start:
        return 0
    if h1 <= start:
        return 0
    return min(end - start + 1, h1 - start)


def append_feature_and_recip(cmds_s1: List[str], model: dict, include_recip: bool) -> None:
    cmds_s1.append(f"register_write MyIngress.feature_mask_reg 0 {int(model['feature_mask'])}")
    for i, idx in enumerate(model["feature_map"]):
        cmds_s1.append(f"register_write MyIngress.feature_map_reg {i} {int(idx)}")

    if include_recip:
        cmds_s1.append("register_write MyIngress.recip_pkt_reg 0 0")
        for d in range(1, MAX_DEN + 1):
            cmds_s1.append(f"register_write MyIngress.recip_pkt_reg {d} {(1 << RECIP_SHIFT) // d}")

        cmds_s1.append("register_write MyIngress.recip_dur_reg 0 0")
        for d in range(1, MAX_DEN + 1):
            cmds_s1.append(
                f"register_write MyIngress.recip_dur_reg {d} {(1 << (RECIP_SHIFT + RATE_SHIFT)) // d}"
            )


def build_commands_one_hidden(model: dict, include_recip: bool, num_switches: int) -> Tuple[List[List[str]], Dict[str, object]]:
    ranges = build_stage_ranges_one_hidden(num_switches)
    by_switch: List[List[str]] = [[] for _ in range(num_switches)]

    neuron_to_switch: Dict[int, int] = {}
    for sw_idx, (start, end) in enumerate(ranges, start=1):
        if start < 0:
            continue
        for neuron in range(start, end + 1):
            neuron_to_switch[neuron] = sw_idx

    for i in range(MAX_H1):
        if i not in neuron_to_switch:
            raise RuntimeError(f"Neuron {i} is not assigned to any switch")

        if i < model["h1"]:
            wi = [0] * MAX_INPUT
            for j in range(model["input_dim"]):
                wi[j] = int(model["w1"][j][i])
            bi = int(model["b1"][i])
        else:
            wi = [0] * MAX_INPUT
            bi = 0

        bias_cmd = f"table_set_default MyIngress.neuron{i}_bias MyIngress.set_bias_{i} {to_hex_32(bi)}"
        weight_cmd = (
            f"table_set_default MyIngress.neuron{i}_weights MyIngress.compute_neuron_{i} "
            + " ".join(to_hex_16(x) for x in wi)
        )

        sw_idx = neuron_to_switch[i]
        by_switch[sw_idx - 1].extend([bias_cmd, weight_cmd])

    append_feature_and_recip(by_switch[0], model, include_recip)

    slast = by_switch[-1]
    w2_32 = [0] * MAX_H1
    for i in range(min(model["h1"], len(model["w2"]), MAX_H1)):
        w2_32[i] = int(model["w2"][i])

    slast.append(
        f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(model['b2'])}"
    )
    slast.append(
        "table_set_default MyIngress.output_weights MyIngress.compute_output "
        + " ".join(to_hex_16(x) for x in w2_32)
    )
    slast.append(f"register_write MyIngress.threshold_reg 0 {to_u32(model['threshold'])}")

    # S1 skips this register.
    for sw_idx, stage_range in enumerate(ranges, start=1):
        if sw_idx == 1:
            continue
        local_active = local_neuron_count(model["h1"], stage_range)
        by_switch[sw_idx - 1].append(
            f"register_write MyIngress.active_local_neuron_count_reg 0 {local_active}"
        )

    for sw_idx in range(1, num_switches + 1):
        add_routes(by_switch[sw_idx - 1], sw_idx, num_switches)

    layout = {
        "profile": PROFILE_ONE,
        "num_switches": num_switches,
        "h1_stage_ranges": ranges,
    }
    return by_switch, layout


def build_commands_two_hidden(model: dict, include_recip: bool, num_switches: int) -> Tuple[List[List[str]], Dict[str, object]]:
    if num_switches != 4:
        raise ValueError("two_hidden profile supports exactly --num-switches 4 (same earlier split)")

    h1_ranges, h2_ranges = fixed_stage_ranges_two_hidden()
    by_switch: List[List[str]] = [[] for _ in range(4)]

    # Balance small models across all switches.
    low_neuron_balanced = model["h1"] <= 8 and model["h2"] <= 4
    h2_partial_accumulate = low_neuron_balanced

    h1_active_counts = [0, 0, 0, 0]
    h2_active_counts = [0, 0, 0, 0]

    if low_neuron_balanced:
        h1_stage_counts = chunk_counts(model["h1"], 4)
        logical_to_physical_h1: Dict[int, int] = {}
        logical_idx = 0
        for sw, count in enumerate(h1_stage_counts):
            base = sw * 8
            for off in range(count):
                logical_to_physical_h1[logical_idx] = base + off
                logical_idx += 1
        if logical_idx != model["h1"]:
            raise RuntimeError("Internal H1 mapping error for low-neuron balancing")

        physical_to_logical_h1 = {phys: logical for logical, phys in logical_to_physical_h1.items()}
        for logical, phys in logical_to_physical_h1.items():
            _ = logical
            h1_active_counts[phys // 8] += 1

        for phys in range(MAX_H1):
            if phys in physical_to_logical_h1:
                logical = physical_to_logical_h1[phys]
                wi = [0] * MAX_INPUT
                for j in range(model["input_dim"]):
                    wi[j] = int(model["w1"][j][logical])
                bi = int(model["b1"][logical])
            else:
                wi = [0] * MAX_INPUT
                bi = 0

            sw = phys // 8
            by_switch[sw].append(
                f"table_set_default MyIngress.neuron{phys}_bias MyIngress.set_bias_{phys} {to_hex_32(bi)}"
            )
            by_switch[sw].append(
                f"table_set_default MyIngress.neuron{phys}_weights MyIngress.compute_neuron_{phys} "
                + " ".join(to_hex_16(x) for x in wi)
            )

        append_feature_and_recip(by_switch[0], model, include_recip)

        # Accumulate H2 across switches and finish on S4.
        logical_to_physical_h2: Dict[int, int] = {}
        for logical in range(model["h2"]):
            phys = 12 + logical
            logical_to_physical_h2[logical] = phys
        for sw in range(4):
            h2_active_counts[sw] = model["h2"]

            local_h1_logical: List[int] = []
            for logical_h1, phys_h1 in logical_to_physical_h1.items():
                if (phys_h1 // 8) == sw:
                    local_h1_logical.append(logical_h1)

            for off in range(4):
                phys = (sw * 4) + off
                if off < model["h2"]:
                    logical_h2 = off
                    wi = [0] * MAX_H1
                    for logical_h1 in local_h1_logical:
                        phys_h1 = logical_to_physical_h1[logical_h1]
                        wi[phys_h1] = int(model["w2"][logical_h1][logical_h2])
                    bi = int(model["b2"][logical_h2]) if sw == 3 else 0
                else:
                    wi = [0] * MAX_H1
                    bi = 0

                by_switch[sw].append(
                    f"table_set_default MyIngress.neuron2_{phys}_bias MyIngress.set_bias2_{phys} {to_hex_32(bi)}"
                )
                by_switch[sw].append(
                    f"table_set_default MyIngress.neuron2_{phys}_weights MyIngress.compute_neuron2_{phys} "
                    + " ".join(to_hex_16(x) for x in wi)
                )

        s4 = by_switch[3]
        w3_16 = [0] * MAX_H2
        for logical_h2, phys_h2 in logical_to_physical_h2.items():
            w3_16[phys_h2] = int(model["w3"][logical_h2])

        s4.append(
            f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(model['b3'])}"
        )
        s4.append(
            "table_set_default MyIngress.output_weights MyIngress.compute_output "
            + " ".join(to_hex_16(x) for x in w3_16)
        )
        s4.append(f"register_write MyIngress.threshold_reg 0 {to_u32(model['threshold'])}")

    else:
        # Fixed split for 9-32-16-1.
        for i in range(MAX_H1):
            if i < model["h1"]:
                wi = [0] * MAX_INPUT
                for j in range(model["input_dim"]):
                    wi[j] = int(model["w1"][j][i])
                bi = int(model["b1"][i])
                h1_active_counts[i // 8] += 1
            else:
                wi = [0] * MAX_INPUT
                bi = 0

            sw = i // 8
            by_switch[sw].append(
                f"table_set_default MyIngress.neuron{i}_bias MyIngress.set_bias_{i} {to_hex_32(bi)}"
            )
            by_switch[sw].append(
                f"table_set_default MyIngress.neuron{i}_weights MyIngress.compute_neuron_{i} "
                + " ".join(to_hex_16(x) for x in wi)
            )

        append_feature_and_recip(by_switch[0], model, include_recip)

        for i in range(MAX_H2):
            if i < model["h2"]:
                wi = [0] * MAX_H1
                for j in range(model["h1"]):
                    wi[j] = int(model["w2"][j][i])
                bi = int(model["b2"][i])
                h2_active_counts[i // 4] += 1
            else:
                wi = [0] * MAX_H1
                bi = 0

            sw = i // 4

            # Keep H2 inputs local to each stage.
            if i < model["h2"]:
                max_ready = [7, 15, 23, 31][sw]
                bad_inputs = [j for j in range(model["h1"]) if wi[j] != 0 and j > max_ready]
                if bad_inputs:
                    raise ValueError(
                        f"neuron2_{i} depends on hidden-1 indexes not available at S{sw + 1}: {bad_inputs}. "
                        "This two_hidden profile keeps the old fixed split and requires stage-local H2 dependencies."
                    )

            by_switch[sw].append(
                f"table_set_default MyIngress.neuron2_{i}_bias MyIngress.set_bias2_{i} {to_hex_32(bi)}"
            )
            by_switch[sw].append(
                f"table_set_default MyIngress.neuron2_{i}_weights MyIngress.compute_neuron2_{i} "
                + " ".join(to_hex_16(x) for x in wi)
            )

        s4 = by_switch[3]
        w3_16 = [0] * MAX_H2
        for i in range(min(model["h2"], len(model["w3"]), MAX_H2)):
            w3_16[i] = int(model["w3"][i])

        s4.append(
            f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(model['b3'])}"
        )
        s4.append(
            "table_set_default MyIngress.output_weights MyIngress.compute_output "
            + " ".join(to_hex_16(x) for x in w3_16)
        )
        s4.append(f"register_write MyIngress.threshold_reg 0 {to_u32(model['threshold'])}")

    for sw_idx in range(1, 5):
        by_switch[sw_idx - 1].append(
            f"register_write MyIngress.h2_partial_mode_reg 0 {1 if h2_partial_accumulate else 0}"
        )
        by_switch[sw_idx - 1].append(
            f"register_write MyIngress.active_local_h2_count_reg 0 {h2_active_counts[sw_idx - 1]}"
        )
        add_routes(by_switch[sw_idx - 1], sw_idx, 4)

    layout = {
        "profile": PROFILE_TWO,
        "num_switches": 4,
        "h1_stage_ranges": h1_ranges,
        "h2_stage_ranges": h2_ranges,
        "h1_stage_active": h1_active_counts,
        "h2_stage_active": h2_active_counts,
        "distribution_mode": "low_neuron_partial_accumulate" if low_neuron_balanced else "legacy_fixed_split",
    }
    return by_switch, layout


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(
        description="Generate commands_s*.txt for dynamic multi-switch profiles"
    )
    ap.add_argument("--model-json", type=Path, required=True, help="Path to model JSON")
    ap.add_argument(
        "--profile",
        choices=["auto", PROFILE_ONE, PROFILE_TWO],
        default="auto",
        help="Model profile (auto by default)",
    )
    ap.add_argument(
        "--num-switches",
        type=int,
        default=4,
        help="Number of switches in the pipeline",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=base_dir,
        help="Directory for commands_s1.txt..commands_sN.txt",
    )
    ap.add_argument(
        "--no-reciprocal-init",
        action="store_true",
        help="Skip reciprocal table initialization commands on S1",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    try:
        if args.num_switches < 2:
            raise ValueError("--num-switches must be >= 2")

        model = load_model(args.model_json, args.profile)

        if model["profile"] == PROFILE_ONE:
            by_switch, layout = build_commands_one_hidden(
                model=model,
                include_recip=not args.no_reciprocal_init,
                num_switches=args.num_switches,
            )
        else:
            by_switch, layout = build_commands_two_hidden(
                model=model,
                include_recip=not args.no_reciprocal_init,
                num_switches=args.num_switches,
            )
    except Exception as exc:
        raise SystemExit(f"Error: {exc}") from exc

    args.output_dir.mkdir(parents=True, exist_ok=True)

    out_files: List[Path] = []
    for sw_idx, cmds in enumerate(by_switch, start=1):
        out = args.output_dir / f"commands_s{sw_idx}.txt"
        out.write_text("\n".join(cmds) + "\n", encoding="utf-8")
        out_files.append(out)

    if model["profile"] == PROFILE_ONE:
        arch = f"{model['input_dim']}-{model['h1']}-1"
    else:
        arch = f"{model['input_dim']}-{model['h1']}-{model['h2']}-1"

    print(f"Model: {args.model_json}")
    print(f"Detected architecture: {arch}")
    print(f"Profile: {model['profile']}, switches={layout['num_switches']}")
    print("Use P4 programs:")
    for sw_idx in range(1, layout["num_switches"] + 1):
        print(f"  dynamic_runtime_template/multi_switch/p4/ids_nn_dynamic_s{sw_idx}.p4")

    print("Stage layout:")
    if model["profile"] == PROFILE_ONE:
        for sw_idx, stage_range in enumerate(layout["h1_stage_ranges"], start=1):
            start, end = stage_range
            active = local_neuron_count(model["h1"], stage_range)
            if start < 0:
                print(f"  S{sw_idx}: no local H1 neurons, active={active}")
            else:
                print(f"  S{sw_idx}: H1 neurons {start}..{end}, active={active}")
    else:
        h1_active = layout.get("h1_stage_active")
        h2_active = layout.get("h2_stage_active")
        mode = layout.get("distribution_mode", "legacy_fixed_split")
        print(f"  distribution_mode={mode}")
        for sw_idx, (h1r, h2r) in enumerate(
            zip(layout["h1_stage_ranges"], layout["h2_stage_ranges"]),
            start=1,
        ):
            if isinstance(h1_active, list) and isinstance(h2_active, list) and len(h1_active) >= sw_idx and len(h2_active) >= sw_idx:
                print(
                    f"  S{sw_idx}: H1 {h1r[0]}..{h1r[1]} (active={h1_active[sw_idx-1]}) "
                    f"and H2 {h2r[0]}..{h2r[1]} (active={h2_active[sw_idx-1]})"
                )
            else:
                print(
                    f"  S{sw_idx}: H1 {h1r[0]}..{h1r[1]} and H2 {h2r[0]}..{h2r[1]}"
                )

    for out, cmds in zip(out_files, by_switch):
        print(f"Generated {len(cmds)} commands: {out}")


if __name__ == "__main__":
    main()
