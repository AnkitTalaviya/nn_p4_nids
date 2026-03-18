#!/usr/bin/env python3
"""Generate BMv2 runtime commands for 9-4-1."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

import numpy as np


def to_hex_16(v: int) -> str:
    v = int(v)
    if v < 0:
        v = (1 << 16) + v
    return f"0x{v & 0xFFFF:04x}"


def to_hex_32(v: int) -> str:
    v = int(v)
    if v < 0:
        v = (1 << 32) + v
    return f"0x{v & 0xFFFFFFFF:08x}"


def load_model(model_json: Path):
    data = json.loads(model_json.read_text(encoding="utf-8"))
    arch = data.get("architecture", {})
    if arch.get("input") != 9 or arch.get("hidden") != [4] or arch.get("output") != 1:
        raise ValueError(f"Expected 9-4-1 architecture, got {arch}")

    w1 = np.array(data["layer_0"]["weights"], dtype=np.int16)  # 9 x 4
    b1 = np.array(data["layer_0"]["biases"], dtype=np.int32)   # 4
    w2 = np.array(data["layer_1"]["weights"], dtype=np.int16).reshape(-1)  # 4
    b2 = int(data["layer_1"]["biases"][0])
    threshold = int(data.get("decision", {}).get("threshold", 0))
    feature_mask = int(data.get("feature_mask", (1 << 9) - 1))
    feature_map = list(data.get("feature_map", list(range(9))))
    if len(feature_map) < 9:
        feature_map = feature_map + [0] * (9 - len(feature_map))
    return w1, b1, w2, b2, threshold, feature_mask, feature_map[:9]


def build_commands(
    w1: np.ndarray,
    b1: np.ndarray,
    w2: np.ndarray,
    b2: int,
    threshold: int,
    feature_mask: int,
    feature_map: List[int],
) -> List[str]:
    cmds: List[str] = []
    active_hidden_count = int(w2.shape[0])

    # Hidden layer: 32 neurons in P4, first 4 active from 9-4-1 model.
    for i in range(32):
        if i < 4:
            # w1 is 9 x 4; extract weights for neuron i in feature order.
            wi = [int(w1[j, i]) for j in range(9)]
            bi = int(b1[i])
        else:
            wi = [0] * 9
            bi = 0

        cmds.append(
            f"table_set_default MyIngress.neuron{i}_bias "
            f"MyIngress.set_bias_{i} {to_hex_32(bi)}"
        )
        cmds.append(
            f"table_set_default MyIngress.neuron{i}_weights "
            f"MyIngress.compute_neuron_{i} " + " ".join(to_hex_16(w) for w in wi)
        )

    # Output layer: pad 4 -> 32.
    w2_32 = np.zeros(32, dtype=np.int16)
    w2_32[:4] = w2.astype(np.int16)
    cmds.append(
        f"table_set_default MyIngress.output_bias MyIngress.set_output_bias {to_hex_32(b2)}"
    )
    cmds.append(
        f"table_set_default MyIngress.output_weights MyIngress.compute_output "
        + " ".join(to_hex_16(int(w)) for w in w2_32.tolist())
    )

    threshold_u32 = threshold if threshold >= 0 else (1 << 32) + threshold
    cmds.append(f"register_write MyIngress.active_hidden_count_reg 0 {active_hidden_count}")
    cmds.append(f"register_write MyIngress.threshold_reg 0 {threshold_u32}")
    cmds.append(f"register_write MyIngress.feature_mask_reg 0 {feature_mask}")
    for i, idx in enumerate(feature_map):
        cmds.append(f"register_write MyIngress.feature_map_reg {i} {int(idx)}")
    return cmds


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve()
    script_dir = here.parent
    default_model = here.parents[2] / "offline/python/output/ptq_model_9_4_1.json"
    default_out = script_dir / "commands.txt"
    ap = argparse.ArgumentParser(description="Generate commands.txt for 9-4-1 online deployment")
    ap.add_argument("--model-json", type=Path, default=default_model)
    ap.add_argument("--output", type=Path, default=default_out)
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    w1, b1, w2, b2, threshold, feature_mask, feature_map = load_model(args.model_json)
    cmds = build_commands(w1, b1, w2, b2, threshold, feature_mask, feature_map)
    args.output.write_text("\n".join(cmds) + "\n", encoding="utf-8")
    print(f"Generated {len(cmds)} commands: {args.output}")


if __name__ == "__main__":
    main()
