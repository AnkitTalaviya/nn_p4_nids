#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
DYN_MULTI_GEN = REPO_ROOT / "dynamic_runtime_template" / "multi_switch" / "scripts" / "generate_multi_commands.py"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate commands_s*.txt via dynamic runtime generator")
    ap.add_argument(
        "--model-json",
        type=Path,
        default=SCRIPT_DIR.parent / "single_switch" / "python" / "output" / "ptq_model.json",
        help="Path to model JSON",
    )
    ap.add_argument("--num-switches", type=int, default=4, help="Number of switches (must be 4 for two_hidden)")
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=SCRIPT_DIR,
        help="Directory for commands_s1..commands_sN",
    )
    ap.add_argument(
        "--no-reciprocal-init",
        action="store_true",
        help="Skip reciprocal table initialization",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    cmd = [
        sys.executable,
        str(DYN_MULTI_GEN),
        "--model-json",
        str(args.model_json),
        "--profile",
        "two_hidden",
        "--num-switches",
        str(args.num_switches),
        "--output-dir",
        str(args.output_dir),
    ]
    if args.no_reciprocal_init:
        cmd.append("--no-reciprocal-init")

    print("[dynamic-wrapper] generating multi-switch commands with two_hidden profile")
    print("[dynamic-wrapper] model:", args.model_json)
    print("[dynamic-wrapper] switches:", args.num_switches)
    print("[dynamic-wrapper] output-dir:", args.output_dir)
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
