#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
DYN_GEN = REPO_ROOT / "dynamic_runtime_template" / "scripts" / "generate_commands.py"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate commands.txt via dynamic runtime generator")
    ap.add_argument(
        "--model-json",
        type=Path,
        default=SCRIPT_DIR.parents[1] / "offline" / "python" / "output" / "ptq_model_9_8_4_1.json",
        help="Path to model JSON",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=SCRIPT_DIR / "commands.txt",
        help="Output commands file",
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
        str(DYN_GEN),
        "--model-json",
        str(args.model_json),
        "--profile",
        "two_hidden",
        "--output",
        str(args.output),
    ]
    if args.no_reciprocal_init:
        cmd.append("--no-reciprocal-init")

    print("[dynamic-wrapper] generating single-switch commands with two_hidden profile")
    print("[dynamic-wrapper] model:", args.model_json)
    print("[dynamic-wrapper] output:", args.output)
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
