#!/usr/bin/env python3
"""BMv2 accuracy test for 9-4-1."""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scapy.all import Ether, IP, UDP, Raw, sendp  # type: ignore


FEATURE_PORT = 5555
FEATURE_SPORT = 40000
SCALE = 512


@dataclass
class Confusion:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    def update(self, y_true: int, y_pred: int) -> None:
        if y_true == 1 and y_pred == 1:
            self.tp += 1
        elif y_true == 0 and y_pred == 0:
            self.tn += 1
        elif y_true == 0 and y_pred == 1:
            self.fp += 1
        else:
            self.fn += 1

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    def metrics(self) -> Dict[str, float]:
        total = max(1, self.total)
        precision_den = self.tp + self.fp
        recall_den = self.tp + self.fn
        accuracy = (self.tp + self.tn) / total
        precision = self.tp / precision_den if precision_den else 0.0
        recall = self.tp / recall_den if recall_den else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }


def parse_int_from_cli(output: str, key: str) -> int | None:
    # Example line: RuntimeCmd: MyIngress.debug_branch[0]= 1
    pat = rf"{re.escape(key)}\[0\]=\s+(-?\d+)"
    m = re.search(pat, output)
    if not m:
        # fallback generic
        m = re.search(r"=\s+(-?\d+)", output)
        if not m:
            return None
    val = int(m.group(1))
    if val > 2147483647:
        val -= 4294967296
    return val


def read_threshold(thrift_port: int) -> int | None:
    cmd = f"echo 'register_read MyIngress.threshold_reg 0' | simple_switch_CLI --thrift-port {thrift_port}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("utf-8")
        return parse_int_from_cli(out, "MyIngress.threshold_reg")
    except Exception:
        return None


def read_debug_snapshot(thrift_port: int) -> Tuple[int | None, int | None]:
    # Read both registers in one CLI call to reduce overhead.
    cli_in = (
        "register_read MyIngress.debug_branch 0\n"
        "register_read MyIngress.debug_nn_result 0\n"
    )
    try:
        out = subprocess.check_output(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=cli_in.encode("utf-8"),
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
    except Exception:
        return None, None

    # Parse specific keys.
    branch = parse_int_from_cli(out, "MyIngress.debug_branch")
    nn_out = parse_int_from_cli(out, "MyIngress.debug_nn_result")
    return branch, nn_out


def load_model(model_json: Path) -> Dict[str, object]:
    return json.loads(model_json.read_text(encoding="utf-8"))


def preprocess_quantized(df: pd.DataFrame, model: Dict[str, object]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    features: List[str] = model["selected_features"]
    prep = model["preprocessing"]
    cat_maps: Dict[str, Dict[str, int]] = prep.get("category_mappings", {})
    medians = prep.get("train_feature_medians", {})
    mean = np.array(prep["scaler_mean"], dtype=np.float64)
    scale = np.array(prep["scaler_scale"], dtype=np.float64)
    scale_safe = np.where(scale == 0.0, 1.0, scale)

    work = df.copy()
    for col, mp in cat_maps.items():
        work[col] = work[col].astype(str).map(mp).fillna(0).astype(np.int32)

    x = work[features].apply(pd.to_numeric, errors="coerce")
    for c in features:
        x[c] = x[c].fillna(float(medians.get(c, 0.0)))

    x_scaled = (x.to_numpy(dtype=np.float64) - mean) / scale_safe
    x_q = np.round(x_scaled * SCALE)
    x_q = np.clip(x_q, -32768, 32767).astype(np.int16)
    y = work["label"].astype(np.int32).to_numpy()
    return x_q, y, features


def infer_offline_quant_logits(x_q: np.ndarray, model: Dict[str, object]) -> np.ndarray:
    w1 = np.array(model["layer_0"]["weights"], dtype=np.int32)  # 9x4
    b1 = np.array(model["layer_0"]["biases"], dtype=np.int32)   # 4
    w2 = np.array(model["layer_1"]["weights"], dtype=np.int32).reshape(-1)  # 4
    b2 = int(model["layer_1"]["biases"][0])

    h = x_q.astype(np.int32) @ w1 + (b1 * SCALE)
    h = np.maximum(0, h)
    h = h >> 9
    out = h @ w2 + b2
    return out.astype(np.int32)


def build_inject_packet(features_q: np.ndarray, ttl: int = 64) -> IP:
    # Send as 9x16-bit words; negative values carried as two's complement.
    words = [int(v) & 0xFFFF for v in features_q.tolist()]
    payload = struct.pack("!9H", *words)
    return IP(src="10.0.0.1", dst="10.0.0.2", ttl=int(ttl), proto=17) / UDP(
        sport=FEATURE_SPORT + random.randint(0, 10000),
        dport=FEATURE_PORT,
    ) / Raw(load=payload)


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    ap = argparse.ArgumentParser(description="9-4-1 BMv2 accuracy/confusion-matrix test")
    ap.add_argument("--dataset", type=Path, default=repo_root / "data/UNSW_NB15_testing-set.csv")
    ap.add_argument("--model-json", type=Path, default=repo_root / "9-4-1/offline/python/output/ptq_model_9_4_1.json")
    ap.add_argument("--sample-count", type=int, default=500, help="0 = full dataset")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--iface", type=str, default="veth0_host")
    ap.add_argument("--thrift-port", type=int, default=9090)
    ap.add_argument("--post-send-sleep-ms", type=float, default=8.0)
    ap.add_argument("--verbose-every", type=int, default=500)
    ap.add_argument(
        "--live-table",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Print per-row live table like legacy model test output.",
    )
    ap.add_argument(
        "--live-table-max-rows",
        type=int,
        default=0,
        help="0 = print all rows, N = print only first N rows in live table.",
    )
    ap.add_argument("--output-csv", type=Path, default=None)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    random.seed(args.seed)
    np.random.seed(args.seed)

    model = load_model(args.model_json)
    threshold_model = int(model.get("decision", {}).get("threshold", 0))
    threshold_sw = read_threshold(args.thrift_port)

    df = pd.read_csv(args.dataset)
    if args.sample_count and args.sample_count > 0 and args.sample_count < len(df):
        df = df.sample(n=args.sample_count, random_state=args.seed).reset_index(drop=True)
    rows = len(df)

    x_q, y_true, features = preprocess_quantized(df, model)

    conf = Confusion()
    csv_rows: List[List[object]] = []

    print("=" * 80)
    print("9-4-1 REAL BMv2 ACCURACY TEST")
    print(f"Dataset rows tested: {rows:,}")
    print(f"Features: {features}")
    print(f"Model threshold: {threshold_model}")
    if threshold_sw is not None:
        print(f"Switch threshold: {threshold_sw}")
    print("=" * 80)

    table_suppressed_msg_printed = False
    if args.live_table:
        print("-" * 150)
        header_feats = " | ".join([f"{name:<8}" for name in features])
        print(f"{'TYPE':<8} | {header_feats} | {'RESULT':<20}")
        print(f"{'(Label)':<8} | {header_feats} | {'(Decision)':<20}")
        print("-" * 150)

    t0 = time.perf_counter()
    for i in range(rows):
        pkt = build_inject_packet(x_q[i])
        sendp(Ether() / pkt, iface=args.iface, verbose=False)
        time.sleep(max(0.0, args.post_send_sleep_ms / 1000.0))

        branch, nn_out = read_debug_snapshot(args.thrift_port)
        if branch is None:
            pred = 0
        else:
            pred = 1 if int(branch) == 1 else 0  # debug_branch: 1=drop/attack, 0=forward/normal

        y = int(y_true[i])
        conf.update(y, pred)

        if y == 1:
            res = "BLOCKED (Correct)" if pred == 1 else "MISSED"
            label_str = "ATTACK"
        else:
            res = "ALLOWED (Correct)" if pred == 0 else "FALSE ALARM"
            label_str = "NORMAL"

        if args.live_table:
            if args.live_table_max_rows == 0 or i < args.live_table_max_rows:
                val_str = " | ".join([f"{int(v):<8}" for v in x_q[i].tolist()])
                print(f"{label_str:<8} | {val_str} | {res:<20}")
            elif not table_suppressed_msg_printed:
                print(f"... live table output suppressed after {args.live_table_max_rows} rows ...")
                table_suppressed_msg_printed = True

        if args.output_csv is not None:
            csv_rows.append(
                [y, int(pred), int(nn_out) if nn_out is not None else ""]
                + [int(v) for v in x_q[i].tolist()]
            )

        if args.verbose_every > 0 and ((i + 1) % args.verbose_every == 0 or i == rows - 1):
            print(f"[{i+1:>7}/{rows}] TP={conf.tp} TN={conf.tn} FP={conf.fp} FN={conf.fn}")

    elapsed = max(1e-9, time.perf_counter() - t0)
    m = conf.metrics()

    print("-" * 80)
    print("Confusion Matrix")
    print(f"TP={conf.tp}  FN={conf.fn}")
    print(f"FP={conf.fp}  TN={conf.tn}")
    print("-" * 80)
    print(f"Accuracy : {m['accuracy'] * 100:.4f}%")
    print(f"Precision: {m['precision'] * 100:.4f}%")
    print(f"Recall   : {m['recall'] * 100:.4f}%")
    print(f"F1-score : {m['f1'] * 100:.4f}%")
    print(f"Runtime: {elapsed:.3f} s ({rows/elapsed:.2f} rows/s)")
    print("=" * 80)

    if args.output_csv is not None:
        args.output_csv.parent.mkdir(parents=True, exist_ok=True)
        with args.output_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["label", "switch_pred", "switch_nn_output"]
                + [f"f{i}" for i in range(9)]
            )
            writer.writerows(csv_rows)
        print(f"Saved detailed CSV: {args.output_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
