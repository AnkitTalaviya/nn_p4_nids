#!/usr/bin/env python3
"""BMv2 multi-switch accuracy test for 9-8-4-1."""

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
        p_den = self.tp + self.fp
        r_den = self.tp + self.fn
        accuracy = (self.tp + self.tn) / total
        precision = self.tp / p_den if p_den else 0.0
        recall = self.tp / r_den if r_den else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }


def _parse_int_from_cli(out: str, key: str) -> int | None:
    m = re.search(rf"{re.escape(key)}\[0\]=\s+(-?\d+)", out)
    if not m:
        m = re.search(r"=\s+(-?\d+)", out)
        if not m:
            return None
    v = int(m.group(1))
    if v > 2147483647:
        v -= 4294967296
    return v


def _read_threshold(thrift_port: int) -> int | None:
    cmd = f"echo 'register_read MyIngress.threshold_reg 0' | simple_switch_CLI --thrift-port {thrift_port}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("utf-8")
        return _parse_int_from_cli(out, "MyIngress.threshold_reg")
    except Exception:
        return None


def _read_debug(thrift_port: int) -> Tuple[int | None, int | None]:
    cli_in = "register_read MyIngress.debug_branch 0\nregister_read MyIngress.debug_nn_result 0\n"
    try:
        out = subprocess.check_output(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=cli_in.encode("utf-8"),
            stderr=subprocess.DEVNULL,
        ).decode("utf-8")
    except Exception:
        return None, None

    branch = _parse_int_from_cli(out, "MyIngress.debug_branch")
    nn_out = _parse_int_from_cli(out, "MyIngress.debug_nn_result")
    return branch, nn_out


def _load_model(model_json: Path) -> Dict[str, object]:
    return json.loads(model_json.read_text(encoding="utf-8"))


def _prepare_quantized_features(df: pd.DataFrame, model: Dict[str, object]) -> Tuple[np.ndarray, np.ndarray, List[str], int]:
    prep = model["preprocessing"]
    selected: List[str] = list(model["selected_features"])
    scale = int(model.get("quantization_scale", 512))

    cat_maps: Dict[str, Dict[str, int]] = prep.get("category_mappings", {})
    mean = np.array(prep["scaler_mean"], dtype=np.float64)
    std = np.array(prep["scaler_scale"], dtype=np.float64)
    std_safe = np.where(std == 0.0, 1.0, std)
    medians = prep.get("train_feature_medians", {})

    work = df.copy()
    for col, mp in cat_maps.items():
        work[col] = work[col].astype(str).map(mp).fillna(0).astype(np.int32)

    x = work[selected].apply(pd.to_numeric, errors="coerce")
    for c in selected:
        x[c] = x[c].fillna(float(medians.get(c, 0.0)))

    x_scaled = (x.to_numpy(dtype=np.float64) - mean) / std_safe
    x_q = np.round(x_scaled * scale)
    x_q = np.clip(x_q, -32768, 32767).astype(np.int16)
    y = work["label"].astype(np.int32).to_numpy()
    return x_q, y, selected, scale


def _build_packet(features_q: np.ndarray, ttl: int, feature_port: int) -> IP:
    words = [int(v) & 0xFFFF for v in features_q.tolist()]
    payload = struct.pack("!9H", *words)
    return IP(src="10.0.0.1", dst="10.0.0.2", ttl=int(ttl), proto=17) / UDP(
        sport=40000 + random.randint(0, 10000),
        dport=feature_port,
    ) / Raw(load=payload)


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve()
    repo_root = here.parents[3]

    p = argparse.ArgumentParser(description="9-8-4-1 multi-switch BMv2 accuracy test")
    p.add_argument("--dataset", type=Path, default=repo_root / "data/UNSW_NB15_testing-set.csv")
    p.add_argument("--model-json", type=Path, default=repo_root / "9-8-4-1/offline/python/output/ptq_model_9_8_4_1.json")
    p.add_argument("--sample-count", type=int, default=1000, help="0 = full dataset")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--iface", type=str, default="veth_h1")
    p.add_argument("--thrift-port", type=int, default=9093)
    p.add_argument("--feature-port", type=int, default=5555)
    p.add_argument("--post-send-sleep-ms", type=float, default=8.0)
    p.add_argument("--verbose-every", type=int, default=200)
    p.add_argument("--live-table", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--live-table-max-rows", type=int, default=120)
    p.add_argument("--output-csv", type=Path, default=None)
    return p.parse_args()


def _coerce_env(args: argparse.Namespace) -> None:
    if "CSV_FILE" in os.environ:
        args.dataset = Path(os.environ["CSV_FILE"])
    if "MODEL_FILE" in os.environ:
        args.model_json = Path(os.environ["MODEL_FILE"])
    if "MODEL_JSON" in os.environ:
        args.model_json = Path(os.environ["MODEL_JSON"])
    if "SAMPLE_COUNT" in os.environ:
        args.sample_count = int(os.environ["SAMPLE_COUNT"])
    if "IFACE_IN" in os.environ:
        args.iface = os.environ["IFACE_IN"]
    if "THRIFT_S4" in os.environ:
        args.thrift_port = int(os.environ["THRIFT_S4"])
    if "THRIFT_PORT" in os.environ:
        args.thrift_port = int(os.environ["THRIFT_PORT"])
    if "FEATURE_PORT" in os.environ:
        args.feature_port = int(os.environ["FEATURE_PORT"])
    if "POST_SEND_SLEEP_MS" in os.environ:
        args.post_send_sleep_ms = float(os.environ["POST_SEND_SLEEP_MS"])
    if "LIVE_TABLE" in os.environ:
        args.live_table = os.environ["LIVE_TABLE"].strip().lower() in ("1", "true", "yes", "y")
    if "LIVE_TABLE_MAX_ROWS" in os.environ:
        args.live_table_max_rows = int(os.environ["LIVE_TABLE_MAX_ROWS"])
    if "OUTPUT_CSV" in os.environ:
        args.output_csv = Path(os.environ["OUTPUT_CSV"])


def main() -> int:
    args = parse_args()
    _coerce_env(args)

    random.seed(args.seed)
    np.random.seed(args.seed)

    if not args.dataset.exists():
        raise FileNotFoundError(f"Dataset not found: {args.dataset}")
    if not args.model_json.exists():
        raise FileNotFoundError(f"Model JSON not found: {args.model_json}")

    model = _load_model(args.model_json)
    threshold_model = int(model.get("decision", {}).get("threshold", 0))
    threshold_sw = _read_threshold(args.thrift_port)

    df = pd.read_csv(args.dataset)
    if args.sample_count and args.sample_count > 0 and args.sample_count < len(df):
        df = df.sample(n=args.sample_count, random_state=args.seed).reset_index(drop=True)

    x_q, y_true, features, _ = _prepare_quantized_features(df, model)

    conf = Confusion()
    csv_rows: List[List[object]] = []

    rows = len(df)
    print("=" * 88)
    print("9-8-4-1 MULTI-SWITCH REAL BMv2 ACCURACY TEST")
    print(f"Dataset rows tested: {rows:,}")
    print(f"Features: {features}")
    print(f"Model threshold: {threshold_model}")
    if threshold_sw is not None:
        print(f"Switch threshold: {threshold_sw}")
    print("=" * 88)

    suppressed = False
    if args.live_table:
        print("-" * 150)
        header_feats = " | ".join([f"{name:<8}" for name in features])
        print(f"{'TYPE':<8} | {header_feats} | {'RESULT':<20}")
        print(f"{'(Label)':<8} | {header_feats} | {'(Decision)':<20}")
        print("-" * 150)

    t0 = time.perf_counter()
    for i in range(rows):
        ttl = int(df.iloc[i].get("sttl", 64)) if "sttl" in df.columns else 64
        pkt = _build_packet(x_q[i], ttl=ttl, feature_port=args.feature_port)
        sendp(Ether() / pkt, iface=args.iface, verbose=False)
        time.sleep(max(0.0, args.post_send_sleep_ms / 1000.0))

        branch, nn_out = _read_debug(args.thrift_port)
        pred = 1 if int(branch) == 1 else 0 if branch is not None else 0

        y = int(y_true[i])
        conf.update(y, pred)

        if y == 1:
            result = "BLOCKED (Correct)" if pred == 1 else "MISSED"
            label = "ATTACK"
        else:
            result = "ALLOWED (Correct)" if pred == 0 else "FALSE ALARM"
            label = "NORMAL"

        if args.live_table:
            if args.live_table_max_rows == 0 or i < args.live_table_max_rows:
                vals = " | ".join([f"{int(v):<8}" for v in x_q[i].tolist()])
                print(f"{label:<8} | {vals} | {result:<20}")
            elif not suppressed:
                print(f"... live table output suppressed after {args.live_table_max_rows} rows ...")
                suppressed = True

        if args.output_csv is not None:
            csv_rows.append(
                [
                    y,
                    int(pred),
                    int(nn_out) if nn_out is not None else "",
                ]
                + [int(v) for v in x_q[i].tolist()]
            )

        if args.verbose_every > 0 and ((i + 1) % args.verbose_every == 0 or i == rows - 1):
            print(f"[{i+1:>7}/{rows}] TP={conf.tp} TN={conf.tn} FP={conf.fp} FN={conf.fn}")

    elapsed = max(1e-9, time.perf_counter() - t0)
    m = conf.metrics()

    print("-" * 88)
    print("Confusion Matrix")
    print(f"TP={conf.tp}  FN={conf.fn}")
    print(f"FP={conf.fp}  TN={conf.tn}")
    print("-" * 88)
    print(f"Accuracy : {m['accuracy'] * 100:.4f}%")
    print(f"Precision: {m['precision'] * 100:.4f}%")
    print(f"Recall   : {m['recall'] * 100:.4f}%")
    print(f"F1-score : {m['f1'] * 100:.4f}%")
    print(f"Runtime: {elapsed:.3f} s ({rows / elapsed:.2f} rows/s)")
    print("=" * 88)

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
