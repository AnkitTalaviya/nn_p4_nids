#!/usr/bin/env python3
"""
Offline training + evaluation pipeline for a 9-4-1 IDS model.

Architecture:
  - 9 input features
  - 4 hidden neurons (ReLU)
  - 1 output neuron (logit)

This script trains a compact model on UNSW-NB15, quantizes weights/inputs to
integer formats used by the P4 flow, calibrates an integer decision threshold,
and exports artifacts for later online/data-plane integration.
"""

from __future__ import annotations

import argparse
import json
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler


SCALE = 512
SHIFT = 9
# Header-direct/adjacent feature set (flow-time/counter features removed):
# - proto, sttl, dttl, swin, dwin: directly from packet headers
# - service, state: categorical proxies tied to ports/flags
# - sbytes, dbytes: packet-length/byte-volume related
FEATURES = ["proto", "sttl", "dttl", "swin", "dwin", "service", "state", "sbytes", "dbytes"]
CATEGORICAL_FEATURES = ["proto", "service", "state"]

# For the next online phase, keep candidate list aligned to selected features.
CANDIDATE_FEATURES = FEATURES[:]
FEATURE_MAP = list(range(len(FEATURES)))


@dataclass
class Metrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    tn: int
    fp: int
    fn: int
    tp: int


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Metrics:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return Metrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
        tn=int(tn),
        fp=int(fp),
        fn=int(fn),
        tp=int(tp),
    )


def quantize_weight_int16(arr: np.ndarray) -> np.ndarray:
    q = np.round(arr * SCALE)
    return np.clip(q, -32768, 32767).astype(np.int16)


def quantize_bias_hidden_int32(arr: np.ndarray) -> np.ndarray:
    # Hidden bias uses SCALE, and is multiplied by SCALE in integer forward pass.
    return np.round(arr * SCALE).astype(np.int32)


def quantize_bias_output_int32(arr: np.ndarray) -> np.ndarray:
    # Output bias is kept at SCALE^2 to match accumulated integer MAC scale.
    return np.round(arr * (SCALE * SCALE)).astype(np.int32)


def quantize_features(x_scaled: np.ndarray) -> np.ndarray:
    q = np.round(x_scaled * SCALE)
    return np.clip(q, -32768, 32767).astype(np.int16)


def infer_float_logits(clf: MLPClassifier, x_scaled: np.ndarray) -> np.ndarray:
    w1 = np.asarray(clf.coefs_[0], dtype=np.float64)     # 9 x 4
    b1 = np.asarray(clf.intercepts_[0], dtype=np.float64)  # 4
    w2 = np.asarray(clf.coefs_[1], dtype=np.float64).reshape(-1)  # 4
    b2 = float(np.asarray(clf.intercepts_[1], dtype=np.float64).reshape(-1)[0])
    hidden = np.maximum(0.0, x_scaled @ w1 + b1)
    return hidden @ w2 + b2


def infer_quantized_logits(
    xq: np.ndarray,
    w1_q: np.ndarray,
    b1_q: np.ndarray,
    w2_q: np.ndarray,
    b2_q: int,
) -> np.ndarray:
    x32 = xq.astype(np.int32)
    h_acc = x32 @ w1_q.astype(np.int32) + (b1_q.astype(np.int32) * SCALE)
    h_relu = np.maximum(0, h_acc)
    h_scaled = h_relu >> SHIFT
    out = h_scaled.astype(np.int32) @ w2_q.astype(np.int32) + int(b2_q)
    return out.astype(np.int32)


def find_best_threshold(logits: np.ndarray, y_true: np.ndarray) -> Tuple[int, float]:
    # Decision rule: attack (1) if nn_result > threshold else normal (0)
    # Candidate thresholds from quantiles + boundary guards.
    qs = np.linspace(0.0, 1.0, 400)
    candidates = np.unique(np.quantile(logits, qs).astype(np.int32))
    if candidates.size == 0:
        return 0, 0.0
    candidates = np.concatenate(([int(logits.min()) - 1], candidates, [int(logits.max()) + 1]))

    best_th = int(candidates[0])
    best_f1 = -1.0
    best_acc = -1.0
    for th in candidates:
        pred = (logits > int(th)).astype(np.int32)
        f1 = f1_score(y_true, pred, zero_division=0)
        acc = accuracy_score(y_true, pred)
        if (f1 > best_f1) or (f1 == best_f1 and acc > best_acc):
            best_f1 = float(f1)
            best_acc = float(acc)
            best_th = int(th)
    return best_th, best_f1


def build_category_mappings(train_df: pd.DataFrame) -> Dict[str, Dict[str, int]]:
    mappings: Dict[str, Dict[str, int]] = {}
    for col in CATEGORICAL_FEATURES:
        uniq = sorted(str(x) for x in train_df[col].dropna().unique())
        mappings[col] = {v: i + 1 for i, v in enumerate(uniq)}
    return mappings


def prepare_xy(
    df: pd.DataFrame,
    category_mappings: Dict[str, Dict[str, int]],
    medians: pd.Series | None = None,
) -> Tuple[pd.DataFrame, np.ndarray]:
    work = df.copy()
    for col in CATEGORICAL_FEATURES:
        work[col] = (
            work[col]
            .astype(str)
            .map(category_mappings[col])
            .fillna(0)
            .astype(np.int32)
        )
    x = work[FEATURES].apply(pd.to_numeric, errors="coerce")
    if medians is None:
        medians = x.median(numeric_only=True)
    x = x.fillna(medians)
    y = work["label"].astype(np.int32).to_numpy()
    return x, y


def run_pipeline(
    train_csv: Path,
    test_csv: Path,
    output_dir: Path,
    random_state: int = 42,
    max_iter: int = 80,
) -> Dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)

    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)
    category_mappings = build_category_mappings(train_df)

    x_train_raw, y_train = prepare_xy(train_df, category_mappings, medians=None)
    medians = x_train_raw.median(numeric_only=True)
    x_train_raw = x_train_raw.fillna(medians)
    x_test_raw, y_test = prepare_xy(test_df, category_mappings, medians=medians)

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train_raw)
    x_test_scaled = scaler.transform(x_test_raw)

    # Validation split from training set for integer-threshold calibration.
    x_train_sub, x_val, y_train_sub, y_val = train_test_split(
        x_train_scaled,
        y_train,
        test_size=0.2,
        random_state=random_state,
        stratify=y_train,
    )

    clf = MLPClassifier(
        hidden_layer_sizes=(4,),
        activation="relu",
        solver="adam",
        learning_rate_init=1e-3,
        batch_size=1024,
        max_iter=max_iter,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=8,
        random_state=random_state,
        verbose=False,
    )
    warnings.filterwarnings("ignore", category=ConvergenceWarning)
    clf.fit(x_train_sub, y_train_sub)

    # Float evaluation (sklearn decision path)
    y_float_test = clf.predict(x_test_scaled).astype(np.int32)
    float_metrics = compute_metrics(y_test, y_float_test)

    # Quantized parameter extraction
    w1 = np.asarray(clf.coefs_[0], dtype=np.float64)            # 9 x 4
    b1 = np.asarray(clf.intercepts_[0], dtype=np.float64)       # 4
    w2 = np.asarray(clf.coefs_[1], dtype=np.float64).reshape(-1)  # 4
    b2 = np.asarray(clf.intercepts_[1], dtype=np.float64).reshape(-1)[0]

    w1_q = quantize_weight_int16(w1)
    b1_q = quantize_bias_hidden_int32(b1)
    w2_q = quantize_weight_int16(w2)
    b2_q = int(quantize_bias_output_int32(np.array([b2]))[0])

    x_val_q = quantize_features(x_val)
    val_logits_q = infer_quantized_logits(x_val_q, w1_q, b1_q, w2_q, b2_q)
    best_threshold, _ = find_best_threshold(val_logits_q, y_val)

    x_test_q = quantize_features(x_test_scaled)
    test_logits_q = infer_quantized_logits(x_test_q, w1_q, b1_q, w2_q, b2_q)
    y_quant_test = (test_logits_q > best_threshold).astype(np.int32)
    quant_metrics = compute_metrics(y_test, y_quant_test)

    # Optional logit alignment indicator
    test_logits_float = infer_float_logits(clf, x_test_scaled)
    if np.std(test_logits_float) > 0 and np.std(test_logits_q) > 0:
        logit_corr = float(np.corrcoef(test_logits_float, test_logits_q)[0, 1])
    else:
        logit_corr = 0.0

    # Export metrics
    metrics = {
        "float": asdict(float_metrics),
        "quantized": asdict(quant_metrics),
        "logit_correlation": logit_corr,
        "decision_rule": "attack_if_nn_result_gt_threshold",
        "threshold": int(best_threshold),
        "iterations": int(clf.n_iter_),
        "train_samples": int(len(y_train_sub)),
        "val_samples": int(len(y_val)),
        "test_samples": int(len(y_test)),
    }
    metrics_path = output_dir / "offline_metrics_9_4_1.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # Export predictions
    pred_df = pd.DataFrame(
        {
            "label": y_test.astype(np.int32),
            "float_pred": y_float_test.astype(np.int32),
            "quant_pred": y_quant_test.astype(np.int32),
            "float_logit": test_logits_float.astype(np.float64),
            "quant_logit": test_logits_q.astype(np.int32),
        }
    )
    pred_path = output_dir / "offline_test_predictions_9_4_1.csv"
    pred_df.to_csv(pred_path, index=False)

    # Export model artifact for later control-plane conversion.
    model_obj = {
        "model_name": "unsw_nb15_9_4_1_offline",
        "architecture": {"input": 9, "hidden": [4], "output": 1},
        "quantization_scale": SCALE,
        "selected_features": FEATURES,
        "feature_mask": (1 << len(FEATURES)) - 1,
        "feature_map": FEATURE_MAP,
        "candidate_features": CANDIDATE_FEATURES,
        "layer_0": {
            "weights": w1_q.astype(np.int16).tolist(),  # shape: 9 x 4
            "biases": b1_q.astype(np.int32).tolist(),   # shape: 4
        },
        "layer_1": {
            "weights": w2_q.astype(np.int16).reshape(-1).tolist(),  # shape: 4
            "biases": [int(b2_q)],
        },
        "decision": {
            "rule": "attack_if_nn_result_gt_threshold",
            "threshold": int(best_threshold),
        },
        "preprocessing": {
            "category_mappings": category_mappings,
            "scaler_mean": scaler.mean_.astype(float).tolist(),
            "scaler_scale": scaler.scale_.astype(float).tolist(),
            "train_feature_medians": medians.astype(float).to_dict(),
        },
        "metrics": metrics,
    }
    model_path = output_dir / "ptq_model_9_4_1.json"
    model_path.write_text(json.dumps(model_obj, indent=2), encoding="utf-8")

    return {
        "metrics_path": str(metrics_path),
        "predictions_path": str(pred_path),
        "model_path": str(model_path),
        "metrics": metrics,
    }


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve()
    repo_root = here.parents[4]
    default_train = repo_root / "data/UNSW_NB15_training-set.csv"
    default_test = repo_root / "data/UNSW_NB15_testing-set.csv"
    default_out = here.parent.parent / "output"

    p = argparse.ArgumentParser(description="Train/evaluate offline UNSW-NB15 9-4-1 model")
    p.add_argument("--train-csv", type=Path, default=default_train)
    p.add_argument("--test-csv", type=Path, default=default_test)
    p.add_argument("--output-dir", type=Path, default=default_out)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-iter", type=int, default=80)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    result = run_pipeline(
        train_csv=args.train_csv,
        test_csv=args.test_csv,
        output_dir=args.output_dir,
        random_state=args.seed,
        max_iter=args.max_iter,
    )

    m = result["metrics"]
    print("=== 9-4-1 Offline Training Complete ===")
    print(f"Model:      {result['model_path']}")
    print(f"Metrics:    {result['metrics_path']}")
    print(f"Predictions:{result['predictions_path']}")
    print("")
    print("Float  -> "
          f"acc={m['float']['accuracy']:.4f} "
          f"prec={m['float']['precision']:.4f} "
          f"rec={m['float']['recall']:.4f} "
          f"f1={m['float']['f1']:.4f}")
    print("Quant  -> "
          f"acc={m['quantized']['accuracy']:.4f} "
          f"prec={m['quantized']['precision']:.4f} "
          f"rec={m['quantized']['recall']:.4f} "
          f"f1={m['quantized']['f1']:.4f}")
    print(f"Threshold (int): {m['threshold']}")
    print(f"Logit corr: {m['logit_correlation']:.6f}")


if __name__ == "__main__":
    main()
