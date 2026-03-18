#!/usr/bin/env python3

import csv
import json
import os
import random
import re
import subprocess
import sys
import time

import numpy as np
import pandas as pd
from scapy.all import Ether, ICMP, IP, TCP, UDP, Raw, sendp


def _parse_int_or_none(val, default=None):
    if val is None:
        return default
    sval = str(val).strip().lower()
    if sval in ("none", "null", "", "0"):
        return None
    return int(sval)


def _safe_int(val, default=0):
    try:
        if pd.isna(val):
            return default
        return int(val)
    except Exception:
        return default


# Runtime settings
CSV_FILE = os.environ.get("CSV_FILE", "../../data/newDataSet.csv")
IFACE_IN = os.environ.get("IFACE_IN", "veth0_host")
SAMPLE_COUNT = _parse_int_or_none(os.environ.get("SAMPLE_COUNT", "5000"), 5000)
MAX_PKTS_PER_FLOW = _parse_int_or_none(os.environ.get("MAX_PKTS_PER_FLOW", "200"), 200)

DUR_SCALE = float(os.environ.get("DUR_SCALE", "0.001"))
DUR_SHIFT = 20
RATE_SHIFT = 10
RECIP_SHIFT = 16
MAX_DEN = 512
POST_SEND_SLEEP_MS = float(os.environ.get("POST_SEND_SLEEP_MS", "50"))

OUTPUT_CSV = os.environ.get("OUTPUT_CSV", "")
MODEL_FILE = os.environ.get("MODEL_FILE", "python/output/ptq_model.json")

DEFAULT_FEATURES = ["proto", "sttl", "sbytes", "dbytes", "dpkts", "dur", "rate", "smean", "dmean"]
SELECTED_FEATURES = DEFAULT_FEATURES
if os.path.exists(MODEL_FILE):
    try:
        with open(MODEL_FILE, "r", encoding="utf-8") as f:
            model_data = json.load(f)
        sel = model_data.get("selected_features")
        if isinstance(sel, list) and 0 < len(sel) <= 9:
            SELECTED_FEATURES = sel
    except Exception:
        pass


def build_recip_tables():
    recip_pkt = np.zeros(MAX_DEN + 1, dtype=np.int64)
    recip_dur = np.zeros(MAX_DEN + 1, dtype=np.int64)
    for d in range(1, MAX_DEN + 1):
        recip_pkt[d] = (1 << RECIP_SHIFT) // d
        recip_dur[d] = (1 << (RECIP_SHIFT + RATE_SHIFT)) // d
    return recip_pkt, recip_dur


RECIP_PKT, RECIP_DUR = build_recip_tables()


def _read_register_signed(reg_name, idx=0, thrift_port=9090):
    cmd = f"echo 'register_read {reg_name} {idx}' | simple_switch_CLI --thrift-port {thrift_port}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("utf-8")
        match = re.search(r"=\s+(-?\d+)", output)
        if not match:
            return None
        val = int(match.group(1))
        if val > 2147483647:
            val -= 4294967296
        return val
    except Exception:
        return None


def check_switch_decision():
    # 1 = drop, 0 = forward
    val = _read_register_signed("MyIngress.debug_branch", 0)
    if val is None:
        return 0
    return int(val)


def read_threshold_register():
    return _read_register_signed("MyIngress.threshold_reg", 0)


def read_nn_output_register():
    return _read_register_signed("MyIngress.debug_nn_result", 0)


def send_burst(pkt, count):
    if count <= 0:
        return
    if count <= 50:
        sendp([Ether() / pkt] * count, iface=IFACE_IN, verbose=False)
    else:
        for _ in range(count):
            sendp(Ether() / pkt, iface=IFACE_IN, verbose=False)


def run_test():
    print("--- STARTING FINAL HARDWARE ACCURACY TEST (9_32_1) ---")

    path = CSV_FILE
    if not os.path.exists(path):
        path = os.path.join("..", CSV_FILE)
    if not os.path.exists(path):
        print(f"Error: CSV not found: {CSV_FILE}")
        sys.exit(1)

    df = pd.read_csv(path)
    if SAMPLE_COUNT is None:
        test_set = df.reset_index(drop=True)
        sample_msg = f"Using ENTIRE dataset: {len(test_set):,} samples"
    else:
        n = min(SAMPLE_COUNT, len(df))
        test_set = df.sample(n=n, random_state=42).reset_index(drop=True)
        sample_msg = f"Selecting {len(test_set):,} random rows from {len(df):,} total entries"

    print(sample_msg)
    print("-" * 150)
    header_feats = " | ".join([f"{name:<8}" for name in SELECTED_FEATURES])
    print(f"{'TYPE':<8} | {header_feats} | {'RESULT':<20}")
    print(f"{'(Label)':<8} | {header_feats} | {'(Decision)':<20}")
    print("-" * 150)

    tp = tn = fp = fn = 0
    tested = 0
    last_nn_output = None

    csv_rows = []
    csv_header = ["label"] + SELECTED_FEATURES + ["decision", "nn_output", "threshold"]

    threshold_val = read_threshold_register()

    for _, row in test_set.iterrows():
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 255}
        proto_str = str(row.get("proto", "")).lower()
        p_val = proto_map.get(proto_str, 255)

        sttl = _safe_int(row.get("sttl", 0))
        dttl = _safe_int(row.get("dttl", sttl))
        swin = _safe_int(row.get("swin", 0))
        dwin = _safe_int(row.get("dwin", swin))
        if p_val != 6:
            swin = 0
            dwin = 0

        sport = random.randint(1024, 65535)
        dport = 80

        pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=sttl, proto=p_val)
        if p_val == 6:
            pkt = pkt / TCP(sport=sport, dport=dport, window=swin)
        elif p_val == 17:
            pkt = pkt / UDP(sport=sport, dport=53)
        elif p_val == 1:
            pkt = pkt / ICMP()
        else:
            pkt = pkt / Raw(load=b"\x00" * 20)

        spkts = _safe_int(row.get("spkts", 15), 15)
        dpkts = _safe_int(row.get("dpkts", 0), 0)
        sbytes = _safe_int(row.get("sbytes", 0), 0)
        dbytes = _safe_int(row.get("dbytes", 0), 0)

        if MAX_PKTS_PER_FLOW is not None:
            if spkts > MAX_PKTS_PER_FLOW and spkts > 0:
                scale = MAX_PKTS_PER_FLOW / spkts
                spkts = MAX_PKTS_PER_FLOW
                sbytes = max(0, int(sbytes * scale))
            if dpkts > MAX_PKTS_PER_FLOW and dpkts > 0:
                scale = MAX_PKTS_PER_FLOW / dpkts
                dpkts = MAX_PKTS_PER_FLOW
                dbytes = max(0, int(dbytes * scale))

        total_pkts = spkts + dpkts
        total_bytes = sbytes + dbytes

        dur_seconds = float(row.get("dur", 0.0) or 0.0)
        dur_ns = dur_seconds * 1e9 * DUR_SCALE
        dur_scaled = int(dur_ns // (1 << DUR_SHIFT)) if dur_ns > 0 else 0
        if dur_scaled > 512:
            dur_scaled = 512

        if dur_scaled > 0:
            denom_idx = dur_scaled if dur_scaled <= MAX_DEN else MAX_DEN
            rate_scaled = int((total_pkts * RECIP_DUR[denom_idx]) >> RECIP_SHIFT)
        else:
            rate_scaled = 0
        if rate_scaled > 512:
            rate_scaled = 512

        if spkts > 0:
            denom_idx = spkts if spkts <= MAX_DEN else MAX_DEN
            smean = int((sbytes * RECIP_PKT[denom_idx]) >> RECIP_SHIFT)
        else:
            smean = 0
        if dpkts > 0:
            denom_idx = dpkts if dpkts <= MAX_DEN else MAX_DEN
            dmean = int((dbytes * RECIP_PKT[denom_idx]) >> RECIP_SHIFT)
        else:
            dmean = 0

        smean_scaled = int((smean - 24) >> 1) if smean > 24 else 0
        dmean_scaled = int((dmean - 24) >> 1) if dmean > 24 else 0
        if smean_scaled > 512:
            smean_scaled = 512
        if dmean_scaled > 512:
            dmean_scaled = 512

        proto_scaled = min((p_val << 4), 512)
        sttl_scaled = min((sttl << 1), 512)
        dttl_scaled = min((dttl << 1), 512)

        sbytes_scaled = int((sbytes - 24) >> 6) if sbytes > 24 else 0
        dbytes_scaled = int((dbytes - 24) >> 6) if dbytes > 24 else 0
        sbytes_scaled = min(sbytes_scaled, 512)
        dbytes_scaled = min(dbytes_scaled, 512)

        swin_scaled = min((swin >> 7) if swin > 0 else 0, 512)
        dwin_scaled = min((dwin >> 7) if dwin > 0 else 0, 512)

        dpkts_scaled = min(int((dpkts - 1) << 2) if dpkts > 0 else 0, 512)
        spkts_scaled = min(int((spkts - 1) << 2) if spkts > 0 else 0, 512)
        totpkts_scaled = min(int((total_pkts - 1) << 2) if total_pkts > 0 else 0, 512)
        totbytes_scaled = min(int((total_bytes - 24) >> 6) if total_bytes > 24 else 0, 512)

        feature_values = {
            "proto": proto_scaled,
            "sttl": sttl_scaled,
            "dttl": dttl_scaled,
            "swin": swin_scaled,
            "dwin": dwin_scaled,
            "sbytes": sbytes_scaled,
            "dbytes": dbytes_scaled,
            "spkts": spkts_scaled,
            "dpkts": dpkts_scaled,
            "totpkts": totpkts_scaled,
            "totbytes": totbytes_scaled,
            "dur": dur_scaled,
            "rate": rate_scaled,
            "smean": smean_scaled,
            "dmean": dmean_scaled,
        }
        vals_raw = [feature_values.get(f, 0) for f in SELECTED_FEATURES]
        vals = list(vals_raw)
        if len(vals) < 9:
            vals += [0] * (9 - len(vals))

        if p_val == 6:
            header_len = 54
        elif p_val == 17:
            header_len = 42
        else:
            header_len = 42

        s_payload = max(0, int(sbytes / spkts) - header_len) if spkts > 0 else 0
        d_payload = max(0, int(dbytes / dpkts) - header_len) if dpkts > 0 else 0

        pkt_forward = pkt / Raw(load=b"\x00" * s_payload) if s_payload > 0 else pkt
        send_burst(pkt_forward, spkts)

        if dpkts > 0:
            pkt_rev = IP(src="10.0.0.2", dst="10.0.0.1", ttl=dttl, proto=p_val)
            if p_val == 6:
                pkt_rev = pkt_rev / TCP(sport=dport, dport=sport, window=dwin)
            elif p_val == 17:
                pkt_rev = pkt_rev / UDP(sport=53, dport=sport)
            elif p_val == 1:
                pkt_rev = pkt_rev / ICMP()
            if d_payload > 0:
                pkt_rev = pkt_rev / Raw(load=b"\x00" * d_payload)
            send_burst(pkt_rev, dpkts)

        time.sleep(POST_SEND_SLEEP_MS / 1000.0)
        tested += 1

        decision = check_switch_decision()
        label = _safe_int(row.get("label", 0), 0)

        if label == 1:
            if decision == 1:
                tp += 1
                result = "BLOCKED (Correct)"
            else:
                fn += 1
                result = "MISSED"
        else:
            if decision == 0:
                tn += 1
                result = "ALLOWED (Correct)"
            else:
                fp += 1
                result = "FALSE ALARM"

        label_str = "ATTACK" if label == 1 else "NORMAL"
        val_str = " | ".join([f"{v:<8}" for v in vals])
        print(f"{label_str:<8} | {val_str} | {result:<20}")

        last_nn_output = read_nn_output_register()
        csv_rows.append([label_str] + vals_raw + [decision, last_nn_output, threshold_val])

    accuracy = (tp + tn) / tested * 100 if tested > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    if threshold_val is None:
        threshold_val = read_threshold_register()

    print("=" * 70)
    print("FINAL SWITCH ACCURACY REPORT ")
    print(f"All 9 Features Displayed: {', '.join(SELECTED_FEATURES)}")
    print("=" * 70)
    print(f"Samples Tested: {tested:,} {'(Full Dataset)' if SAMPLE_COUNT is None else ''}")
    print(f"Accuracy:  {accuracy:.2f}%")
    print(f"Precision: {precision:.2f}%")
    print(f"Recall:    {recall:.2f}%")
    print(f"F1 Score:  {f1:.2f}%")
    print("-" * 40)
    print("Confusion Matrix")
    print(f"TP (Attack->Blocked): {tp}")
    print(f"FN (Attack->Allowed): {fn}")
    print(f"FP (Normal->Blocked): {fp}")
    print(f"TN (Normal->Allowed): {tn}")
    print("-" * 40)
    if threshold_val is not None:
        print(f"Switch Threshold:    {threshold_val:,}")
    if last_nn_output is not None:
        print(f"Last NN Output:      {last_nn_output:,}")
    print("=" * 70)

    if OUTPUT_CSV:
        try:
            os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
            with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(csv_header)
                writer.writerows(csv_rows)
            print(f"Saved detailed results to: {OUTPUT_CSV}")
        except Exception as exc:
            print(f"Failed to write CSV: {exc}")


if __name__ == "__main__":
    run_test()
