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
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, sendp


def _parse_int_or_none(val, default=None):
    if val is None:
        return default
    sval = str(val).strip().lower()
    if sval in ("none", "null", "", "0"):
        return None
    return int(sval)


CSV_FILE = os.environ.get("CSV_FILE", "../../data/newDataSet.csv")
MODEL_FILE = os.environ.get("MODEL_FILE", "../single_switch/python/output/ptq_model.json")
IFACE_IN = os.environ.get("IFACE_IN", "veth_h1")
SAMPLE_COUNT = _parse_int_or_none(os.environ.get("SAMPLE_COUNT", "5000"), 5000)
POST_SEND_SLEEP_MS = float(os.environ.get("POST_SEND_SLEEP_MS", "50"))
THRIFT_S4 = int(os.environ.get("THRIFT_S4", "9093"))
OUTPUT_CSV = os.environ.get("OUTPUT_CSV", "")

# Runtime settings
MAX_PKTS_PER_FLOW = _parse_int_or_none(os.environ.get("MAX_PKTS_PER_FLOW", "200"), 200)
DUR_SCALE = float(os.environ.get("DUR_SCALE", "0.001"))
DUR_SHIFT = 20
RATE_SHIFT = 10
RECIP_SHIFT = 16
MAX_DEN = 512

DEFAULT_FEATURES = ["proto", "sttl", "sbytes", "dbytes", "dpkts", "dur", "rate", "smean", "dmean"]
SELECTED_FEATURES = DEFAULT_FEATURES
if os.path.exists(MODEL_FILE):
    try:
        with open(MODEL_FILE, "r") as f:
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

def send_burst(pkt, count):
    if count <= 0:
        return
    if count <= 50:
        sendp([Ether()/pkt] * count, iface=IFACE_IN, verbose=False)
    else:
        for _ in range(count):
            sendp(Ether()/pkt, iface=IFACE_IN, verbose=False)


def _safe_int(val, default=0):
    try:
        if pd.isna(val):
            return default
        return int(val)
    except Exception:
        return default


def cli_read_register(port, reg_name, idx):
    cmd = f"echo 'register_read {reg_name} {idx}' | simple_switch_CLI --thrift-port {port}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("utf-8")
        m = re.search(r"=\s+(-?\d+)", out)
        if not m:
            return None
        val = int(m.group(1))
        if val > 2147483647:
            val -= 4294967296
        return val
    except Exception:
        return None


def check_switch_decision():
    v = cli_read_register(THRIFT_S4, "MyIngress.debug_branch", 0)
    return 0 if v is None else int(v)


def read_nn_output_register():
    return cli_read_register(THRIFT_S4, "MyIngress.debug_nn_result", 0)


def read_threshold_register():
    return cli_read_register(THRIFT_S4, "MyIngress.threshold_reg", 0)


def run_test():
    print("--- STARTING MULTI-SWITCH HARDWARE ACCURACY TEST ---")
    path = CSV_FILE
    if not os.path.exists(path):
        path = '../' + CSV_FILE
    if not os.path.exists(path):
        print("Error: CSV not found.")
        sys.exit(1)

    df = pd.read_csv(path)
    if SAMPLE_COUNT is None:
        test_set = df
        sample_msg = f"Using ENTIRE dataset: {len(test_set):,} samples"
    else:
        test_set = df.sample(n=min(SAMPLE_COUNT, len(df)), random_state=42).reset_index(drop=True)
        sample_msg = f"Selecting {len(test_set):,} random rows from {len(df):,} total entries"

    print(sample_msg)
    print("-" * 150)
    header_feats = " | ".join([f"{name:<8}" for name in SELECTED_FEATURES])
    print(f"{'TYPE':<8} | {header_feats} | {'RESULT':<20}")
    print(f"{'(Label)':<8} | {header_feats} | {'(Decision)':<20}")
    print("-" * 150)

    tp = tn = fp = fn = 0
    tested = 0
    csv_rows = []

    threshold_val = read_threshold_register()
    last_nn = None

    max_pkts = MAX_PKTS_PER_FLOW

    for _, row in test_set.iterrows():
        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'arp': 255}
        p_val = proto_map.get(str(row.get('proto', '')).lower(), 255)
        
        sttl = _safe_int(row.get('sttl', 64))
        dttl = _safe_int(row.get('dttl', sttl))
        swin = _safe_int(row.get('swin', 0))
        dwin = _safe_int(row.get('dwin', swin))
        
        if p_val != 6:
            swin = 0
            dwin = 0
        
        # Change source port
        sport = random.randint(1024, 65535)
        dport = 80
        
        pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=sttl, proto=p_val)
        
        if p_val == 6:  # TCP
            pkt = pkt / TCP(sport=sport, dport=dport, window=swin)
        elif p_val == 17:  # UDP
            pkt = pkt / UDP(sport=sport, dport=53)
        elif p_val == 1:  # ICMP
            pkt = pkt / ICMP()
        else:  # Other protocols
            pkt = pkt / Raw(load=b'\x00' * 20)
        
        spkts = _safe_int(row.get('spkts', 15), 15)
        dpkts = _safe_int(row.get('dpkts', 0), 0)
        sbytes = _safe_int(row.get('sbytes', 0), 0)
        dbytes = _safe_int(row.get('dbytes', 0), 0)

        if max_pkts is not None:
            if spkts > max_pkts and spkts > 0:
                scale = max_pkts / spkts
                spkts = max_pkts
                sbytes = max(0, int(sbytes * scale))
            if dpkts > max_pkts and dpkts > 0:
                scale = max_pkts / dpkts
                dpkts = max_pkts
                dbytes = max(0, int(dbytes * scale))

        total_pkts = spkts + dpkts
        dur_seconds = float(row['dur']) if 'dur' in row else 0.0
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

        proto_scaled = (p_val << 4)
        if proto_scaled > 512: proto_scaled = 512
        sttl_scaled = (sttl << 1)
        if sttl_scaled > 512: sttl_scaled = 512
        dttl_scaled = (dttl << 1)
        if dttl_scaled > 512: dttl_scaled = 512
        sbytes_scaled = int((sbytes - 24) >> 6) if sbytes > 24 else 0
        dbytes_scaled = int((dbytes - 24) >> 6) if dbytes > 24 else 0
        if sbytes_scaled > 512: sbytes_scaled = 512
        if dbytes_scaled > 512: dbytes_scaled = 512
        swin_scaled = (swin >> 7) if swin > 0 else 0
        if swin_scaled > 512: swin_scaled = 512
        dwin_scaled = (dwin >> 7) if dwin > 0 else 0
        if dwin_scaled > 512: dwin_scaled = 512
        dpkts_scaled = int((dpkts - 1) << 2) if dpkts > 0 else 0
        if dpkts_scaled > 512: dpkts_scaled = 512
        spkts_scaled = int((spkts - 1) << 2) if spkts > 0 else 0
        if spkts_scaled > 512: spkts_scaled = 512
        totpkts_scaled = int((total_pkts - 1) << 2) if total_pkts > 0 else 0
        if totpkts_scaled > 512: totpkts_scaled = 512
        total_bytes = sbytes + dbytes
        totbytes_scaled = int((total_bytes - 24) >> 6) if total_bytes > 24 else 0
        if totbytes_scaled > 512: totbytes_scaled = 512

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
            vals = vals + [0] * (9 - len(vals))

        # Match payload size
        if p_val == 6:
            header_len = 54
        elif p_val == 17:
            header_len = 42
        else:
            header_len = 42

        s_payload = max(0, int(sbytes / spkts) - header_len) if spkts > 0 else 0
        d_payload = max(0, int(dbytes / dpkts) - header_len) if dpkts > 0 else 0

        if s_payload > 0:
            pkt_forward = pkt / Raw(load=b'\x00' * s_payload)
        else:
            pkt_forward = pkt
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
                pkt_rev = pkt_rev / Raw(load=b'\x00' * d_payload)
            send_burst(pkt_rev, dpkts)

        time.sleep(POST_SEND_SLEEP_MS / 1000.0)
        
        tested += 1

        decision = check_switch_decision()
        last_nn = read_nn_output_register()
        label = int(row['label']) if 'label' in row else 0

        if label == 1:
            if decision == 1:
                tp += 1
                res = "BLOCKED (Correct)"
            else:
                fn += 1
                res = "MISSED"
        else:
            if decision == 0:
                tn += 1
                res = "ALLOWED (Correct)"
            else:
                fp += 1
                res = "FALSE ALARM"

        label_str = 'ATTACK' if label == 1 else 'NORMAL'
        val_str = " | ".join([f"{v:<8}" for v in vals])
        print(f"{label_str:<8} | {val_str} | {res:<20}")

        csv_rows.append([label_str] + vals_raw + [decision, last_nn, threshold_val, res])

    accuracy = (tp + tn) / tested * 100 if tested > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    print("=" * 70)
    print("FINAL MULTI-SWITCH ACCURACY REPORT (Flow Reconstruction Mode)")
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
        print(f"Switch Threshold (S4): {threshold_val:,}")
    if last_nn is not None:
        print(f"Last NN Output (S4):   {last_nn:,}")
    print("=" * 70)

    if OUTPUT_CSV:
        try:
            os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
            with open(OUTPUT_CSV, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["label"] + SELECTED_FEATURES + ["decision", "nn_output", "threshold", "result"])
                w.writerows(csv_rows)
            print(f"Saved detailed results to: {OUTPUT_CSV}")
        except Exception as e:
            print(f"Failed to write CSV: {e}")


if __name__ == "__main__":
    run_test()
