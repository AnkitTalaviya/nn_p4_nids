#!/usr/bin/env python3
"""Generate multi-switch P4 programs for dynamic NN runtime templates.

Profiles:
- one_hidden: variable N >= 2, max 9-32-1
- two_hidden: fixed N = 4, max 9-32-16-1, same split as earlier project
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

FEATURE_UDP_PORT = 5555
NN_MAGIC = 0xface
MAX_H1 = 32
S1_FIXED_END = 7

PROFILE_ONE = "one_hidden"
PROFILE_TWO = "two_hidden"


def chunk_counts(total: int, buckets: int) -> List[int]:
    if buckets <= 0:
        return []
    base = total // buckets
    rem = total % buckets
    return [base + (1 if i < rem else 0) for i in range(buckets)]


def build_stage_ranges_one_hidden(num_switches: int) -> List[Tuple[int, int]]:
    """Return per-switch H1 neuron ranges for one-hidden profile."""
    if num_switches < 2:
        raise ValueError("num_switches must be >= 2")

    ranges: List[Tuple[int, int]] = [(0, S1_FIXED_END)]

    remaining = MAX_H1 - (S1_FIXED_END + 1)  # 24 neurons: 8..31
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


def neuron_action(idx: int, source: str) -> str:
    # source in {"hdr.nn", "meta"}
    if source == "meta":
        src = [f"meta.feature_{i}" for i in range(9)]
        dst = f"meta.result_{idx}"
    else:
        src = [f"hdr.nn.f{i}" for i in range(9)]
        dst = f"hdr.nn.r{idx}"

    acc_lines = "\n".join(
        f"        acc = acc + ((int<32>)(int<16>)w{i} * (int<32>)((int<16>){src[i]}));"
        for i in range(9)
    )

    return f"""
    action set_bias_{idx}(int<32> b) {{
        bias_{idx} = (int<32>)b;
    }}

    table neuron{idx}_bias {{
        actions = {{ set_bias_{idx}; }}
        default_action = set_bias_{idx}(0);
    }}

    action compute_neuron_{idx}(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {{
        int<32> acc = 0;
{acc_lines}
        acc = acc + (bias_{idx} * (int<32>)512);

        if (acc > 0) {{
            {dst} = (int<32>)acc;
        }} else {{
            {dst} = 0;
        }}
    }}

    table neuron{idx}_weights {{
        actions = {{ compute_neuron_{idx}; NoAction; }}
        default_action = NoAction();
    }}
"""


def common_headers_nn_only() -> str:
    return f"""/* P4_16 */
#include <core.p4>
#include <v1model.p4>

const bit<16> FEATURE_UDP_PORT = {FEATURE_UDP_PORT};
const bit<16> NN_MAGIC = 16w0x{NN_MAGIC:04x};

header ethernet_t {{
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}}

header ipv4_t {{
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    int<32> srcAddr;
    int<32> dstAddr;
}}

header tcp_t {{
    bit<16> srcPort;
    bit<16> dstPort;
    int<32> seqNo;
    int<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}}

header udp_t {{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}}

header nn_state_t {{
    bit<16> magic;
    bit<16> flags;
    bit<16> f0;
    bit<16> f1;
    bit<16> f2;
    bit<16> f3;
    bit<16> f4;
    bit<16> f5;
    bit<16> f6;
    bit<16> f7;
    bit<16> f8;
    int<32> r0;
    int<32> r1;
    int<32> r2;
    int<32> r3;
    int<32> r4;
    int<32> r5;
    int<32> r6;
    int<32> r7;
    int<32> r8;
    int<32> r9;
    int<32> r10;
    int<32> r11;
    int<32> r12;
    int<32> r13;
    int<32> r14;
    int<32> r15;
    int<32> r16;
    int<32> r17;
    int<32> r18;
    int<32> r19;
    int<32> r20;
    int<32> r21;
    int<32> r22;
    int<32> r23;
    int<32> r24;
    int<32> r25;
    int<32> r26;
    int<32> r27;
    int<32> r28;
    int<32> r29;
    int<32> r30;
    int<32> r31;
    int<32> nn_result;
}}

struct headers {{
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    nn_state_t nn;
}}

struct metadata {{
    bit<16> feature_0;
    bit<16> feature_1;
    bit<16> feature_2;
    bit<16> feature_3;
    bit<16> feature_4;
    bit<16> feature_5;
    bit<16> feature_6;
    bit<16> feature_7;
    bit<16> feature_8;
    int<32> result_0;
    int<32> result_1;
    int<32> result_2;
    int<32> result_3;
    int<32> result_4;
    int<32> result_5;
    int<32> result_6;
    int<32> result_7;
    int<32> result_8;
    int<32> result_9;
    int<32> result_10;
    int<32> result_11;
    int<32> result_12;
    int<32> result_13;
    int<32> result_14;
    int<32> result_15;
    int<32> result_16;
    int<32> result_17;
    int<32> result_18;
    int<32> result_19;
    int<32> result_20;
    int<32> result_21;
    int<32> result_22;
    int<32> result_23;
    int<32> result_24;
    int<32> result_25;
    int<32> result_26;
    int<32> result_27;
    int<32> result_28;
    int<32> result_29;
    int<32> result_30;
    int<32> result_31;

    bit<32> flow_packet_count;
    bit<32> flow_byte_count;
    bit<32> flow_dst_packet_count;
    bit<32> flow_dst_byte_count;
    bit<48> flow_duration;
    bit<16> src_port;
    bit<16> dst_port;
    bit<1> is_forward_direction;
    bit<8> flow_sttl;
    bit<8> flow_dttl;
    bit<16> flow_swin;
    bit<16> flow_dwin;

    int<32> debug_nn_result;
    int<32> debug_decision;
}}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {{
    state start {{
        transition parse_ethernet;
    }}

    state parse_ethernet {{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {{
            0x0800: parse_ipv4;
            default: accept;
        }}
    }}

    state parse_ipv4 {{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {{
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }}
    }}

    state parse_tcp {{
        packet.extract(hdr.tcp);
        transition select(standard_metadata.ingress_port) {{
            0: parse_nn;
            default: accept;
        }}
    }}

    state parse_udp {{
        packet.extract(hdr.udp);
        transition select(standard_metadata.ingress_port) {{
            0: parse_nn;
            default: accept;
        }}
    }}

    state parse_nn {{
        packet.extract(hdr.nn);
        transition accept;
    }}
}}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {{
    apply {{ }}
}}
"""


def route_block() -> str:
    return """
    action set_nhop(bit<9> port, bit<48> dmac, bit<48> smac) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ethernet.srcAddr = smac;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = { set_nhop; NoAction; }
        size = 64;
        default_action = NoAction();
    }
"""


def make_active_weight_apply(neuron_ids: List[int]) -> str:
    if not neuron_ids:
        return ""

    out = ["            active_local_neuron_count_reg.read(active_local_neuron_count, 0);"]
    for local_idx, neuron_id in enumerate(neuron_ids):
        out.append(
            f"            if (active_local_neuron_count > {local_idx}) "
            f"{{ neuron{neuron_id}_weights.apply(); }} else {{ hdr.nn.r{neuron_id} = 0; }}"
        )
    return "\n".join(out)


def stage_mid_program(n0: int, n1: int) -> str:
    neuron_ids = list(range(n0, n1 + 1)) if n0 >= 0 and n1 >= n0 else []
    neurons = "\n".join(neuron_action(i, "hdr.nn") for i in neuron_ids)
    biases = "\n".join(f"    int<32> bias_{i};" for i in neuron_ids)
    apply_bias = " ".join(f"neuron{i}_bias.apply();" for i in neuron_ids)
    apply_weights = make_active_weight_apply(neuron_ids)

    return common_headers_nn_only() + f"""

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {{

{biases}
    bit<8> active_local_neuron_count;
    register<bit<8>>(1) active_local_neuron_count_reg;

{neurons}
{route_block()}

    apply {{
        if (hdr.ipv4.isValid() && hdr.nn.isValid() && hdr.nn.magic == NN_MAGIC) {{
            {apply_bias}
{apply_weights}
            ipv4_lpm.apply();
        }} else if (hdr.ipv4.isValid()) {{
            ipv4_lpm.apply();
        }}
    }}
}}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {{
    apply {{ }}
}}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {{
    apply {{ }}
}}

control MyDeparser(packet_out packet, in headers hdr) {{
    apply {{
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.nn);
    }}
}}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
"""


def stage_last_program(n0: int, n1: int) -> str:
    neuron_ids = list(range(n0, n1 + 1)) if n0 >= 0 and n1 >= n0 else []
    neurons = "\n".join(neuron_action(i, "hdr.nn") for i in neuron_ids)
    biases = "\n".join(f"    int<32> bias_{i};" for i in neuron_ids)
    apply_bias = " ".join(f"neuron{i}_bias.apply();" for i in neuron_ids)
    apply_weights = make_active_weight_apply(neuron_ids)

    return common_headers_nn_only() + f"""

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {{

{biases}
    int<32> bias_output;
    bit<8> active_local_neuron_count;

    register<bit<32>>(1) threshold_reg;
    register<int<32>>(1) debug_nn_result;
    register<int<32>>(1) debug_branch;
    register<int<32>>(1) debug_threshold;
    register<bit<8>>(1) active_local_neuron_count_reg;

{neurons}

    action set_output_bias(int<32> b) {{
        bias_output = (int<32>)b;
    }}

    table output_bias {{
        actions = {{ set_output_bias; }}
        default_action = set_output_bias(0);
    }}

    action compute_output(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7,
                          bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15,
                          bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23,
                          bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {{
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * ((int<32>)hdr.nn.r0 >> 9));
        acc = acc + ((int<32>)(int<16>)w1 * ((int<32>)hdr.nn.r1 >> 9));
        acc = acc + ((int<32>)(int<16>)w2 * ((int<32>)hdr.nn.r2 >> 9));
        acc = acc + ((int<32>)(int<16>)w3 * ((int<32>)hdr.nn.r3 >> 9));
        acc = acc + ((int<32>)(int<16>)w4 * ((int<32>)hdr.nn.r4 >> 9));
        acc = acc + ((int<32>)(int<16>)w5 * ((int<32>)hdr.nn.r5 >> 9));
        acc = acc + ((int<32>)(int<16>)w6 * ((int<32>)hdr.nn.r6 >> 9));
        acc = acc + ((int<32>)(int<16>)w7 * ((int<32>)hdr.nn.r7 >> 9));
        acc = acc + ((int<32>)(int<16>)w8 * ((int<32>)hdr.nn.r8 >> 9));
        acc = acc + ((int<32>)(int<16>)w9 * ((int<32>)hdr.nn.r9 >> 9));
        acc = acc + ((int<32>)(int<16>)w10 * ((int<32>)hdr.nn.r10 >> 9));
        acc = acc + ((int<32>)(int<16>)w11 * ((int<32>)hdr.nn.r11 >> 9));
        acc = acc + ((int<32>)(int<16>)w12 * ((int<32>)hdr.nn.r12 >> 9));
        acc = acc + ((int<32>)(int<16>)w13 * ((int<32>)hdr.nn.r13 >> 9));
        acc = acc + ((int<32>)(int<16>)w14 * ((int<32>)hdr.nn.r14 >> 9));
        acc = acc + ((int<32>)(int<16>)w15 * ((int<32>)hdr.nn.r15 >> 9));
        acc = acc + ((int<32>)(int<16>)w16 * ((int<32>)hdr.nn.r16 >> 9));
        acc = acc + ((int<32>)(int<16>)w17 * ((int<32>)hdr.nn.r17 >> 9));
        acc = acc + ((int<32>)(int<16>)w18 * ((int<32>)hdr.nn.r18 >> 9));
        acc = acc + ((int<32>)(int<16>)w19 * ((int<32>)hdr.nn.r19 >> 9));
        acc = acc + ((int<32>)(int<16>)w20 * ((int<32>)hdr.nn.r20 >> 9));
        acc = acc + ((int<32>)(int<16>)w21 * ((int<32>)hdr.nn.r21 >> 9));
        acc = acc + ((int<32>)(int<16>)w22 * ((int<32>)hdr.nn.r22 >> 9));
        acc = acc + ((int<32>)(int<16>)w23 * ((int<32>)hdr.nn.r23 >> 9));
        acc = acc + ((int<32>)(int<16>)w24 * ((int<32>)hdr.nn.r24 >> 9));
        acc = acc + ((int<32>)(int<16>)w25 * ((int<32>)hdr.nn.r25 >> 9));
        acc = acc + ((int<32>)(int<16>)w26 * ((int<32>)hdr.nn.r26 >> 9));
        acc = acc + ((int<32>)(int<16>)w27 * ((int<32>)hdr.nn.r27 >> 9));
        acc = acc + ((int<32>)(int<16>)w28 * ((int<32>)hdr.nn.r28 >> 9));
        acc = acc + ((int<32>)(int<16>)w29 * ((int<32>)hdr.nn.r29 >> 9));
        acc = acc + ((int<32>)(int<16>)w30 * ((int<32>)hdr.nn.r30 >> 9));
        acc = acc + ((int<32>)(int<16>)w31 * ((int<32>)hdr.nn.r31 >> 9));
        acc = acc + bias_output;
        hdr.nn.nn_result = acc;
        debug_nn_result.write(0, acc);
    }}

    table output_weights {{
        actions = {{ compute_output; NoAction; }}
        default_action = NoAction();
    }}

{route_block()}

    apply {{
        if (hdr.ipv4.isValid() && hdr.nn.isValid() && hdr.nn.magic == NN_MAGIC) {{
            {apply_bias}
            output_bias.apply();
{apply_weights}
            output_weights.apply();

            bit<32> threshold_unsigned;
            threshold_reg.read(threshold_unsigned, 0);
            int<32> threshold_val = (int<32>)threshold_unsigned;
            debug_threshold.write(0, threshold_val);

            bool is_normal = (int<32>)hdr.nn.nn_result <= threshold_val;
            debug_branch.write(0, is_normal ? (int<32>)0 : (int<32>)1);

            if (is_normal) {{
                if ((bit<32>)hdr.ipv4.dstAddr == 32w0x0a000002) {{
                    // Left-to-right: remove transit NN state before host delivery.
                    hdr.nn.setInvalid();
                }} else {{
                    // Right-to-left: keep NN state so S1 can confirm classification and strip it there.
                    hdr.ipv4.diffserv = 8w0xfd;
                    hdr.nn.flags = 16w0x0001;
                }}
            }} else {{
                mark_to_drop(standard_metadata);
                standard_metadata.egress_spec = 511;
            }}
        }}

        if (hdr.ipv4.isValid() && standard_metadata.egress_spec != 511) {{
            ipv4_lpm.apply();
        }}
    }}
}}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {{
    apply {{
        if (standard_metadata.egress_spec == 511) {{
            mark_to_drop(standard_metadata);
        }}
    }}
}}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {{
    apply {{ }}
}}

control MyDeparser(packet_out packet, in headers hdr) {{
    apply {{
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.nn);
    }}
}}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
"""


def generate_one_hidden(num_switches: int, output_dir: Path, stage1_template: Path) -> Dict[str, object]:
    if num_switches < 2:
        raise ValueError("--num-switches must be >= 2 for one_hidden")
    if not stage1_template.exists():
        raise ValueError(f"stage1 template not found: {stage1_template}")

    ranges = build_stage_ranges_one_hidden(num_switches)
    output_dir.mkdir(parents=True, exist_ok=True)

    s1_out = output_dir / "ids_nn_dynamic_s1.p4"
    s1_out.write_text(stage1_template.read_text(encoding="utf-8"), encoding="utf-8")

    for switch_idx in range(2, num_switches + 1):
        n0, n1 = ranges[switch_idx - 1]
        if switch_idx == num_switches:
            text = stage_last_program(n0, n1)
        else:
            text = stage_mid_program(n0, n1)
        out = output_dir / f"ids_nn_dynamic_s{switch_idx}.p4"
        out.write_text(text, encoding="utf-8")

    return {
        "profile": PROFILE_ONE,
        "num_switches": num_switches,
        "h1_stage_ranges": ranges,
    }


def generate_two_hidden(
    num_switches: int,
    output_dir: Path,
    template_dir: Path,
) -> Dict[str, object]:
    if num_switches != 4:
        raise ValueError("two_hidden profile supports exactly --num-switches 4 (same earlier split)")

    sources = [template_dir / f"ids_nn_dynamic_s{i}.p4" for i in (1, 2, 3, 4)]
    missing = [str(p) for p in sources if not p.exists()]
    if missing:
        raise ValueError(
            "two_hidden dynamic template files missing. Expected: " + ", ".join(missing)
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    for i, src in enumerate(sources, start=1):
        dst = output_dir / f"ids_nn_dynamic_s{i}.p4"
        if src.resolve() != dst.resolve():
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    return {
        "profile": PROFILE_TWO,
        "num_switches": 4,
        "h1_stage_ranges": [(0, 7), (8, 15), (16, 23), (24, 31)],
        "h2_stage_ranges": [(0, 3), (4, 7), (8, 11), (12, 15)],
        "notes": "Same 4-switch distribution as the current 9_32_16_1 multi-switch design",
    }


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parents[1]

    ap = argparse.ArgumentParser(description="Generate dynamic multi-switch P4 files")
    ap.add_argument(
        "--profile",
        choices=[PROFILE_ONE, PROFILE_TWO],
        default=PROFILE_ONE,
        help="Profile family to generate",
    )
    ap.add_argument("--num-switches", type=int, default=4, help="Number of switches")
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=base_dir / "p4",
        help="Output directory for ids_nn_dynamic_s*.p4",
    )
    ap.add_argument(
        "--stage1-template",
        type=Path,
        default=base_dir / "p4" / "ids_nn_dynamic_s1.p4",
        help="Template P4 for one_hidden stage-1 (feature extraction stage)",
    )
    ap.add_argument(
        "--two-hidden-template-dir",
        type=Path,
        default=base_dir / "templates" / "two_hidden",
        help="Directory containing ids_nn_dynamic_s1.p4..ids_nn_dynamic_s4.p4 templates",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    try:
        if args.profile == PROFILE_ONE:
            layout = generate_one_hidden(
                num_switches=args.num_switches,
                output_dir=args.output_dir,
                stage1_template=args.stage1_template,
            )
        else:
            layout = generate_two_hidden(
                num_switches=args.num_switches,
                output_dir=args.output_dir,
                template_dir=args.two_hidden_template_dir,
            )
    except Exception as exc:
        raise SystemExit(f"Error: {exc}") from exc

    layout_path = args.output_dir / "switch_layout.json"
    layout_path.write_text(json.dumps(layout, indent=2) + "\n", encoding="utf-8")

    print(f"Generated dynamic P4 stages in: {args.output_dir}")
    print(f"Profile: {layout['profile']}")
    if layout["profile"] == PROFILE_ONE:
        print(f"Stage-1 template: {args.stage1_template}")
        for i, r in enumerate(layout["h1_stage_ranges"], start=1):
            start, end = r
            count = 0 if start < 0 else (end - start + 1)
            if count == 0:
                print(f"  S{i}: no local neurons")
            else:
                print(f"  S{i}: H1 neurons {start}..{end} (count={count})")
    else:
        print(f"Two-hidden dynamic template dir: {args.two_hidden_template_dir}")
        for i, (h1r, h2r) in enumerate(
            zip(layout["h1_stage_ranges"], layout["h2_stage_ranges"]),
            start=1,
        ):
            print(
                f"  S{i}: H1 {h1r[0]}..{h1r[1]} and H2 {h2r[0]}..{h2r[1]}"
            )

    print(f"Layout manifest: {layout_path}")


if __name__ == "__main__":
    main()
