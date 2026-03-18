#!/usr/bin/env python3
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "p4"

FEATURE_UDP_PORT = 5555
NN_MAGIC = 0xface


def neuron_action(idx: int, use_meta: str) -> str:
    # use_meta in {"meta", "hdr.nn"}
    if use_meta == "meta":
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


def common_headers(include_features: bool, include_nn_parse: bool) -> str:
    feat_hdr = """
header features_t {
    bit<16> f0;
    bit<16> f1;
    bit<16> f2;
    bit<16> f3;
    bit<16> f4;
    bit<16> f5;
    bit<16> f6;
    bit<16> f7;
    bit<16> f8;
}
""" if include_features else ""

    parse_feat = """
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            FEATURE_UDP_PORT: parse_features;
            default: accept;
        }
    }

    state parse_features {
        packet.extract(hdr.features);
        transition accept;
    }
""" if include_features else """
    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_nn;
    }
"""

    parse_nn = """
    state parse_nn {
        packet.extract(hdr.nn);
        transition accept;
    }
""" if include_nn_parse else ""

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

{feat_hdr}
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
    {'features_t features;' if include_features else ''}
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
        transition {'parse_nn' if include_nn_parse else 'accept'};
    }}

{parse_feat}
{parse_nn}
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


def stage1_program() -> str:
    neurons = "\n".join(neuron_action(i, "meta") for i in range(8))
    apply_bias = " ".join(f"neuron{i}_bias.apply();" for i in range(8))
    apply_w = " ".join(f"neuron{i}_weights.apply();" for i in range(8))

    return common_headers(include_features=True, include_nn_parse=False) + f"""

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {{

    int<32> bias_0;
    int<32> bias_1;
    int<32> bias_2;
    int<32> bias_3;
    int<32> bias_4;
    int<32> bias_5;
    int<32> bias_6;
    int<32> bias_7;

    bit<32> total_pkts;
    bit<32> total_bytes;
    bit<32> tmp_scaled;
    bit<32> proto_scaled;
    bit<32> sttl_scaled;
    bit<32> duration_scaled;
    bit<32> rate_scaled;
    bit<32> mean_bytes;
    bit<32> denom_idx;
    bit<32> recip_val;
    bit<64> mul_tmp;

    bit<16> cand_0;
    bit<16> cand_1;
    bit<16> cand_2;
    bit<16> cand_3;
    bit<16> cand_4;
    bit<16> cand_5;
    bit<16> cand_6;
    bit<16> cand_7;
    bit<16> cand_8;
    bit<16> cand_9;
    bit<16> cand_10;
    bit<16> cand_11;
    bit<16> cand_12;
    bit<16> cand_13;
    bit<16> cand_14;
    bit<8> map_idx;

    bit<16> feature_mask;

    register<bit<16>>(1) feature_mask_reg;
    register<bit<8>>(9) feature_map_reg;

    register<bit<32>>(16384) reg_packet_count;
    register<bit<32>>(16384) reg_byte_count;
    register<bit<32>>(16384) reg_dst_packet_count;
    register<bit<32>>(16384) reg_dst_byte_count;
    register<bit<8>>(16384) reg_sttl;
    register<bit<8>>(16384) reg_dttl;
    register<bit<16>>(16384) reg_swin;
    register<bit<16>>(16384) reg_dwin;
    register<bit<48>>(16384) reg_first_ts;

    register<bit<32>>(513) recip_pkt_reg;
    register<bit<32>>(513) recip_dur_reg;

    register<bit<16>>(9) debug_features;

    action update_flow_stats() {{
        bit<14> hash_index;
        bit<32> src_pkt_cnt;
        bit<32> src_byte_cnt;
        bit<32> dst_pkt_cnt;
        bit<32> dst_byte_cnt;
        bit<8> sttl_val;
        bit<8> dttl_val;
        bit<16> swin_val;
        bit<16> dwin_val;
        bit<48> first_ts;
        bit<48> cur_ts;
        bit<48> flow_dur;
        int<32> norm_ip1;
        int<32> norm_ip2;
        bit<16> norm_port1;
        bit<16> norm_port2;

        if (hdr.tcp.isValid()) {{
            meta.src_port = hdr.tcp.srcPort;
            meta.dst_port = hdr.tcp.dstPort;
        }} else if (hdr.udp.isValid()) {{
            meta.src_port = hdr.udp.srcPort;
            meta.dst_port = hdr.udp.dstPort;
        }} else {{
            meta.src_port = 0;
            meta.dst_port = 0;
        }}

        if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {{
            meta.is_forward_direction = 1;
            norm_ip1 = hdr.ipv4.srcAddr;
            norm_ip2 = hdr.ipv4.dstAddr;
            norm_port1 = meta.src_port;
            norm_port2 = meta.dst_port;
        }} else if (hdr.ipv4.srcAddr > hdr.ipv4.dstAddr) {{
            meta.is_forward_direction = 0;
            norm_ip1 = hdr.ipv4.dstAddr;
            norm_ip2 = hdr.ipv4.srcAddr;
            norm_port1 = meta.dst_port;
            norm_port2 = meta.src_port;
        }} else {{
            if (meta.src_port <= meta.dst_port) {{
                meta.is_forward_direction = 1;
                norm_ip1 = hdr.ipv4.srcAddr;
                norm_ip2 = hdr.ipv4.dstAddr;
                norm_port1 = meta.src_port;
                norm_port2 = meta.dst_port;
            }} else {{
                meta.is_forward_direction = 0;
                norm_ip1 = hdr.ipv4.dstAddr;
                norm_ip2 = hdr.ipv4.srcAddr;
                norm_port1 = meta.dst_port;
                norm_port2 = meta.src_port;
            }}
        }}

        hash(hash_index, HashAlgorithm.crc16, (bit<14>)0,
             {{ norm_ip1, norm_ip2, hdr.ipv4.protocol, norm_port1, norm_port2 }},
             (int<32>)16384);

        reg_packet_count.read(src_pkt_cnt, (bit<32>)hash_index);
        reg_byte_count.read(src_byte_cnt, (bit<32>)hash_index);
        reg_dst_packet_count.read(dst_pkt_cnt, (bit<32>)hash_index);
        reg_dst_byte_count.read(dst_byte_cnt, (bit<32>)hash_index);
        reg_sttl.read(sttl_val, (bit<32>)hash_index);
        reg_dttl.read(dttl_val, (bit<32>)hash_index);
        reg_swin.read(swin_val, (bit<32>)hash_index);
        reg_dwin.read(dwin_val, (bit<32>)hash_index);
        reg_first_ts.read(first_ts, (bit<32>)hash_index);

        cur_ts = (bit<48>)standard_metadata.ingress_global_timestamp;
        if ((src_pkt_cnt == 0) && (dst_pkt_cnt == 0)) {{
            first_ts = cur_ts;
            reg_first_ts.write((bit<32>)hash_index, first_ts);
        }}

        if (meta.is_forward_direction == 1) {{
            if (src_pkt_cnt == 0) {{
                sttl_val = hdr.ipv4.ttl;
                reg_sttl.write((bit<32>)hash_index, sttl_val);
                if (hdr.tcp.isValid()) {{
                    swin_val = hdr.tcp.window;
                }} else {{
                    swin_val = 0;
                }}
                reg_swin.write((bit<32>)hash_index, swin_val);
            }}
            src_pkt_cnt = src_pkt_cnt + 1;
            src_byte_cnt = src_byte_cnt + (bit<32>)standard_metadata.packet_length;
            reg_packet_count.write((bit<32>)hash_index, src_pkt_cnt);
            reg_byte_count.write((bit<32>)hash_index, src_byte_cnt);
        }} else {{
            if (dst_pkt_cnt == 0) {{
                dttl_val = hdr.ipv4.ttl;
                reg_dttl.write((bit<32>)hash_index, dttl_val);
                if (hdr.tcp.isValid()) {{
                    dwin_val = hdr.tcp.window;
                }} else {{
                    dwin_val = 0;
                }}
                reg_dwin.write((bit<32>)hash_index, dwin_val);
            }}
            dst_pkt_cnt = dst_pkt_cnt + 1;
            dst_byte_cnt = dst_byte_cnt + (bit<32>)standard_metadata.packet_length;
            reg_dst_packet_count.write((bit<32>)hash_index, dst_pkt_cnt);
            reg_dst_byte_count.write((bit<32>)hash_index, dst_byte_cnt);
        }}

        meta.flow_packet_count = src_pkt_cnt;
        meta.flow_byte_count = src_byte_cnt;
        meta.flow_dst_packet_count = dst_pkt_cnt;
        meta.flow_dst_byte_count = dst_byte_cnt;
        meta.flow_sttl = sttl_val;
        meta.flow_dttl = dttl_val;
        meta.flow_swin = swin_val;
        meta.flow_dwin = dwin_val;
        flow_dur = cur_ts - first_ts;
        meta.flow_duration = flow_dur;
    }}

{neurons}
{route_block()}

    apply {{
        if (hdr.ipv4.isValid()) {{
            if (hdr.features.isValid()) {{
                meta.feature_0 = hdr.features.f0;
                meta.feature_1 = hdr.features.f1;
                meta.feature_2 = hdr.features.f2;
                meta.feature_3 = hdr.features.f3;
                meta.feature_4 = hdr.features.f4;
                meta.feature_5 = hdr.features.f5;
                meta.feature_6 = hdr.features.f6;
                meta.feature_7 = hdr.features.f7;
                meta.feature_8 = hdr.features.f8;
            }} else {{
                update_flow_stats();

                total_pkts = meta.flow_packet_count + meta.flow_dst_packet_count;
                total_bytes = meta.flow_byte_count + meta.flow_dst_byte_count;

                proto_scaled = ((bit<32>)hdr.ipv4.protocol) << 4;
                if (proto_scaled > 512) {{ cand_0 = 512; }} else {{ cand_0 = (bit<16>)proto_scaled; }}

                sttl_scaled = ((bit<32>)meta.flow_sttl) << 1;
                if (sttl_scaled > 512) {{ cand_1 = 512; }} else {{ cand_1 = (bit<16>)sttl_scaled; }}

                if (meta.flow_byte_count > 24) {{
                    tmp_scaled = (meta.flow_byte_count - 24) >> 6;
                    cand_2 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_2 = 0; }}

                if (meta.flow_dst_byte_count > 24) {{
                    tmp_scaled = (meta.flow_dst_byte_count - 24) >> 6;
                    cand_3 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_3 = 0; }}

                if (meta.flow_packet_count > 0) {{
                    tmp_scaled = (meta.flow_packet_count - 1) << 2;
                    cand_4 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_4 = 0; }}

                if (meta.flow_dst_packet_count > 0) {{
                    tmp_scaled = (meta.flow_dst_packet_count - 1) << 2;
                    cand_5 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_5 = 0; }}

                if (total_pkts > 0) {{
                    tmp_scaled = (total_pkts - 1) << 2;
                    cand_6 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_6 = 0; }}

                if (total_bytes > 24) {{
                    tmp_scaled = (total_bytes - 24) >> 6;
                    cand_7 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                }} else {{ cand_7 = 0; }}

                duration_scaled = (bit<32>)(meta.flow_duration >> 20);
                cand_8 = (duration_scaled > 512) ? 512 : (bit<16>)duration_scaled;

                if (duration_scaled > 0) {{
                    denom_idx = duration_scaled;
                    if (denom_idx > 512) {{ denom_idx = 512; }}
                    recip_dur_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)total_pkts * (bit<64>)recip_val;
                    rate_scaled = (bit<32>)(mul_tmp >> 16);
                    cand_9 = (rate_scaled > 512) ? 512 : (bit<16>)rate_scaled;
                }} else {{ cand_9 = 0; }}

                if (meta.flow_packet_count > 0) {{
                    denom_idx = meta.flow_packet_count;
                    if (denom_idx > 512) {{ denom_idx = 512; }}
                    recip_pkt_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)meta.flow_byte_count * (bit<64>)recip_val;
                    mean_bytes = (bit<32>)(mul_tmp >> 16);
                    if (mean_bytes > 24) {{
                        tmp_scaled = (mean_bytes - 24) >> 1;
                        cand_10 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                    }} else {{ cand_10 = 0; }}
                }} else {{ cand_10 = 0; }}

                if (meta.flow_dst_packet_count > 0) {{
                    denom_idx = meta.flow_dst_packet_count;
                    if (denom_idx > 512) {{ denom_idx = 512; }}
                    recip_pkt_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)meta.flow_dst_byte_count * (bit<64>)recip_val;
                    mean_bytes = (bit<32>)(mul_tmp >> 16);
                    if (mean_bytes > 24) {{
                        tmp_scaled = (mean_bytes - 24) >> 1;
                        cand_11 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                    }} else {{ cand_11 = 0; }}
                }} else {{ cand_11 = 0; }}

                sttl_scaled = ((bit<32>)meta.flow_dttl) << 1;
                if (sttl_scaled > 512) {{ cand_12 = 512; }} else {{ cand_12 = (bit<16>)sttl_scaled; }}

                tmp_scaled = ((bit<32>)meta.flow_swin) >> 7;
                cand_13 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                tmp_scaled = ((bit<32>)meta.flow_dwin) >> 7;
                cand_14 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                feature_map_reg.read(map_idx, 0);
                if (map_idx == 0) {{ meta.feature_0 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_0 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_0 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_0 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_0 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_0 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_0 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_0 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_0 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_0 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_0 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_0 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_0 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_0 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_0 = cand_14; }}
                else {{ meta.feature_0 = 0; }}

                feature_map_reg.read(map_idx, 1);
                if (map_idx == 0) {{ meta.feature_1 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_1 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_1 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_1 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_1 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_1 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_1 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_1 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_1 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_1 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_1 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_1 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_1 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_1 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_1 = cand_14; }}
                else {{ meta.feature_1 = 0; }}

                feature_map_reg.read(map_idx, 2);
                if (map_idx == 0) {{ meta.feature_2 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_2 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_2 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_2 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_2 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_2 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_2 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_2 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_2 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_2 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_2 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_2 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_2 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_2 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_2 = cand_14; }}
                else {{ meta.feature_2 = 0; }}

                feature_map_reg.read(map_idx, 3);
                if (map_idx == 0) {{ meta.feature_3 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_3 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_3 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_3 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_3 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_3 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_3 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_3 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_3 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_3 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_3 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_3 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_3 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_3 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_3 = cand_14; }}
                else {{ meta.feature_3 = 0; }}

                feature_map_reg.read(map_idx, 4);
                if (map_idx == 0) {{ meta.feature_4 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_4 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_4 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_4 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_4 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_4 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_4 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_4 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_4 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_4 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_4 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_4 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_4 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_4 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_4 = cand_14; }}
                else {{ meta.feature_4 = 0; }}

                feature_map_reg.read(map_idx, 5);
                if (map_idx == 0) {{ meta.feature_5 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_5 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_5 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_5 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_5 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_5 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_5 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_5 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_5 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_5 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_5 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_5 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_5 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_5 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_5 = cand_14; }}
                else {{ meta.feature_5 = 0; }}

                feature_map_reg.read(map_idx, 6);
                if (map_idx == 0) {{ meta.feature_6 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_6 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_6 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_6 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_6 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_6 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_6 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_6 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_6 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_6 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_6 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_6 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_6 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_6 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_6 = cand_14; }}
                else {{ meta.feature_6 = 0; }}

                feature_map_reg.read(map_idx, 7);
                if (map_idx == 0) {{ meta.feature_7 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_7 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_7 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_7 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_7 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_7 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_7 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_7 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_7 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_7 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_7 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_7 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_7 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_7 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_7 = cand_14; }}
                else {{ meta.feature_7 = 0; }}

                feature_map_reg.read(map_idx, 8);
                if (map_idx == 0) {{ meta.feature_8 = cand_0; }}
                else if (map_idx == 1) {{ meta.feature_8 = cand_1; }}
                else if (map_idx == 2) {{ meta.feature_8 = cand_2; }}
                else if (map_idx == 3) {{ meta.feature_8 = cand_3; }}
                else if (map_idx == 4) {{ meta.feature_8 = cand_4; }}
                else if (map_idx == 5) {{ meta.feature_8 = cand_5; }}
                else if (map_idx == 6) {{ meta.feature_8 = cand_6; }}
                else if (map_idx == 7) {{ meta.feature_8 = cand_7; }}
                else if (map_idx == 8) {{ meta.feature_8 = cand_8; }}
                else if (map_idx == 9) {{ meta.feature_8 = cand_9; }}
                else if (map_idx == 10) {{ meta.feature_8 = cand_10; }}
                else if (map_idx == 11) {{ meta.feature_8 = cand_11; }}
                else if (map_idx == 12) {{ meta.feature_8 = cand_12; }}
                else if (map_idx == 13) {{ meta.feature_8 = cand_13; }}
                else if (map_idx == 14) {{ meta.feature_8 = cand_14; }}
                else {{ meta.feature_8 = 0; }}
            }}

            feature_mask_reg.read(feature_mask, 0);
            if ((feature_mask & 16w0x0001) == 0) {{ meta.feature_0 = 0; }}
            if ((feature_mask & 16w0x0002) == 0) {{ meta.feature_1 = 0; }}
            if ((feature_mask & 16w0x0004) == 0) {{ meta.feature_2 = 0; }}
            if ((feature_mask & 16w0x0008) == 0) {{ meta.feature_3 = 0; }}
            if ((feature_mask & 16w0x0010) == 0) {{ meta.feature_4 = 0; }}
            if ((feature_mask & 16w0x0020) == 0) {{ meta.feature_5 = 0; }}
            if ((feature_mask & 16w0x0040) == 0) {{ meta.feature_6 = 0; }}
            if ((feature_mask & 16w0x0080) == 0) {{ meta.feature_7 = 0; }}
            if ((feature_mask & 16w0x0100) == 0) {{ meta.feature_8 = 0; }}

            debug_features.write(0, meta.feature_0);
            debug_features.write(1, meta.feature_1);
            debug_features.write(2, meta.feature_2);
            debug_features.write(3, meta.feature_3);
            debug_features.write(4, meta.feature_4);
            debug_features.write(5, meta.feature_5);
            debug_features.write(6, meta.feature_6);
            debug_features.write(7, meta.feature_7);
            debug_features.write(8, meta.feature_8);

            {apply_bias}
            {apply_w}

            if (hdr.features.isValid()) {{
                hdr.features.setInvalid();
            }}

            hdr.nn.setValid();
            hdr.nn.magic = NN_MAGIC;
            hdr.nn.flags = 0;
            hdr.nn.f0 = meta.feature_0;
            hdr.nn.f1 = meta.feature_1;
            hdr.nn.f2 = meta.feature_2;
            hdr.nn.f3 = meta.feature_3;
            hdr.nn.f4 = meta.feature_4;
            hdr.nn.f5 = meta.feature_5;
            hdr.nn.f6 = meta.feature_6;
            hdr.nn.f7 = meta.feature_7;
            hdr.nn.f8 = meta.feature_8;
            hdr.nn.r0 = 0; hdr.nn.r1 = 0; hdr.nn.r2 = 0; hdr.nn.r3 = 0;
            hdr.nn.r4 = 0; hdr.nn.r5 = 0; hdr.nn.r6 = 0; hdr.nn.r7 = 0;
            hdr.nn.r8 = 0; hdr.nn.r9 = 0; hdr.nn.r10 = 0; hdr.nn.r11 = 0;
            hdr.nn.r12 = 0; hdr.nn.r13 = 0; hdr.nn.r14 = 0; hdr.nn.r15 = 0;
            hdr.nn.r16 = 0; hdr.nn.r17 = 0; hdr.nn.r18 = 0; hdr.nn.r19 = 0;
            hdr.nn.r20 = 0; hdr.nn.r21 = 0; hdr.nn.r22 = 0; hdr.nn.r23 = 0;
            hdr.nn.r24 = 0; hdr.nn.r25 = 0; hdr.nn.r26 = 0; hdr.nn.r27 = 0;
            hdr.nn.r28 = 0; hdr.nn.r29 = 0; hdr.nn.r30 = 0; hdr.nn.r31 = 0;
            hdr.nn.nn_result = 0;

            hdr.nn.r0 = meta.result_0;
            hdr.nn.r1 = meta.result_1;
            hdr.nn.r2 = meta.result_2;
            hdr.nn.r3 = meta.result_3;
            hdr.nn.r4 = meta.result_4;
            hdr.nn.r5 = meta.result_5;
            hdr.nn.r6 = meta.result_6;
            hdr.nn.r7 = meta.result_7;

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
        packet.emit(hdr.features);
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


def stage_mid_program(name: str, n0: int, n1: int) -> str:
    neurons = "\n".join(neuron_action(i, "hdr.nn") for i in range(n0, n1 + 1))
    apply_bias = " ".join(f"neuron{i}_bias.apply();" for i in range(n0, n1 + 1))
    apply_w = " ".join(f"neuron{i}_weights.apply();" for i in range(n0, n1 + 1))
    biases = "\n".join(f"    int<32> bias_{i};" for i in range(n0, n1 + 1))

    return common_headers(include_features=False, include_nn_parse=True) + f"""

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {{

{biases}
{neurons}
{route_block()}

    apply {{
        if (hdr.ipv4.isValid() && hdr.nn.isValid() && hdr.nn.magic == NN_MAGIC) {{
            {apply_bias}
            {apply_w}
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


def stage4_program() -> str:
    neurons = "\n".join(neuron_action(i, "hdr.nn") for i in range(24, 32))
    apply_bias = " ".join(f"neuron{i}_bias.apply();" for i in range(24, 32))
    apply_w = " ".join(f"neuron{i}_weights.apply();" for i in range(24, 32))
    biases = "\n".join(f"    int<32> bias_{i};" for i in range(24, 32))

    return common_headers(include_features=False, include_nn_parse=True) + f"""

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {{

{biases}
    int<32> bias_output;

    register<bit<32>>(1) threshold_reg;
    register<int<32>>(1) debug_nn_result;
    register<int<32>>(1) debug_branch;
    register<int<32>>(1) debug_threshold;

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
            {apply_w}
            output_weights.apply();

            bit<32> threshold_unsigned;
            threshold_reg.read(threshold_unsigned, 0);
            int<32> threshold_val = (int<32>)threshold_unsigned;
            debug_threshold.write(0, threshold_val);

            bool is_normal = (int<32>)hdr.nn.nn_result <= threshold_val;
            debug_branch.write(0, is_normal ? (int<32>)0 : (int<32>)1);

            if (is_normal) {{
                hdr.nn.setInvalid();
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


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "ids_nn_s1.p4").write_text(stage1_program())
    (OUT_DIR / "ids_nn_s2.p4").write_text(stage_mid_program("s2", 8, 15))
    (OUT_DIR / "ids_nn_s3.p4").write_text(stage_mid_program("s3", 16, 23))
    (OUT_DIR / "ids_nn_s4.p4").write_text(stage4_program())
    print(f"Generated P4 files in {OUT_DIR}")


if __name__ == "__main__":
    main()
