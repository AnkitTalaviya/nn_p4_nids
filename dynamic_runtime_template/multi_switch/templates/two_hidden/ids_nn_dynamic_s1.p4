/* P4_16 */
#include <core.p4>
#include <v1model.p4>

const bit<16> FEATURE_UDP_PORT = 5555;
const bit<16> NN_MAGIC = 16w0xface;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
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
}

header tcp_t {
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
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


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

header nn_state_t {
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
    int<32> h2_acc0;
    int<32> h2_acc1;
    int<32> h2_acc2;
    int<32> h2_acc3;
    int<32> nn_result;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    features_t features;
    nn_state_t nn;
}

struct metadata {
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
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }


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


}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    int<32> bias_0;
    int<32> bias_1;
    int<32> bias_2;
    int<32> bias_3;
    int<32> bias_4;
    int<32> bias_5;
    int<32> bias_6;
    int<32> bias_7;
    int<32> bias2_0;
    int<32> bias2_1;
    int<32> bias2_2;
    int<32> bias2_3;

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
    bit<8> active_h2_count;
    bit<8> h2_partial_mode;

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
    register<bit<8>>(1) active_local_h2_count_reg;
    register<bit<8>>(1) h2_partial_mode_reg;

    action update_flow_stats() {
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

        if (hdr.tcp.isValid()) {
            meta.src_port = hdr.tcp.srcPort;
            meta.dst_port = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.src_port = hdr.udp.srcPort;
            meta.dst_port = hdr.udp.dstPort;
        } else {
            meta.src_port = 0;
            meta.dst_port = 0;
        }

        if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {
            meta.is_forward_direction = 1;
            norm_ip1 = hdr.ipv4.srcAddr;
            norm_ip2 = hdr.ipv4.dstAddr;
            norm_port1 = meta.src_port;
            norm_port2 = meta.dst_port;
        } else if (hdr.ipv4.srcAddr > hdr.ipv4.dstAddr) {
            meta.is_forward_direction = 0;
            norm_ip1 = hdr.ipv4.dstAddr;
            norm_ip2 = hdr.ipv4.srcAddr;
            norm_port1 = meta.dst_port;
            norm_port2 = meta.src_port;
        } else {
            if (meta.src_port <= meta.dst_port) {
                meta.is_forward_direction = 1;
                norm_ip1 = hdr.ipv4.srcAddr;
                norm_ip2 = hdr.ipv4.dstAddr;
                norm_port1 = meta.src_port;
                norm_port2 = meta.dst_port;
            } else {
                meta.is_forward_direction = 0;
                norm_ip1 = hdr.ipv4.dstAddr;
                norm_ip2 = hdr.ipv4.srcAddr;
                norm_port1 = meta.dst_port;
                norm_port2 = meta.src_port;
            }
        }

        hash(hash_index, HashAlgorithm.crc16, (bit<14>)0,
             { norm_ip1, norm_ip2, hdr.ipv4.protocol, norm_port1, norm_port2 },
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
        if ((src_pkt_cnt == 0) && (dst_pkt_cnt == 0)) {
            first_ts = cur_ts;
            reg_first_ts.write((bit<32>)hash_index, first_ts);
        }

        if (meta.is_forward_direction == 1) {
            if (src_pkt_cnt == 0) {
                sttl_val = hdr.ipv4.ttl;
                reg_sttl.write((bit<32>)hash_index, sttl_val);
                if (hdr.tcp.isValid()) {
                    swin_val = hdr.tcp.window;
                } else {
                    swin_val = 0;
                }
                reg_swin.write((bit<32>)hash_index, swin_val);
            }
            src_pkt_cnt = src_pkt_cnt + 1;
            src_byte_cnt = src_byte_cnt + (bit<32>)standard_metadata.packet_length;
            reg_packet_count.write((bit<32>)hash_index, src_pkt_cnt);
            reg_byte_count.write((bit<32>)hash_index, src_byte_cnt);
        } else {
            if (dst_pkt_cnt == 0) {
                dttl_val = hdr.ipv4.ttl;
                reg_dttl.write((bit<32>)hash_index, dttl_val);
                if (hdr.tcp.isValid()) {
                    dwin_val = hdr.tcp.window;
                } else {
                    dwin_val = 0;
                }
                reg_dwin.write((bit<32>)hash_index, dwin_val);
            }
            dst_pkt_cnt = dst_pkt_cnt + 1;
            dst_byte_cnt = dst_byte_cnt + (bit<32>)standard_metadata.packet_length;
            reg_dst_packet_count.write((bit<32>)hash_index, dst_pkt_cnt);
            reg_dst_byte_count.write((bit<32>)hash_index, dst_byte_cnt);
        }

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
    }


    action set_bias_0(int<32> b) {
        bias_0 = (int<32>)b;
    }

    table neuron0_bias {
        actions = { set_bias_0; }
        default_action = set_bias_0(0);
    }

    action compute_neuron_0(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_0 * (int<32>)512);

        if (acc > 0) {
            meta.result_0 = (int<32>)acc;
        } else {
            meta.result_0 = 0;
        }
    }

    table neuron0_weights {
        actions = { compute_neuron_0; NoAction; }
        default_action = NoAction();
    }


    action set_bias_1(int<32> b) {
        bias_1 = (int<32>)b;
    }

    table neuron1_bias {
        actions = { set_bias_1; }
        default_action = set_bias_1(0);
    }

    action compute_neuron_1(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_1 * (int<32>)512);

        if (acc > 0) {
            meta.result_1 = (int<32>)acc;
        } else {
            meta.result_1 = 0;
        }
    }

    table neuron1_weights {
        actions = { compute_neuron_1; NoAction; }
        default_action = NoAction();
    }


    action set_bias_2(int<32> b) {
        bias_2 = (int<32>)b;
    }

    table neuron2_bias {
        actions = { set_bias_2; }
        default_action = set_bias_2(0);
    }

    action compute_neuron_2(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_2 * (int<32>)512);

        if (acc > 0) {
            meta.result_2 = (int<32>)acc;
        } else {
            meta.result_2 = 0;
        }
    }

    table neuron2_weights {
        actions = { compute_neuron_2; NoAction; }
        default_action = NoAction();
    }


    action set_bias_3(int<32> b) {
        bias_3 = (int<32>)b;
    }

    table neuron3_bias {
        actions = { set_bias_3; }
        default_action = set_bias_3(0);
    }

    action compute_neuron_3(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_3 * (int<32>)512);

        if (acc > 0) {
            meta.result_3 = (int<32>)acc;
        } else {
            meta.result_3 = 0;
        }
    }

    table neuron3_weights {
        actions = { compute_neuron_3; NoAction; }
        default_action = NoAction();
    }


    action set_bias_4(int<32> b) {
        bias_4 = (int<32>)b;
    }

    table neuron4_bias {
        actions = { set_bias_4; }
        default_action = set_bias_4(0);
    }

    action compute_neuron_4(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_4 * (int<32>)512);

        if (acc > 0) {
            meta.result_4 = (int<32>)acc;
        } else {
            meta.result_4 = 0;
        }
    }

    table neuron4_weights {
        actions = { compute_neuron_4; NoAction; }
        default_action = NoAction();
    }


    action set_bias_5(int<32> b) {
        bias_5 = (int<32>)b;
    }

    table neuron5_bias {
        actions = { set_bias_5; }
        default_action = set_bias_5(0);
    }

    action compute_neuron_5(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_5 * (int<32>)512);

        if (acc > 0) {
            meta.result_5 = (int<32>)acc;
        } else {
            meta.result_5 = 0;
        }
    }

    table neuron5_weights {
        actions = { compute_neuron_5; NoAction; }
        default_action = NoAction();
    }


    action set_bias_6(int<32> b) {
        bias_6 = (int<32>)b;
    }

    table neuron6_bias {
        actions = { set_bias_6; }
        default_action = set_bias_6(0);
    }

    action compute_neuron_6(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_6 * (int<32>)512);

        if (acc > 0) {
            meta.result_6 = (int<32>)acc;
        } else {
            meta.result_6 = 0;
        }
    }

    table neuron6_weights {
        actions = { compute_neuron_6; NoAction; }
        default_action = NoAction();
    }


    action set_bias_7(int<32> b) {
        bias_7 = (int<32>)b;
    }

    table neuron7_bias {
        actions = { set_bias_7; }
        default_action = set_bias_7(0);
    }

    action compute_neuron_7(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8));
        acc = acc + (bias_7 * (int<32>)512);

        if (acc > 0) {
            meta.result_7 = (int<32>)acc;
        } else {
            meta.result_7 = 0;
        }
    }

    table neuron7_weights {
        actions = { compute_neuron_7; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_0(int<32> b) {
        bias2_0 = (int<32>)b;
    }

    table neuron2_0_bias {
        actions = { set_bias2_0; }
        default_action = set_bias2_0(0);
    }

    action compute_neuron2_0(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
        if (h2_partial_mode == 1) {
            hdr.nn.h2_acc0 = hdr.nn.h2_acc0 + acc;
        } else {
            acc = acc + (bias2_0 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r0 = acc;
            } else {
                hdr.nn.r0 = 0;
            }
        }
    }

    table neuron2_0_weights {
        actions = { compute_neuron2_0; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_1(int<32> b) {
        bias2_1 = (int<32>)b;
    }

    table neuron2_1_bias {
        actions = { set_bias2_1; }
        default_action = set_bias2_1(0);
    }

    action compute_neuron2_1(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
        if (h2_partial_mode == 1) {
            hdr.nn.h2_acc1 = hdr.nn.h2_acc1 + acc;
        } else {
            acc = acc + (bias2_1 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r1 = acc;
            } else {
                hdr.nn.r1 = 0;
            }
        }
    }

    table neuron2_1_weights {
        actions = { compute_neuron2_1; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_2(int<32> b) {
        bias2_2 = (int<32>)b;
    }

    table neuron2_2_bias {
        actions = { set_bias2_2; }
        default_action = set_bias2_2(0);
    }

    action compute_neuron2_2(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
        if (h2_partial_mode == 1) {
            hdr.nn.h2_acc2 = hdr.nn.h2_acc2 + acc;
        } else {
            acc = acc + (bias2_2 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r2 = acc;
            } else {
                hdr.nn.r2 = 0;
            }
        }
    }

    table neuron2_2_weights {
        actions = { compute_neuron2_2; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_3(int<32> b) {
        bias2_3 = (int<32>)b;
    }

    table neuron2_3_bias {
        actions = { set_bias2_3; }
        default_action = set_bias2_3(0);
    }

    action compute_neuron2_3(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
        if (h2_partial_mode == 1) {
            hdr.nn.h2_acc3 = hdr.nn.h2_acc3 + acc;
        } else {
            acc = acc + (bias2_3 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r3 = acc;
            } else {
                hdr.nn.r3 = 0;
            }
        }
    }

    table neuron2_3_weights {
        actions = { compute_neuron2_3; NoAction; }
        default_action = NoAction();
    }


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


    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.features.isValid()) {
                meta.feature_0 = hdr.features.f0;
                meta.feature_1 = hdr.features.f1;
                meta.feature_2 = hdr.features.f2;
                meta.feature_3 = hdr.features.f3;
                meta.feature_4 = hdr.features.f4;
                meta.feature_5 = hdr.features.f5;
                meta.feature_6 = hdr.features.f6;
                meta.feature_7 = hdr.features.f7;
                meta.feature_8 = hdr.features.f8;
            } else {
                update_flow_stats();

                total_pkts = meta.flow_packet_count + meta.flow_dst_packet_count;
                total_bytes = meta.flow_byte_count + meta.flow_dst_byte_count;

                proto_scaled = ((bit<32>)hdr.ipv4.protocol) << 4;
                if (proto_scaled > 512) { cand_0 = 512; } else { cand_0 = (bit<16>)proto_scaled; }

                sttl_scaled = ((bit<32>)meta.flow_sttl) << 1;
                if (sttl_scaled > 512) { cand_1 = 512; } else { cand_1 = (bit<16>)sttl_scaled; }

                if (meta.flow_byte_count > 24) {
                    tmp_scaled = (meta.flow_byte_count - 24) >> 6;
                    cand_2 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_2 = 0; }

                if (meta.flow_dst_byte_count > 24) {
                    tmp_scaled = (meta.flow_dst_byte_count - 24) >> 6;
                    cand_3 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_3 = 0; }

                if (meta.flow_packet_count > 0) {
                    tmp_scaled = (meta.flow_packet_count - 1) << 2;
                    cand_4 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_4 = 0; }

                if (meta.flow_dst_packet_count > 0) {
                    tmp_scaled = (meta.flow_dst_packet_count - 1) << 2;
                    cand_5 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_5 = 0; }

                if (total_pkts > 0) {
                    tmp_scaled = (total_pkts - 1) << 2;
                    cand_6 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_6 = 0; }

                if (total_bytes > 24) {
                    tmp_scaled = (total_bytes - 24) >> 6;
                    cand_7 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_7 = 0; }

                duration_scaled = (bit<32>)(meta.flow_duration >> 20);
                cand_8 = (duration_scaled > 512) ? 512 : (bit<16>)duration_scaled;

                if (duration_scaled > 0) {
                    denom_idx = duration_scaled;
                    if (denom_idx > 512) { denom_idx = 512; }
                    recip_dur_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)total_pkts * (bit<64>)recip_val;
                    rate_scaled = (bit<32>)(mul_tmp >> 16);
                    cand_9 = (rate_scaled > 512) ? 512 : (bit<16>)rate_scaled;
                } else { cand_9 = 0; }

                if (meta.flow_packet_count > 0) {
                    denom_idx = meta.flow_packet_count;
                    if (denom_idx > 512) { denom_idx = 512; }
                    recip_pkt_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)meta.flow_byte_count * (bit<64>)recip_val;
                    mean_bytes = (bit<32>)(mul_tmp >> 16);
                    if (mean_bytes > 24) {
                        tmp_scaled = (mean_bytes - 24) >> 1;
                        cand_10 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                    } else { cand_10 = 0; }
                } else { cand_10 = 0; }

                if (meta.flow_dst_packet_count > 0) {
                    denom_idx = meta.flow_dst_packet_count;
                    if (denom_idx > 512) { denom_idx = 512; }
                    recip_pkt_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)meta.flow_dst_byte_count * (bit<64>)recip_val;
                    mean_bytes = (bit<32>)(mul_tmp >> 16);
                    if (mean_bytes > 24) {
                        tmp_scaled = (mean_bytes - 24) >> 1;
                        cand_11 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                    } else { cand_11 = 0; }
                } else { cand_11 = 0; }

                sttl_scaled = ((bit<32>)meta.flow_dttl) << 1;
                if (sttl_scaled > 512) { cand_12 = 512; } else { cand_12 = (bit<16>)sttl_scaled; }

                tmp_scaled = ((bit<32>)meta.flow_swin) >> 7;
                cand_13 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                tmp_scaled = ((bit<32>)meta.flow_dwin) >> 7;
                cand_14 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                feature_map_reg.read(map_idx, 0);
                if (map_idx == 0) { meta.feature_0 = cand_0; }
                else if (map_idx == 1) { meta.feature_0 = cand_1; }
                else if (map_idx == 2) { meta.feature_0 = cand_2; }
                else if (map_idx == 3) { meta.feature_0 = cand_3; }
                else if (map_idx == 4) { meta.feature_0 = cand_4; }
                else if (map_idx == 5) { meta.feature_0 = cand_5; }
                else if (map_idx == 6) { meta.feature_0 = cand_6; }
                else if (map_idx == 7) { meta.feature_0 = cand_7; }
                else if (map_idx == 8) { meta.feature_0 = cand_8; }
                else if (map_idx == 9) { meta.feature_0 = cand_9; }
                else if (map_idx == 10) { meta.feature_0 = cand_10; }
                else if (map_idx == 11) { meta.feature_0 = cand_11; }
                else if (map_idx == 12) { meta.feature_0 = cand_12; }
                else if (map_idx == 13) { meta.feature_0 = cand_13; }
                else if (map_idx == 14) { meta.feature_0 = cand_14; }
                else { meta.feature_0 = 0; }

                feature_map_reg.read(map_idx, 1);
                if (map_idx == 0) { meta.feature_1 = cand_0; }
                else if (map_idx == 1) { meta.feature_1 = cand_1; }
                else if (map_idx == 2) { meta.feature_1 = cand_2; }
                else if (map_idx == 3) { meta.feature_1 = cand_3; }
                else if (map_idx == 4) { meta.feature_1 = cand_4; }
                else if (map_idx == 5) { meta.feature_1 = cand_5; }
                else if (map_idx == 6) { meta.feature_1 = cand_6; }
                else if (map_idx == 7) { meta.feature_1 = cand_7; }
                else if (map_idx == 8) { meta.feature_1 = cand_8; }
                else if (map_idx == 9) { meta.feature_1 = cand_9; }
                else if (map_idx == 10) { meta.feature_1 = cand_10; }
                else if (map_idx == 11) { meta.feature_1 = cand_11; }
                else if (map_idx == 12) { meta.feature_1 = cand_12; }
                else if (map_idx == 13) { meta.feature_1 = cand_13; }
                else if (map_idx == 14) { meta.feature_1 = cand_14; }
                else { meta.feature_1 = 0; }

                feature_map_reg.read(map_idx, 2);
                if (map_idx == 0) { meta.feature_2 = cand_0; }
                else if (map_idx == 1) { meta.feature_2 = cand_1; }
                else if (map_idx == 2) { meta.feature_2 = cand_2; }
                else if (map_idx == 3) { meta.feature_2 = cand_3; }
                else if (map_idx == 4) { meta.feature_2 = cand_4; }
                else if (map_idx == 5) { meta.feature_2 = cand_5; }
                else if (map_idx == 6) { meta.feature_2 = cand_6; }
                else if (map_idx == 7) { meta.feature_2 = cand_7; }
                else if (map_idx == 8) { meta.feature_2 = cand_8; }
                else if (map_idx == 9) { meta.feature_2 = cand_9; }
                else if (map_idx == 10) { meta.feature_2 = cand_10; }
                else if (map_idx == 11) { meta.feature_2 = cand_11; }
                else if (map_idx == 12) { meta.feature_2 = cand_12; }
                else if (map_idx == 13) { meta.feature_2 = cand_13; }
                else if (map_idx == 14) { meta.feature_2 = cand_14; }
                else { meta.feature_2 = 0; }

                feature_map_reg.read(map_idx, 3);
                if (map_idx == 0) { meta.feature_3 = cand_0; }
                else if (map_idx == 1) { meta.feature_3 = cand_1; }
                else if (map_idx == 2) { meta.feature_3 = cand_2; }
                else if (map_idx == 3) { meta.feature_3 = cand_3; }
                else if (map_idx == 4) { meta.feature_3 = cand_4; }
                else if (map_idx == 5) { meta.feature_3 = cand_5; }
                else if (map_idx == 6) { meta.feature_3 = cand_6; }
                else if (map_idx == 7) { meta.feature_3 = cand_7; }
                else if (map_idx == 8) { meta.feature_3 = cand_8; }
                else if (map_idx == 9) { meta.feature_3 = cand_9; }
                else if (map_idx == 10) { meta.feature_3 = cand_10; }
                else if (map_idx == 11) { meta.feature_3 = cand_11; }
                else if (map_idx == 12) { meta.feature_3 = cand_12; }
                else if (map_idx == 13) { meta.feature_3 = cand_13; }
                else if (map_idx == 14) { meta.feature_3 = cand_14; }
                else { meta.feature_3 = 0; }

                feature_map_reg.read(map_idx, 4);
                if (map_idx == 0) { meta.feature_4 = cand_0; }
                else if (map_idx == 1) { meta.feature_4 = cand_1; }
                else if (map_idx == 2) { meta.feature_4 = cand_2; }
                else if (map_idx == 3) { meta.feature_4 = cand_3; }
                else if (map_idx == 4) { meta.feature_4 = cand_4; }
                else if (map_idx == 5) { meta.feature_4 = cand_5; }
                else if (map_idx == 6) { meta.feature_4 = cand_6; }
                else if (map_idx == 7) { meta.feature_4 = cand_7; }
                else if (map_idx == 8) { meta.feature_4 = cand_8; }
                else if (map_idx == 9) { meta.feature_4 = cand_9; }
                else if (map_idx == 10) { meta.feature_4 = cand_10; }
                else if (map_idx == 11) { meta.feature_4 = cand_11; }
                else if (map_idx == 12) { meta.feature_4 = cand_12; }
                else if (map_idx == 13) { meta.feature_4 = cand_13; }
                else if (map_idx == 14) { meta.feature_4 = cand_14; }
                else { meta.feature_4 = 0; }

                feature_map_reg.read(map_idx, 5);
                if (map_idx == 0) { meta.feature_5 = cand_0; }
                else if (map_idx == 1) { meta.feature_5 = cand_1; }
                else if (map_idx == 2) { meta.feature_5 = cand_2; }
                else if (map_idx == 3) { meta.feature_5 = cand_3; }
                else if (map_idx == 4) { meta.feature_5 = cand_4; }
                else if (map_idx == 5) { meta.feature_5 = cand_5; }
                else if (map_idx == 6) { meta.feature_5 = cand_6; }
                else if (map_idx == 7) { meta.feature_5 = cand_7; }
                else if (map_idx == 8) { meta.feature_5 = cand_8; }
                else if (map_idx == 9) { meta.feature_5 = cand_9; }
                else if (map_idx == 10) { meta.feature_5 = cand_10; }
                else if (map_idx == 11) { meta.feature_5 = cand_11; }
                else if (map_idx == 12) { meta.feature_5 = cand_12; }
                else if (map_idx == 13) { meta.feature_5 = cand_13; }
                else if (map_idx == 14) { meta.feature_5 = cand_14; }
                else { meta.feature_5 = 0; }

                feature_map_reg.read(map_idx, 6);
                if (map_idx == 0) { meta.feature_6 = cand_0; }
                else if (map_idx == 1) { meta.feature_6 = cand_1; }
                else if (map_idx == 2) { meta.feature_6 = cand_2; }
                else if (map_idx == 3) { meta.feature_6 = cand_3; }
                else if (map_idx == 4) { meta.feature_6 = cand_4; }
                else if (map_idx == 5) { meta.feature_6 = cand_5; }
                else if (map_idx == 6) { meta.feature_6 = cand_6; }
                else if (map_idx == 7) { meta.feature_6 = cand_7; }
                else if (map_idx == 8) { meta.feature_6 = cand_8; }
                else if (map_idx == 9) { meta.feature_6 = cand_9; }
                else if (map_idx == 10) { meta.feature_6 = cand_10; }
                else if (map_idx == 11) { meta.feature_6 = cand_11; }
                else if (map_idx == 12) { meta.feature_6 = cand_12; }
                else if (map_idx == 13) { meta.feature_6 = cand_13; }
                else if (map_idx == 14) { meta.feature_6 = cand_14; }
                else { meta.feature_6 = 0; }

                feature_map_reg.read(map_idx, 7);
                if (map_idx == 0) { meta.feature_7 = cand_0; }
                else if (map_idx == 1) { meta.feature_7 = cand_1; }
                else if (map_idx == 2) { meta.feature_7 = cand_2; }
                else if (map_idx == 3) { meta.feature_7 = cand_3; }
                else if (map_idx == 4) { meta.feature_7 = cand_4; }
                else if (map_idx == 5) { meta.feature_7 = cand_5; }
                else if (map_idx == 6) { meta.feature_7 = cand_6; }
                else if (map_idx == 7) { meta.feature_7 = cand_7; }
                else if (map_idx == 8) { meta.feature_7 = cand_8; }
                else if (map_idx == 9) { meta.feature_7 = cand_9; }
                else if (map_idx == 10) { meta.feature_7 = cand_10; }
                else if (map_idx == 11) { meta.feature_7 = cand_11; }
                else if (map_idx == 12) { meta.feature_7 = cand_12; }
                else if (map_idx == 13) { meta.feature_7 = cand_13; }
                else if (map_idx == 14) { meta.feature_7 = cand_14; }
                else { meta.feature_7 = 0; }

                feature_map_reg.read(map_idx, 8);
                if (map_idx == 0) { meta.feature_8 = cand_0; }
                else if (map_idx == 1) { meta.feature_8 = cand_1; }
                else if (map_idx == 2) { meta.feature_8 = cand_2; }
                else if (map_idx == 3) { meta.feature_8 = cand_3; }
                else if (map_idx == 4) { meta.feature_8 = cand_4; }
                else if (map_idx == 5) { meta.feature_8 = cand_5; }
                else if (map_idx == 6) { meta.feature_8 = cand_6; }
                else if (map_idx == 7) { meta.feature_8 = cand_7; }
                else if (map_idx == 8) { meta.feature_8 = cand_8; }
                else if (map_idx == 9) { meta.feature_8 = cand_9; }
                else if (map_idx == 10) { meta.feature_8 = cand_10; }
                else if (map_idx == 11) { meta.feature_8 = cand_11; }
                else if (map_idx == 12) { meta.feature_8 = cand_12; }
                else if (map_idx == 13) { meta.feature_8 = cand_13; }
                else if (map_idx == 14) { meta.feature_8 = cand_14; }
                else { meta.feature_8 = 0; }
            }

            feature_mask_reg.read(feature_mask, 0);
            if ((feature_mask & 16w0x0001) == 0) { meta.feature_0 = 0; }
            if ((feature_mask & 16w0x0002) == 0) { meta.feature_1 = 0; }
            if ((feature_mask & 16w0x0004) == 0) { meta.feature_2 = 0; }
            if ((feature_mask & 16w0x0008) == 0) { meta.feature_3 = 0; }
            if ((feature_mask & 16w0x0010) == 0) { meta.feature_4 = 0; }
            if ((feature_mask & 16w0x0020) == 0) { meta.feature_5 = 0; }
            if ((feature_mask & 16w0x0040) == 0) { meta.feature_6 = 0; }
            if ((feature_mask & 16w0x0080) == 0) { meta.feature_7 = 0; }
            if ((feature_mask & 16w0x0100) == 0) { meta.feature_8 = 0; }

            debug_features.write(0, meta.feature_0);
            debug_features.write(1, meta.feature_1);
            debug_features.write(2, meta.feature_2);
            debug_features.write(3, meta.feature_3);
            debug_features.write(4, meta.feature_4);
            debug_features.write(5, meta.feature_5);
            debug_features.write(6, meta.feature_6);
            debug_features.write(7, meta.feature_7);
            debug_features.write(8, meta.feature_8);

            neuron0_bias.apply(); neuron1_bias.apply(); neuron2_bias.apply(); neuron3_bias.apply(); neuron4_bias.apply(); neuron5_bias.apply(); neuron6_bias.apply(); neuron7_bias.apply();
            neuron0_weights.apply(); neuron1_weights.apply(); neuron2_weights.apply(); neuron3_weights.apply(); neuron4_weights.apply(); neuron5_weights.apply(); neuron6_weights.apply(); neuron7_weights.apply();

            if (hdr.features.isValid()) {
                hdr.features.setInvalid();
            }

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
            hdr.nn.h2_acc0 = 0; hdr.nn.h2_acc1 = 0; hdr.nn.h2_acc2 = 0; hdr.nn.h2_acc3 = 0;
            hdr.nn.nn_result = 0;

            hdr.nn.r0 = meta.result_0;
            hdr.nn.r1 = meta.result_1;
            hdr.nn.r2 = meta.result_2;
            hdr.nn.r3 = meta.result_3;
            hdr.nn.r4 = meta.result_4;
            hdr.nn.r5 = meta.result_5;
            hdr.nn.r6 = meta.result_6;
            hdr.nn.r7 = meta.result_7;
            h2_partial_mode_reg.read(h2_partial_mode, 0);
            active_local_h2_count_reg.read(active_h2_count, 0);
            if (active_h2_count > 0) {
                neuron2_0_bias.apply(); neuron2_1_bias.apply(); neuron2_2_bias.apply(); neuron2_3_bias.apply();
                neuron2_0_weights.apply(); neuron2_1_weights.apply(); neuron2_2_weights.apply(); neuron2_3_weights.apply();
            }

            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.features);
        packet.emit(hdr.nn);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
