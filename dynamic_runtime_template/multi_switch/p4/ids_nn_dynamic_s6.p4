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
    int<32> nn_result;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
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
        transition select(standard_metadata.ingress_port) {
            0: parse_nn;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(standard_metadata.ingress_port) {
            0: parse_nn;
            default: accept;
        }
    }

    state parse_nn {
        packet.extract(hdr.nn);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    int<32> bias_28;
    int<32> bias_29;
    int<32> bias_30;
    int<32> bias_31;
    int<32> bias_output;
    bit<8> active_local_neuron_count;

    register<bit<32>>(1) threshold_reg;
    register<int<32>>(1) debug_nn_result;
    register<int<32>>(1) debug_branch;
    register<int<32>>(1) debug_threshold;
    register<bit<8>>(1) active_local_neuron_count_reg;


    action set_bias_28(int<32> b) {
        bias_28 = (int<32>)b;
    }

    table neuron28_bias {
        actions = { set_bias_28; }
        default_action = set_bias_28(0);
    }

    action compute_neuron_28(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)hdr.nn.f0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)hdr.nn.f1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)hdr.nn.f2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)hdr.nn.f3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)hdr.nn.f4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)hdr.nn.f5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)hdr.nn.f6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)hdr.nn.f7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)hdr.nn.f8));
        acc = acc + (bias_28 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r28 = (int<32>)acc;
        } else {
            hdr.nn.r28 = 0;
        }
    }

    table neuron28_weights {
        actions = { compute_neuron_28; NoAction; }
        default_action = NoAction();
    }


    action set_bias_29(int<32> b) {
        bias_29 = (int<32>)b;
    }

    table neuron29_bias {
        actions = { set_bias_29; }
        default_action = set_bias_29(0);
    }

    action compute_neuron_29(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)hdr.nn.f0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)hdr.nn.f1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)hdr.nn.f2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)hdr.nn.f3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)hdr.nn.f4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)hdr.nn.f5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)hdr.nn.f6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)hdr.nn.f7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)hdr.nn.f8));
        acc = acc + (bias_29 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r29 = (int<32>)acc;
        } else {
            hdr.nn.r29 = 0;
        }
    }

    table neuron29_weights {
        actions = { compute_neuron_29; NoAction; }
        default_action = NoAction();
    }


    action set_bias_30(int<32> b) {
        bias_30 = (int<32>)b;
    }

    table neuron30_bias {
        actions = { set_bias_30; }
        default_action = set_bias_30(0);
    }

    action compute_neuron_30(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)hdr.nn.f0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)hdr.nn.f1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)hdr.nn.f2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)hdr.nn.f3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)hdr.nn.f4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)hdr.nn.f5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)hdr.nn.f6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)hdr.nn.f7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)hdr.nn.f8));
        acc = acc + (bias_30 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r30 = (int<32>)acc;
        } else {
            hdr.nn.r30 = 0;
        }
    }

    table neuron30_weights {
        actions = { compute_neuron_30; NoAction; }
        default_action = NoAction();
    }


    action set_bias_31(int<32> b) {
        bias_31 = (int<32>)b;
    }

    table neuron31_bias {
        actions = { set_bias_31; }
        default_action = set_bias_31(0);
    }

    action compute_neuron_31(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        acc = acc + ((int<32>)(int<16>)w0 * (int<32>)((int<16>)hdr.nn.f0));
        acc = acc + ((int<32>)(int<16>)w1 * (int<32>)((int<16>)hdr.nn.f1));
        acc = acc + ((int<32>)(int<16>)w2 * (int<32>)((int<16>)hdr.nn.f2));
        acc = acc + ((int<32>)(int<16>)w3 * (int<32>)((int<16>)hdr.nn.f3));
        acc = acc + ((int<32>)(int<16>)w4 * (int<32>)((int<16>)hdr.nn.f4));
        acc = acc + ((int<32>)(int<16>)w5 * (int<32>)((int<16>)hdr.nn.f5));
        acc = acc + ((int<32>)(int<16>)w6 * (int<32>)((int<16>)hdr.nn.f6));
        acc = acc + ((int<32>)(int<16>)w7 * (int<32>)((int<16>)hdr.nn.f7));
        acc = acc + ((int<32>)(int<16>)w8 * (int<32>)((int<16>)hdr.nn.f8));
        acc = acc + (bias_31 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r31 = (int<32>)acc;
        } else {
            hdr.nn.r31 = 0;
        }
    }

    table neuron31_weights {
        actions = { compute_neuron_31; NoAction; }
        default_action = NoAction();
    }


    action set_output_bias(int<32> b) {
        bias_output = (int<32>)b;
    }

    table output_bias {
        actions = { set_output_bias; }
        default_action = set_output_bias(0);
    }

    action compute_output(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7,
                          bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15,
                          bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23,
                          bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
    }

    table output_weights {
        actions = { compute_output; NoAction; }
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
        if (hdr.ipv4.isValid() && hdr.nn.isValid() && hdr.nn.magic == NN_MAGIC) {
            neuron28_bias.apply(); neuron29_bias.apply(); neuron30_bias.apply(); neuron31_bias.apply();
            output_bias.apply();
            active_local_neuron_count_reg.read(active_local_neuron_count, 0);
            if (active_local_neuron_count > 0) { neuron28_weights.apply(); } else { hdr.nn.r28 = 0; }
            if (active_local_neuron_count > 1) { neuron29_weights.apply(); } else { hdr.nn.r29 = 0; }
            if (active_local_neuron_count > 2) { neuron30_weights.apply(); } else { hdr.nn.r30 = 0; }
            if (active_local_neuron_count > 3) { neuron31_weights.apply(); } else { hdr.nn.r31 = 0; }
            output_weights.apply();

            bit<32> threshold_unsigned;
            threshold_reg.read(threshold_unsigned, 0);
            int<32> threshold_val = (int<32>)threshold_unsigned;
            debug_threshold.write(0, threshold_val);

            bool is_normal = (int<32>)hdr.nn.nn_result <= threshold_val;
            debug_branch.write(0, is_normal ? (int<32>)0 : (int<32>)1);

            if (is_normal) {
                if ((bit<32>)hdr.ipv4.dstAddr == 32w0x0a000002) {
                    // Left-to-right: remove transit NN state before host delivery.
                    hdr.nn.setInvalid();
                } else {
                    // Right-to-left: keep NN state so S1 can confirm classification and strip it there.
                    hdr.ipv4.diffserv = 8w0xfd;
                    hdr.nn.flags = 16w0x0001;
                }
            } else {
                mark_to_drop(standard_metadata);
                standard_metadata.egress_spec = 511;
            }
        }

        if (hdr.ipv4.isValid() && standard_metadata.egress_spec != 511) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_spec == 511) {
            mark_to_drop(standard_metadata);
        }
    }
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
