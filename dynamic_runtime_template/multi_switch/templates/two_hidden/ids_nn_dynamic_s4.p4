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
        transition parse_nn;
    }


    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_nn;
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

    int<32> bias_24;
    int<32> bias_25;
    int<32> bias_26;
    int<32> bias_27;
    int<32> bias_28;
    int<32> bias_29;
    int<32> bias_30;
    int<32> bias_31;
    int<32> bias2_12;
    int<32> bias2_13;
    int<32> bias2_14;
    int<32> bias2_15;
    int<32> bias_output;
    bit<8> active_h2_count;
    bit<8> h2_partial_mode;

    register<bit<32>>(1) threshold_reg;
    register<int<32>>(1) debug_nn_result;
    register<int<32>>(1) debug_branch;
    register<int<32>>(1) debug_threshold;
    register<bit<8>>(1) active_local_h2_count_reg;
    register<bit<8>>(1) h2_partial_mode_reg;


    action set_bias_24(int<32> b) {
        bias_24 = (int<32>)b;
    }

    table neuron24_bias {
        actions = { set_bias_24; }
        default_action = set_bias_24(0);
    }

    action compute_neuron_24(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_24 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r24 = (int<32>)acc;
        } else {
            hdr.nn.r24 = 0;
        }
    }

    table neuron24_weights {
        actions = { compute_neuron_24; NoAction; }
        default_action = NoAction();
    }


    action set_bias_25(int<32> b) {
        bias_25 = (int<32>)b;
    }

    table neuron25_bias {
        actions = { set_bias_25; }
        default_action = set_bias_25(0);
    }

    action compute_neuron_25(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_25 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r25 = (int<32>)acc;
        } else {
            hdr.nn.r25 = 0;
        }
    }

    table neuron25_weights {
        actions = { compute_neuron_25; NoAction; }
        default_action = NoAction();
    }


    action set_bias_26(int<32> b) {
        bias_26 = (int<32>)b;
    }

    table neuron26_bias {
        actions = { set_bias_26; }
        default_action = set_bias_26(0);
    }

    action compute_neuron_26(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_26 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r26 = (int<32>)acc;
        } else {
            hdr.nn.r26 = 0;
        }
    }

    table neuron26_weights {
        actions = { compute_neuron_26; NoAction; }
        default_action = NoAction();
    }


    action set_bias_27(int<32> b) {
        bias_27 = (int<32>)b;
    }

    table neuron27_bias {
        actions = { set_bias_27; }
        default_action = set_bias_27(0);
    }

    action compute_neuron_27(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_27 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r27 = (int<32>)acc;
        } else {
            hdr.nn.r27 = 0;
        }
    }

    table neuron27_weights {
        actions = { compute_neuron_27; NoAction; }
        default_action = NoAction();
    }


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


    action set_bias2_12(int<32> b) {
        bias2_12 = (int<32>)b;
    }

    table neuron2_12_bias {
        actions = { set_bias2_12; }
        default_action = set_bias2_12(0);
    }

    action compute_neuron2_12(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_12 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r12 = acc;
            } else {
                hdr.nn.r12 = 0;
            }
        }
    }

    table neuron2_12_weights {
        actions = { compute_neuron2_12; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_13(int<32> b) {
        bias2_13 = (int<32>)b;
    }

    table neuron2_13_bias {
        actions = { set_bias2_13; }
        default_action = set_bias2_13(0);
    }

    action compute_neuron2_13(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_13 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r13 = acc;
            } else {
                hdr.nn.r13 = 0;
            }
        }
    }

    table neuron2_13_weights {
        actions = { compute_neuron2_13; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_14(int<32> b) {
        bias2_14 = (int<32>)b;
    }

    table neuron2_14_bias {
        actions = { set_bias2_14; }
        default_action = set_bias2_14(0);
    }

    action compute_neuron2_14(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_14 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r14 = acc;
            } else {
                hdr.nn.r14 = 0;
            }
        }
    }

    table neuron2_14_weights {
        actions = { compute_neuron2_14; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_15(int<32> b) {
        bias2_15 = (int<32>)b;
    }

    table neuron2_15_bias {
        actions = { set_bias2_15; }
        default_action = set_bias2_15(0);
    }

    action compute_neuron2_15(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_15 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r15 = acc;
            } else {
                hdr.nn.r15 = 0;
            }
        }
    }

    table neuron2_15_weights {
        actions = { compute_neuron2_15; NoAction; }
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
                          bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15) {
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
            neuron24_bias.apply(); neuron25_bias.apply(); neuron26_bias.apply(); neuron27_bias.apply(); neuron28_bias.apply(); neuron29_bias.apply(); neuron30_bias.apply(); neuron31_bias.apply();
            neuron24_weights.apply(); neuron25_weights.apply(); neuron26_weights.apply(); neuron27_weights.apply(); neuron28_weights.apply(); neuron29_weights.apply(); neuron30_weights.apply(); neuron31_weights.apply();
            h2_partial_mode_reg.read(h2_partial_mode, 0);
            active_local_h2_count_reg.read(active_h2_count, 0);
            if (active_h2_count > 0) {
                neuron2_12_bias.apply(); neuron2_13_bias.apply(); neuron2_14_bias.apply(); neuron2_15_bias.apply();
                neuron2_12_weights.apply(); neuron2_13_weights.apply(); neuron2_14_weights.apply(); neuron2_15_weights.apply();
                if (h2_partial_mode == 1) {
                    hdr.nn.r12 = hdr.nn.h2_acc0 + (bias2_12 * (int<32>)512);
                    if (hdr.nn.r12 <= 0) { hdr.nn.r12 = 0; }
                    hdr.nn.r13 = hdr.nn.h2_acc1 + (bias2_13 * (int<32>)512);
                    if (hdr.nn.r13 <= 0) { hdr.nn.r13 = 0; }
                    hdr.nn.r14 = hdr.nn.h2_acc2 + (bias2_14 * (int<32>)512);
                    if (hdr.nn.r14 <= 0) { hdr.nn.r14 = 0; }
                    hdr.nn.r15 = hdr.nn.h2_acc3 + (bias2_15 * (int<32>)512);
                    if (hdr.nn.r15 <= 0) { hdr.nn.r15 = 0; }
                }
            }
            output_bias.apply();
            output_weights.apply();

            bit<32> threshold_unsigned;
            threshold_reg.read(threshold_unsigned, 0);
            int<32> threshold_val = (int<32>)threshold_unsigned;
            debug_threshold.write(0, threshold_val);

            bool is_normal = (int<32>)hdr.nn.nn_result <= threshold_val;
            debug_branch.write(0, is_normal ? (int<32>)0 : (int<32>)1);

            if (is_normal) {
                hdr.nn.setInvalid();
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
