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

    int<32> bias_8;
    int<32> bias_9;
    int<32> bias_10;
    int<32> bias_11;
    int<32> bias_12;
    int<32> bias_13;
    int<32> bias_14;
    int<32> bias_15;
    int<32> bias2_4;
    int<32> bias2_5;
    int<32> bias2_6;
    int<32> bias2_7;
    bit<8> active_h2_count;
    bit<8> h2_partial_mode;

    register<bit<8>>(1) active_local_h2_count_reg;
    register<bit<8>>(1) h2_partial_mode_reg;

    action set_bias_8(int<32> b) {
        bias_8 = (int<32>)b;
    }

    table neuron8_bias {
        actions = { set_bias_8; }
        default_action = set_bias_8(0);
    }

    action compute_neuron_8(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_8 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r8 = (int<32>)acc;
        } else {
            hdr.nn.r8 = 0;
        }
    }

    table neuron8_weights {
        actions = { compute_neuron_8; NoAction; }
        default_action = NoAction();
    }


    action set_bias_9(int<32> b) {
        bias_9 = (int<32>)b;
    }

    table neuron9_bias {
        actions = { set_bias_9; }
        default_action = set_bias_9(0);
    }

    action compute_neuron_9(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_9 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r9 = (int<32>)acc;
        } else {
            hdr.nn.r9 = 0;
        }
    }

    table neuron9_weights {
        actions = { compute_neuron_9; NoAction; }
        default_action = NoAction();
    }


    action set_bias_10(int<32> b) {
        bias_10 = (int<32>)b;
    }

    table neuron10_bias {
        actions = { set_bias_10; }
        default_action = set_bias_10(0);
    }

    action compute_neuron_10(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_10 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r10 = (int<32>)acc;
        } else {
            hdr.nn.r10 = 0;
        }
    }

    table neuron10_weights {
        actions = { compute_neuron_10; NoAction; }
        default_action = NoAction();
    }


    action set_bias_11(int<32> b) {
        bias_11 = (int<32>)b;
    }

    table neuron11_bias {
        actions = { set_bias_11; }
        default_action = set_bias_11(0);
    }

    action compute_neuron_11(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_11 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r11 = (int<32>)acc;
        } else {
            hdr.nn.r11 = 0;
        }
    }

    table neuron11_weights {
        actions = { compute_neuron_11; NoAction; }
        default_action = NoAction();
    }


    action set_bias_12(int<32> b) {
        bias_12 = (int<32>)b;
    }

    table neuron12_bias {
        actions = { set_bias_12; }
        default_action = set_bias_12(0);
    }

    action compute_neuron_12(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_12 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r12 = (int<32>)acc;
        } else {
            hdr.nn.r12 = 0;
        }
    }

    table neuron12_weights {
        actions = { compute_neuron_12; NoAction; }
        default_action = NoAction();
    }


    action set_bias_13(int<32> b) {
        bias_13 = (int<32>)b;
    }

    table neuron13_bias {
        actions = { set_bias_13; }
        default_action = set_bias_13(0);
    }

    action compute_neuron_13(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_13 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r13 = (int<32>)acc;
        } else {
            hdr.nn.r13 = 0;
        }
    }

    table neuron13_weights {
        actions = { compute_neuron_13; NoAction; }
        default_action = NoAction();
    }


    action set_bias_14(int<32> b) {
        bias_14 = (int<32>)b;
    }

    table neuron14_bias {
        actions = { set_bias_14; }
        default_action = set_bias_14(0);
    }

    action compute_neuron_14(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_14 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r14 = (int<32>)acc;
        } else {
            hdr.nn.r14 = 0;
        }
    }

    table neuron14_weights {
        actions = { compute_neuron_14; NoAction; }
        default_action = NoAction();
    }


    action set_bias_15(int<32> b) {
        bias_15 = (int<32>)b;
    }

    table neuron15_bias {
        actions = { set_bias_15; }
        default_action = set_bias_15(0);
    }

    action compute_neuron_15(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
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
        acc = acc + (bias_15 * (int<32>)512);

        if (acc > 0) {
            hdr.nn.r15 = (int<32>)acc;
        } else {
            hdr.nn.r15 = 0;
        }
    }

    table neuron15_weights {
        actions = { compute_neuron_15; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_4(int<32> b) {
        bias2_4 = (int<32>)b;
    }

    table neuron2_4_bias {
        actions = { set_bias2_4; }
        default_action = set_bias2_4(0);
    }

    action compute_neuron2_4(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_4 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r4 = acc;
            } else {
                hdr.nn.r4 = 0;
            }
        }
    }

    table neuron2_4_weights {
        actions = { compute_neuron2_4; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_5(int<32> b) {
        bias2_5 = (int<32>)b;
    }

    table neuron2_5_bias {
        actions = { set_bias2_5; }
        default_action = set_bias2_5(0);
    }

    action compute_neuron2_5(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_5 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r5 = acc;
            } else {
                hdr.nn.r5 = 0;
            }
        }
    }

    table neuron2_5_weights {
        actions = { compute_neuron2_5; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_6(int<32> b) {
        bias2_6 = (int<32>)b;
    }

    table neuron2_6_bias {
        actions = { set_bias2_6; }
        default_action = set_bias2_6(0);
    }

    action compute_neuron2_6(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_6 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r6 = acc;
            } else {
                hdr.nn.r6 = 0;
            }
        }
    }

    table neuron2_6_weights {
        actions = { compute_neuron2_6; NoAction; }
        default_action = NoAction();
    }


    action set_bias2_7(int<32> b) {
        bias2_7 = (int<32>)b;
    }

    table neuron2_7_bias {
        actions = { set_bias2_7; }
        default_action = set_bias2_7(0);
    }

    action compute_neuron2_7(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
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
            acc = acc + (bias2_7 * (int<32>)512);
            if (acc > 0) {
                hdr.nn.r7 = acc;
            } else {
                hdr.nn.r7 = 0;
            }
        }
    }

    table neuron2_7_weights {
        actions = { compute_neuron2_7; NoAction; }
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
            neuron8_bias.apply(); neuron9_bias.apply(); neuron10_bias.apply(); neuron11_bias.apply(); neuron12_bias.apply(); neuron13_bias.apply(); neuron14_bias.apply(); neuron15_bias.apply();
            neuron8_weights.apply(); neuron9_weights.apply(); neuron10_weights.apply(); neuron11_weights.apply(); neuron12_weights.apply(); neuron13_weights.apply(); neuron14_weights.apply(); neuron15_weights.apply();
            h2_partial_mode_reg.read(h2_partial_mode, 0);
            active_local_h2_count_reg.read(active_h2_count, 0);
            if (active_h2_count > 0) {
                neuron2_4_bias.apply(); neuron2_5_bias.apply(); neuron2_6_bias.apply(); neuron2_7_bias.apply();
                neuron2_4_weights.apply(); neuron2_5_weights.apply(); neuron2_6_weights.apply(); neuron2_7_weights.apply();
            }
            ipv4_lpm.apply();
        } else if (hdr.ipv4.isValid()) {
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
