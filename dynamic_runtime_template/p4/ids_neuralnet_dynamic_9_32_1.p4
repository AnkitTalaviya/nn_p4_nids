/* P4_16 */
#include <core.p4>
#include <v1model.p4>

const bit<16> FEATURE_UDP_PORT = 5555;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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

// Optional feature injection header (9x16-bit scaled features)
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

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    features_t features;
}

struct metadata {
    /* The Inputs for the Neural Network */
    bit<16> feature_0;
    bit<16> feature_1;
    bit<16> feature_2;
    bit<16> feature_3;
    bit<16> feature_4;
    bit<16> feature_5;
    bit<16> feature_6;
    bit<16> feature_7;
    bit<16> feature_8;

    /* The Output of the Neural Network */
    int<32> nn_result;

    /* Flow Stats (The Eyes) - Bidirectional */
    bit<32> flow_packet_count;       // Forward direction packet count
    bit<32> flow_byte_count;         // Forward direction byte count
    bit<32> flow_dst_packet_count;   // Reverse direction packet count
    bit<32> flow_dst_byte_count;     // Reverse direction byte count
    bit<48> flow_duration;           // Flow duration (ns)
    
    /* Flow key fields (for proper 5-tuple hashing) */
    bit<16> src_port;
    bit<16> dst_port;
    
    /* Direction detection */
    bit<1> is_forward_direction;     // 1 = forward, 0 = reverse
    bit<8> flow_sttl;                // Stored source TTL (first forward packet)
    bit<8> flow_dttl;                // Stored destination TTL (first reverse packet)
    bit<16> flow_swin;               // Stored source TCP window (first forward TCP)
    bit<16> flow_dwin;               // Stored dest TCP window (first reverse TCP)

    /* HIDDEN LAYER RESULTS (Working Memory for Neurons) */
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
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

/*************************************************************************
*********************** I N G R E S S  **********************************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* --- 1. MEMORY (Registers) --- */
    /* --- 0. LOCAL VARIABLES (Biases) --- */
    // We must define these so the actions can use them
    int<32> bias_0;
    int<32> bias_1;
    int<32> bias_2;
    int<32> bias_3;
    int<32> bias_4;
    int<32> bias_5;
    int<32> bias_6;
    int<32> bias_7;
    int<32> bias_8;
    int<32> bias_9;
    int<32> bias_10;
    int<32> bias_11;
    int<32> bias_12;
    int<32> bias_13;
    int<32> bias_14;
    int<32> bias_15;
    int<32> bias_16;
    int<32> bias_17;
    int<32> bias_18;
    int<32> bias_19;
    int<32> bias_20;
    int<32> bias_21;
    int<32> bias_22;
    int<32> bias_23;
    int<32> bias_24;
    int<32> bias_25;
    int<32> bias_26;
    int<32> bias_27;
    int<32> bias_28;
    int<32> bias_29;
    int<32> bias_30;
    int<32> bias_31;
    int<32> bias_output;

    /* Flow feature scratch variables */
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
    bit<8> map_idx;
    bit<8> active_hidden_count;
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
    bit<16> feature_mask;
    
    // Register to store the Threshold (use bit<32>, convert to signed for comparison)
    register<bit<32>>(1) threshold_reg;
    // Feature mask register (bit i enables feature_i). Default set via CLI.
    register<bit<16>>(1) feature_mask_reg;
    // Feature mapping register (index into candidate feature list)
    register<bit<8>>(9) feature_map_reg;
    register<bit<8>>(1) active_hidden_count_reg;
    register<int<32>>(1) debug_nn_result;  // DEBUG: Capture nn_result values
    register<int<32>>(1) debug_branch;      // DEBUG: 1=drop, 0=forward
    register<int<32>>(1) debug_threshold;   // DEBUG: Capture threshold_val
    register<bit<16>>(9) debug_features;    // DEBUG: Capture final NN input features
    register<int<32>>(32) debug_hidden;     // DEBUG: Capture hidden layer outputs
    
    // Source direction counters
    register<bit<32>>(16384) reg_packet_count;
    register<bit<32>>(16384) reg_byte_count;
    
    // Destination direction counters (for bidirectional flows)
    register<bit<32>>(16384) reg_dst_packet_count;
    register<bit<32>>(16384) reg_dst_byte_count;
    register<bit<8>>(16384) reg_sttl;
    register<bit<8>>(16384) reg_dttl;
    register<bit<16>>(16384) reg_swin;
    register<bit<16>>(16384) reg_dwin;

    // Timestamp register (first packet timestamp per flow)
    register<bit<48>>(16384) reg_first_ts;

    // Reciprocal lookup tables (fixed-point) for division avoidance
    register<bit<32>>(513) recip_pkt_reg;  // for packet counts
    register<bit<32>>(513) recip_dur_reg;  // for duration_scaled

    /* --- 2. ACTIONS FOR BIDIRECTIONAL FLOW TRACKING --- */

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
        
        // Normalized flow key fields
        int<32> norm_ip1;
        int<32> norm_ip2;
        bit<16> norm_port1;
        bit<16> norm_port2;

        // Extract ports based on protocol
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

        // BIDIRECTIONAL NORMALIZATION:
        // Always order the 5-tuple so A<->B and B<->A hash to the same bucket
        // Compare IPs first, then ports if IPs are equal
        if (hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) {
            // Forward direction: src < dst
            meta.is_forward_direction = 1;
            norm_ip1 = hdr.ipv4.srcAddr;
            norm_ip2 = hdr.ipv4.dstAddr;
            norm_port1 = meta.src_port;
            norm_port2 = meta.dst_port;
        } else if (hdr.ipv4.srcAddr > hdr.ipv4.dstAddr) {
            // Reverse direction: src > dst (swap)
            meta.is_forward_direction = 0;
            norm_ip1 = hdr.ipv4.dstAddr;
            norm_ip2 = hdr.ipv4.srcAddr;
            norm_port1 = meta.dst_port;
            norm_port2 = meta.src_port;
        } else {
            // IPs are equal, use port ordering
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

        // Calculate hash using NORMALIZED 5-tuple
        hash(hash_index, HashAlgorithm.crc16, (bit<14>)0, 
             { norm_ip1, norm_ip2, hdr.ipv4.protocol, norm_port1, norm_port2 }, 
             (int<32>)16384);

        // Read current flow state
        reg_packet_count.read(src_pkt_cnt, (bit<32>)hash_index);
        reg_byte_count.read(src_byte_cnt, (bit<32>)hash_index);
        reg_dst_packet_count.read(dst_pkt_cnt, (bit<32>)hash_index);
        reg_dst_byte_count.read(dst_byte_cnt, (bit<32>)hash_index);
        reg_sttl.read(sttl_val, (bit<32>)hash_index);
        reg_dttl.read(dttl_val, (bit<32>)hash_index);
        reg_swin.read(swin_val, (bit<32>)hash_index);
        reg_dwin.read(dwin_val, (bit<32>)hash_index);
        reg_first_ts.read(first_ts, (bit<32>)hash_index);

        // Capture current timestamp
        cur_ts = (bit<48>)standard_metadata.ingress_global_timestamp;

        // Initialize first timestamp on new flow
        if ((src_pkt_cnt == 0) && (dst_pkt_cnt == 0)) {
            first_ts = cur_ts;
            reg_first_ts.write((bit<32>)hash_index, first_ts);
        }

        // Update counters based on packet direction
        if (meta.is_forward_direction == 1) {
            // Forward packet: increment source counters
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
            // Reverse packet: increment destination counters and capture metrics
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

        // Save to metadata for neural network
        meta.flow_packet_count = src_pkt_cnt;
        meta.flow_byte_count = src_byte_cnt;
        meta.flow_dst_packet_count = dst_pkt_cnt;
        meta.flow_dst_byte_count = dst_byte_cnt;
        meta.flow_sttl = sttl_val;
        meta.flow_dttl = dttl_val;
        meta.flow_swin = swin_val;
        meta.flow_dwin = dwin_val;

        // Duration since first packet (ns)
        flow_dur = cur_ts - first_ts;
        meta.flow_duration = flow_dur;
    }

    /* --- 3. NEURAL NETWORK TABLES (Placeholder) --- */
    // Note: You must keep your existing tables (table_hidden_layer_0, etc.)
    // I am putting a placeholder here. You likely have these defined already.
    // If you deleted them, you need to put them back inside this block.

    action set_bias_0(int<32> b) {
        bias_0 = (int<32>)b;
    }

    table neuron0_bias {
        actions = { set_bias_0; }
        default_action = set_bias_0(0);
    }

    action set_bias_1(int<32> b) {
        bias_1 = (int<32>)b;
    }

    table neuron1_bias {
        actions = { set_bias_1; }
        default_action = set_bias_1(0);
    }

    action set_bias_2(int<32> b) {
        bias_2 = (int<32>)b;
    }

    table neuron2_bias {
        actions = { set_bias_2; }
        default_action = set_bias_2(0);
    }

    action set_bias_3(int<32> b) {
        bias_3 = (int<32>)b;
    }

    table neuron3_bias {
        actions = { set_bias_3; }
        default_action = set_bias_3(0);
    }

    action set_bias_4(int<32> b) {
        bias_4 = (int<32>)b;
    }

    table neuron4_bias {
        actions = { set_bias_4; }
        default_action = set_bias_4(0);
    }

    action set_bias_5(int<32> b) {
        bias_5 = (int<32>)b;
    }

    table neuron5_bias {
        actions = { set_bias_5; }
        default_action = set_bias_5(0);
    }

    action set_bias_6(int<32> b) {
        bias_6 = (int<32>)b;
    }

    table neuron6_bias {
        actions = { set_bias_6; }
        default_action = set_bias_6(0);
    }

    action set_bias_7(int<32> b) {
        bias_7 = (int<32>)b;
    }

    table neuron7_bias {
        actions = { set_bias_7; }
        default_action = set_bias_7(0);
    }

    action set_bias_8(int<32> b) {
        bias_8 = (int<32>)b;
    }

    table neuron8_bias {
        actions = { set_bias_8; }
        default_action = set_bias_8(0);
    }

    action set_bias_9(int<32> b) {
        bias_9 = (int<32>)b;
    }

    table neuron9_bias {
        actions = { set_bias_9; }
        default_action = set_bias_9(0);
    }

    action set_bias_10(int<32> b) {
        bias_10 = (int<32>)b;
    }

    table neuron10_bias {
        actions = { set_bias_10; }
        default_action = set_bias_10(0);
    }

    action set_bias_11(int<32> b) {
        bias_11 = (int<32>)b;
    }

    table neuron11_bias {
        actions = { set_bias_11; }
        default_action = set_bias_11(0);
    }

    action set_bias_12(int<32> b) {
        bias_12 = (int<32>)b;
    }

    table neuron12_bias {
        actions = { set_bias_12; }
        default_action = set_bias_12(0);
    }

    action set_bias_13(int<32> b) {
        bias_13 = (int<32>)b;
    }

    table neuron13_bias {
        actions = { set_bias_13; }
        default_action = set_bias_13(0);
    }

    action set_bias_14(int<32> b) {
        bias_14 = (int<32>)b;
    }

    table neuron14_bias {
        actions = { set_bias_14; }
        default_action = set_bias_14(0);
    }

    action set_bias_15(int<32> b) {
        bias_15 = (int<32>)b;
    }

    table neuron15_bias {
        actions = { set_bias_15; }
        default_action = set_bias_15(0);
    }

    action set_bias_16(int<32> b) {
        bias_16 = (int<32>)b;
    }

    table neuron16_bias {
        actions = { set_bias_16; }
        default_action = set_bias_16(0);
    }

    action set_bias_17(int<32> b) {
        bias_17 = (int<32>)b;
    }

    table neuron17_bias {
        actions = { set_bias_17; }
        default_action = set_bias_17(0);
    }

    action set_bias_18(int<32> b) {
        bias_18 = (int<32>)b;
    }

    table neuron18_bias {
        actions = { set_bias_18; }
        default_action = set_bias_18(0);
    }

    action set_bias_19(int<32> b) {
        bias_19 = (int<32>)b;
    }

    table neuron19_bias {
        actions = { set_bias_19; }
        default_action = set_bias_19(0);
    }

    action set_bias_20(int<32> b) {
        bias_20 = (int<32>)b;
    }

    table neuron20_bias {
        actions = { set_bias_20; }
        default_action = set_bias_20(0);
    }

    action set_bias_21(int<32> b) {
        bias_21 = (int<32>)b;
    }

    table neuron21_bias {
        actions = { set_bias_21; }
        default_action = set_bias_21(0);
    }

    action set_bias_22(int<32> b) {
        bias_22 = (int<32>)b;
    }

    table neuron22_bias {
        actions = { set_bias_22; }
        default_action = set_bias_22(0);
    }

    action set_bias_23(int<32> b) {
        bias_23 = (int<32>)b;
    }

    table neuron23_bias {
        actions = { set_bias_23; }
        default_action = set_bias_23(0);
    }

    action set_bias_24(int<32> b) {
        bias_24 = (int<32>)b;
    }

    table neuron24_bias {
        actions = { set_bias_24; }
        default_action = set_bias_24(0);
    }

    action set_bias_25(int<32> b) {
        bias_25 = (int<32>)b;
    }

    table neuron25_bias {
        actions = { set_bias_25; }
        default_action = set_bias_25(0);
    }

    action set_bias_26(int<32> b) {
        bias_26 = (int<32>)b;
    }

    table neuron26_bias {
        actions = { set_bias_26; }
        default_action = set_bias_26(0);
    }

    action set_bias_27(int<32> b) {
        bias_27 = (int<32>)b;
    }

    table neuron27_bias {
        actions = { set_bias_27; }
        default_action = set_bias_27(0);
    }

    action set_bias_28(int<32> b) {
        bias_28 = (int<32>)b;
    }

    table neuron28_bias {
        actions = { set_bias_28; }
        default_action = set_bias_28(0);
    }

    action set_bias_29(int<32> b) {
        bias_29 = (int<32>)b;
    }

    table neuron29_bias {
        actions = { set_bias_29; }
        default_action = set_bias_29(0);
    }

    action set_bias_30(int<32> b) {
        bias_30 = (int<32>)b;
    }

    table neuron30_bias {
        actions = { set_bias_30; }
        default_action = set_bias_30(0);
    }

    action set_bias_31(int<32> b) {
        bias_31 = (int<32>)b;
    }

    table neuron31_bias {
        actions = { set_bias_31; }
        default_action = set_bias_31(0);
    }

    action set_output_bias(int<32> b) {
        bias_output = (int<32>)b;
    }

    table output_bias {
        actions = { set_output_bias; }
        default_action = set_output_bias(0);
    }

    action compute_neuron_0(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_0 * (int<32>)512);

        if (acc > 0) {
            meta.result_0 = (int<32>)acc;
        } else {
            meta.result_0 = 0;
        }
    }

    action compute_neuron_1(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_1 * (int<32>)512);

        if (acc > 0) {
            meta.result_1 = (int<32>)acc;
        } else {
            meta.result_1 = 0;
        }
    }

    action compute_neuron_2(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_2 * (int<32>)512);

        if (acc > 0) {
            meta.result_2 = (int<32>)acc;
        } else {
            meta.result_2 = 0;
        }
    }

    action compute_neuron_3(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_3 * (int<32>)512);

        if (acc > 0) {
            meta.result_3 = (int<32>)acc;
        } else {
            meta.result_3 = 0;
        }
    }

    action compute_neuron_4(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_4 * (int<32>)512);

        if (acc > 0) {
            meta.result_4 = (int<32>)acc;
        } else {
            meta.result_4 = 0;
        }
    }

    action compute_neuron_5(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_5 * (int<32>)512);

        if (acc > 0) {
            meta.result_5 = (int<32>)acc;
        } else {
            meta.result_5 = 0;
        }
    }

    action compute_neuron_6(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_6 * (int<32>)512);

        if (acc > 0) {
            meta.result_6 = (int<32>)acc;
        } else {
            meta.result_6 = 0;
        }
    }

    action compute_neuron_7(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_7 * (int<32>)512);

        if (acc > 0) {
            meta.result_7 = (int<32>)acc;
        } else {
            meta.result_7 = 0;
        }
    }

    action compute_neuron_8(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_8 * (int<32>)512);

        if (acc > 0) {
            meta.result_8 = (int<32>)acc;
        } else {
            meta.result_8 = 0;
        }
    }

    action compute_neuron_9(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_9 * (int<32>)512);

        if (acc > 0) {
            meta.result_9 = (int<32>)acc;
        } else {
            meta.result_9 = 0;
        }
    }

    action compute_neuron_10(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_10 * (int<32>)512);

        if (acc > 0) {
            meta.result_10 = (int<32>)acc;
        } else {
            meta.result_10 = 0;
        }
    }

    action compute_neuron_11(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_11 * (int<32>)512);

        if (acc > 0) {
            meta.result_11 = (int<32>)acc;
        } else {
            meta.result_11 = 0;
        }
    }

    action compute_neuron_12(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_12 * (int<32>)512);

        if (acc > 0) {
            meta.result_12 = (int<32>)acc;
        } else {
            meta.result_12 = 0;
        }
    }

    action compute_neuron_13(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_13 * (int<32>)512);

        if (acc > 0) {
            meta.result_13 = (int<32>)acc;
        } else {
            meta.result_13 = 0;
        }
    }

    action compute_neuron_14(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_14 * (int<32>)512);

        if (acc > 0) {
            meta.result_14 = (int<32>)acc;
        } else {
            meta.result_14 = 0;
        }
    }

    action compute_neuron_15(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_15 * (int<32>)512);

        if (acc > 0) {
            meta.result_15 = (int<32>)acc;
        } else {
            meta.result_15 = 0;
        }
    }

    action compute_neuron_16(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_16 * (int<32>)512);

        if (acc > 0) {
            meta.result_16 = (int<32>)acc;
        } else {
            meta.result_16 = 0;
        }
    }

    action compute_neuron_17(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_17 * (int<32>)512);

        if (acc > 0) {
            meta.result_17 = (int<32>)acc;
        } else {
            meta.result_17 = 0;
        }
    }

    action compute_neuron_18(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_18 * (int<32>)512);

        if (acc > 0) {
            meta.result_18 = (int<32>)acc;
        } else {
            meta.result_18 = 0;
        }
    }

    action compute_neuron_19(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_19 * (int<32>)512);

        if (acc > 0) {
            meta.result_19 = (int<32>)acc;
        } else {
            meta.result_19 = 0;
        }
    }

    action compute_neuron_20(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_20 * (int<32>)512);

        if (acc > 0) {
            meta.result_20 = (int<32>)acc;
        } else {
            meta.result_20 = 0;
        }
    }

    action compute_neuron_21(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_21 * (int<32>)512);

        if (acc > 0) {
            meta.result_21 = (int<32>)acc;
        } else {
            meta.result_21 = 0;
        }
    }

    action compute_neuron_22(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_22 * (int<32>)512);

        if (acc > 0) {
            meta.result_22 = (int<32>)acc;
        } else {
            meta.result_22 = 0;
        }
    }

    action compute_neuron_23(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_23 * (int<32>)512);

        if (acc > 0) {
            meta.result_23 = (int<32>)acc;
        } else {
            meta.result_23 = 0;
        }
    }

    action compute_neuron_24(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_24 * (int<32>)512);

        if (acc > 0) {
            meta.result_24 = (int<32>)acc;
        } else {
            meta.result_24 = 0;
        }
    }

    action compute_neuron_25(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_25 * (int<32>)512);

        if (acc > 0) {
            meta.result_25 = (int<32>)acc;
        } else {
            meta.result_25 = 0;
        }
    }

    action compute_neuron_26(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_26 * (int<32>)512);

        if (acc > 0) {
            meta.result_26 = (int<32>)acc;
        } else {
            meta.result_26 = 0;
        }
    }

    action compute_neuron_27(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_27 * (int<32>)512);

        if (acc > 0) {
            meta.result_27 = (int<32>)acc;
        } else {
            meta.result_27 = 0;
        }
    }

    action compute_neuron_28(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_28 * (int<32>)512);

        if (acc > 0) {
            meta.result_28 = (int<32>)acc;
        } else {
            meta.result_28 = 0;
        }
    }

    action compute_neuron_29(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_29 * (int<32>)512);

        if (acc > 0) {
            meta.result_29 = (int<32>)acc;
        } else {
            meta.result_29 = 0;
        }
    }

    action compute_neuron_30(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_30 * (int<32>)512);

        if (acc > 0) {
            meta.result_30 = (int<32>)acc;
        } else {
            meta.result_30 = 0;
        }
    }

    action compute_neuron_31(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8) {
        int<32> acc = 0;
        int<32> product;

        product = (int<32>)(int<16>)w0 * (int<32>)((int<16>)meta.feature_0);
        acc = acc + product;

        product = (int<32>)(int<16>)w1 * (int<32>)((int<16>)meta.feature_1);
        acc = acc + product;

        product = (int<32>)(int<16>)w2 * (int<32>)((int<16>)meta.feature_2);
        acc = acc + product;

        product = (int<32>)(int<16>)w3 * (int<32>)((int<16>)meta.feature_3);
        acc = acc + product;

        product = (int<32>)(int<16>)w4 * (int<32>)((int<16>)meta.feature_4);
        acc = acc + product;

        product = (int<32>)(int<16>)w5 * (int<32>)((int<16>)meta.feature_5);
        acc = acc + product;

        product = (int<32>)(int<16>)w6 * (int<32>)((int<16>)meta.feature_6);
        acc = acc + product;

        product = (int<32>)(int<16>)w7 * (int<32>)((int<16>)meta.feature_7);
        acc = acc + product;

        product = (int<32>)(int<16>)w8 * (int<32>)((int<16>)meta.feature_8);
        acc = acc + product;

        acc = acc + (bias_31 * (int<32>)512);

        if (acc > 0) {
            meta.result_31 = (int<32>)acc;
        } else {
            meta.result_31 = 0;
        }
    }

    /* --- OUTPUT LAYER CALCULATION --- */
    
    action compute_output(bit<16> w0, bit<16> w1, bit<16> w2, bit<16> w3, bit<16> w4, bit<16> w5, bit<16> w6, bit<16> w7, bit<16> w8, bit<16> w9, bit<16> w10, bit<16> w11, bit<16> w12, bit<16> w13, bit<16> w14, bit<16> w15, bit<16> w16, bit<16> w17, bit<16> w18, bit<16> w19, bit<16> w20, bit<16> w21, bit<16> w22, bit<16> w23, bit<16> w24, bit<16> w25, bit<16> w26, bit<16> w27, bit<16> w28, bit<16> w29, bit<16> w30, bit<16> w31) {
        int<32> acc = 0;

        // Multiply Hidden Layer Results by Output Weights
        acc = acc + ((int<32>)(int<16>)w0 * ((int<32>)meta.result_0 >> 9));
        acc = acc + ((int<32>)(int<16>)w1 * ((int<32>)meta.result_1 >> 9));
        acc = acc + ((int<32>)(int<16>)w2 * ((int<32>)meta.result_2 >> 9));
        acc = acc + ((int<32>)(int<16>)w3 * ((int<32>)meta.result_3 >> 9));
        acc = acc + ((int<32>)(int<16>)w4 * ((int<32>)meta.result_4 >> 9));
        acc = acc + ((int<32>)(int<16>)w5 * ((int<32>)meta.result_5 >> 9));
        acc = acc + ((int<32>)(int<16>)w6 * ((int<32>)meta.result_6 >> 9));
        acc = acc + ((int<32>)(int<16>)w7 * ((int<32>)meta.result_7 >> 9));
        acc = acc + ((int<32>)(int<16>)w8 * ((int<32>)meta.result_8 >> 9));
        acc = acc + ((int<32>)(int<16>)w9 * ((int<32>)meta.result_9 >> 9));
        acc = acc + ((int<32>)(int<16>)w10 * ((int<32>)meta.result_10 >> 9));
        acc = acc + ((int<32>)(int<16>)w11 * ((int<32>)meta.result_11 >> 9));
        acc = acc + ((int<32>)(int<16>)w12 * ((int<32>)meta.result_12 >> 9));
        acc = acc + ((int<32>)(int<16>)w13 * ((int<32>)meta.result_13 >> 9));
        acc = acc + ((int<32>)(int<16>)w14 * ((int<32>)meta.result_14 >> 9));
        acc = acc + ((int<32>)(int<16>)w15 * ((int<32>)meta.result_15 >> 9));
        acc = acc + ((int<32>)(int<16>)w16 * ((int<32>)meta.result_16 >> 9));
        acc = acc + ((int<32>)(int<16>)w17 * ((int<32>)meta.result_17 >> 9));
        acc = acc + ((int<32>)(int<16>)w18 * ((int<32>)meta.result_18 >> 9));
        acc = acc + ((int<32>)(int<16>)w19 * ((int<32>)meta.result_19 >> 9));
        acc = acc + ((int<32>)(int<16>)w20 * ((int<32>)meta.result_20 >> 9));
        acc = acc + ((int<32>)(int<16>)w21 * ((int<32>)meta.result_21 >> 9));
        acc = acc + ((int<32>)(int<16>)w22 * ((int<32>)meta.result_22 >> 9));
        acc = acc + ((int<32>)(int<16>)w23 * ((int<32>)meta.result_23 >> 9));
        acc = acc + ((int<32>)(int<16>)w24 * ((int<32>)meta.result_24 >> 9));
        acc = acc + ((int<32>)(int<16>)w25 * ((int<32>)meta.result_25 >> 9));
        acc = acc + ((int<32>)(int<16>)w26 * ((int<32>)meta.result_26 >> 9));
        acc = acc + ((int<32>)(int<16>)w27 * ((int<32>)meta.result_27 >> 9));
        acc = acc + ((int<32>)(int<16>)w28 * ((int<32>)meta.result_28 >> 9));
        acc = acc + ((int<32>)(int<16>)w29 * ((int<32>)meta.result_29 >> 9));
        acc = acc + ((int<32>)(int<16>)w30 * ((int<32>)meta.result_30 >> 9));
        acc = acc + ((int<32>)(int<16>)w31 * ((int<32>)meta.result_31 >> 9));

        // Add Output Bias
        acc = acc + bias_output;

        // Save Final Result to Metadata (Fixed Variable Name)
        meta.nn_result = (int<32>)acc;
        debug_nn_result.write(0, meta.nn_result);  // DEBUG: Save for inspection

    }
    
    /* --- WEIGHT TABLES --- */
    
    // We need one table for the output weights
    table output_weights {
        actions = {
            compute_output;
            NoAction;
        }
        default_action = NoAction();
    }

    // And tables for all hidden neurons
    table neuron0_weights { actions = { compute_neuron_0; NoAction; } default_action = NoAction(); }
    table neuron1_weights { actions = { compute_neuron_1; NoAction; } default_action = NoAction(); }
    table neuron2_weights { actions = { compute_neuron_2; NoAction; } default_action = NoAction(); }
    table neuron3_weights { actions = { compute_neuron_3; NoAction; } default_action = NoAction(); }
    table neuron4_weights { actions = { compute_neuron_4; NoAction; } default_action = NoAction(); }
    table neuron5_weights { actions = { compute_neuron_5; NoAction; } default_action = NoAction(); }
    table neuron6_weights { actions = { compute_neuron_6; NoAction; } default_action = NoAction(); }
    table neuron7_weights { actions = { compute_neuron_7; NoAction; } default_action = NoAction(); }
    table neuron8_weights { actions = { compute_neuron_8; NoAction; } default_action = NoAction(); }
    table neuron9_weights { actions = { compute_neuron_9; NoAction; } default_action = NoAction(); }
    table neuron10_weights { actions = { compute_neuron_10; NoAction; } default_action = NoAction(); }
    table neuron11_weights { actions = { compute_neuron_11; NoAction; } default_action = NoAction(); }
    table neuron12_weights { actions = { compute_neuron_12; NoAction; } default_action = NoAction(); }
    table neuron13_weights { actions = { compute_neuron_13; NoAction; } default_action = NoAction(); }
    table neuron14_weights { actions = { compute_neuron_14; NoAction; } default_action = NoAction(); }
    table neuron15_weights { actions = { compute_neuron_15; NoAction; } default_action = NoAction(); }
    table neuron16_weights { actions = { compute_neuron_16; NoAction; } default_action = NoAction(); }
    table neuron17_weights { actions = { compute_neuron_17; NoAction; } default_action = NoAction(); }
    table neuron18_weights { actions = { compute_neuron_18; NoAction; } default_action = NoAction(); }
    table neuron19_weights { actions = { compute_neuron_19; NoAction; } default_action = NoAction(); }
    table neuron20_weights { actions = { compute_neuron_20; NoAction; } default_action = NoAction(); }
    table neuron21_weights { actions = { compute_neuron_21; NoAction; } default_action = NoAction(); }
    table neuron22_weights { actions = { compute_neuron_22; NoAction; } default_action = NoAction(); }
    table neuron23_weights { actions = { compute_neuron_23; NoAction; } default_action = NoAction(); }
    table neuron24_weights { actions = { compute_neuron_24; NoAction; } default_action = NoAction(); }
    table neuron25_weights { actions = { compute_neuron_25; NoAction; } default_action = NoAction(); }
    table neuron26_weights { actions = { compute_neuron_26; NoAction; } default_action = NoAction(); }
    table neuron27_weights { actions = { compute_neuron_27; NoAction; } default_action = NoAction(); }
    table neuron28_weights { actions = { compute_neuron_28; NoAction; } default_action = NoAction(); }
    table neuron29_weights { actions = { compute_neuron_29; NoAction; } default_action = NoAction(); }
    table neuron30_weights { actions = { compute_neuron_30; NoAction; } default_action = NoAction(); }
    table neuron31_weights { actions = { compute_neuron_31; NoAction; } default_action = NoAction(); }

    action drop() {
        mark_to_drop(standard_metadata);
        standard_metadata.egress_spec = 511; // Explicit drop port
    }

    /* --- 4. MAIN LOGIC --- */
    apply {
        if (hdr.ipv4.isValid()) {

            if (hdr.features.isValid()) {
                // Feature injection mode: use header-provided scaled features
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
                // STEP A: Run the "Eyes"
                update_flow_stats();

                // STEP B: Map Mixed Packet+Flow Features to "Brain" Inputs (BIDIRECTIONAL)
                // Candidate features (order for mapping):
                // 0: proto, 1: sttl, 2: sbytes, 3: dbytes, 4: spkts, 5: dpkts,
                // 6: totpkts, 7: totbytes, 8: dur, 9: rate, 10: smean, 11: dmean,
                // 12: dttl, 13: swin, 14: dwin

                total_pkts = meta.flow_packet_count + meta.flow_dst_packet_count;
                total_bytes = meta.flow_byte_count + meta.flow_dst_byte_count;

                // cand_0 proto
                proto_scaled = ((bit<32>)hdr.ipv4.protocol) << 4;
                if (proto_scaled > 512) { cand_0 = 512; } else { cand_0 = (bit<16>)proto_scaled; }

                // cand_1 sttl (stored forward TTL)
                sttl_scaled = ((bit<32>)meta.flow_sttl) << 1;
                if (sttl_scaled > 512) { cand_1 = 512; } else { cand_1 = (bit<16>)sttl_scaled; }

                // cand_2 sbytes
                if (meta.flow_byte_count > 24) {
                    tmp_scaled = (meta.flow_byte_count - 24) >> 6;
                    cand_2 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_2 = 0; }

                // cand_3 dbytes
                if (meta.flow_dst_byte_count > 24) {
                    tmp_scaled = (meta.flow_dst_byte_count - 24) >> 6;
                    cand_3 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_3 = 0; }

                // cand_4 spkts
                if (meta.flow_packet_count > 0) {
                    tmp_scaled = (meta.flow_packet_count - 1) << 2;
                    cand_4 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_4 = 0; }

                // cand_5 dpkts
                if (meta.flow_dst_packet_count > 0) {
                    tmp_scaled = (meta.flow_dst_packet_count - 1) << 2;
                    cand_5 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_5 = 0; }

                // cand_6 totpkts
                if (total_pkts > 0) {
                    tmp_scaled = (total_pkts - 1) << 2;
                    cand_6 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_6 = 0; }

                // cand_7 totbytes
                if (total_bytes > 24) {
                    tmp_scaled = (total_bytes - 24) >> 6;
                    cand_7 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;
                } else { cand_7 = 0; }

                // cand_8 dur -> duration_scaled = (ns >> 20)
                duration_scaled = (bit<32>)(meta.flow_duration >> 20);
                cand_8 = (duration_scaled > 512) ? 512 : (bit<16>)duration_scaled;

                // cand_9 rate -> (total_pkts * recip_dur) >> 16
                if (duration_scaled > 0) {
                    denom_idx = duration_scaled;
                    if (denom_idx > 512) { denom_idx = 512; }
                    recip_dur_reg.read(recip_val, (bit<32>)denom_idx);
                    mul_tmp = (bit<64>)total_pkts * (bit<64>)recip_val;
                    rate_scaled = (bit<32>)(mul_tmp >> 16);
                    cand_9 = (rate_scaled > 512) ? 512 : (bit<16>)rate_scaled;
                } else { cand_9 = 0; }

                // cand_10 smean -> mean bytes via reciprocal
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

                // cand_11 dmean -> mean bytes via reciprocal
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

                // cand_12 dttl (stored reverse TTL)
                sttl_scaled = ((bit<32>)meta.flow_dttl) << 1;
                if (sttl_scaled > 512) { cand_12 = 512; } else { cand_12 = (bit<16>)sttl_scaled; }

                // cand_13 swin (stored forward TCP window) -> scale to [0,512] via >> 7
                tmp_scaled = ((bit<32>)meta.flow_swin) >> 7;
                cand_13 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                // cand_14 dwin (stored reverse TCP window) -> scale to [0,512] via >> 7
                tmp_scaled = ((bit<32>)meta.flow_dwin) >> 7;
                cand_14 = (tmp_scaled > 512) ? 512 : (bit<16>)tmp_scaled;

                // Map candidate features -> NN inputs (feature_map_reg)
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

            // Apply feature mask (bit i enables feature_i)
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

            // DEBUG: capture final NN inputs after mask
            debug_features.write(0, meta.feature_0);
            debug_features.write(1, meta.feature_1);
            debug_features.write(2, meta.feature_2);
            debug_features.write(3, meta.feature_3);
            debug_features.write(4, meta.feature_4);
            debug_features.write(5, meta.feature_5);
            debug_features.write(6, meta.feature_6);
            debug_features.write(7, meta.feature_7);
            debug_features.write(8, meta.feature_8);

            // STEP C: Run the "Brain" (Your existing NN logic)
            // 1. Run Bias Tables (Set Baseline)
            neuron0_bias.apply(); neuron1_bias.apply(); neuron2_bias.apply(); neuron3_bias.apply();
            neuron4_bias.apply(); neuron5_bias.apply(); neuron6_bias.apply(); neuron7_bias.apply();
            neuron8_bias.apply(); neuron9_bias.apply(); neuron10_bias.apply(); neuron11_bias.apply();
            neuron12_bias.apply(); neuron13_bias.apply(); neuron14_bias.apply(); neuron15_bias.apply();
            neuron16_bias.apply(); neuron17_bias.apply(); neuron18_bias.apply(); neuron19_bias.apply();
            neuron20_bias.apply(); neuron21_bias.apply(); neuron22_bias.apply(); neuron23_bias.apply();
            neuron24_bias.apply(); neuron25_bias.apply(); neuron26_bias.apply(); neuron27_bias.apply();
            neuron28_bias.apply(); neuron29_bias.apply(); neuron30_bias.apply(); neuron31_bias.apply();
            output_bias.apply();

            // 2. Run Hidden Layer Weights (Calculate Neurons)
            active_hidden_count_reg.read(active_hidden_count, 0);
            if (active_hidden_count > 0) { neuron0_weights.apply(); } else { meta.result_0 = 0; }
            if (active_hidden_count > 1) { neuron1_weights.apply(); } else { meta.result_1 = 0; }
            if (active_hidden_count > 2) { neuron2_weights.apply(); } else { meta.result_2 = 0; }
            if (active_hidden_count > 3) { neuron3_weights.apply(); } else { meta.result_3 = 0; }
            if (active_hidden_count > 4) { neuron4_weights.apply(); } else { meta.result_4 = 0; }
            if (active_hidden_count > 5) { neuron5_weights.apply(); } else { meta.result_5 = 0; }
            if (active_hidden_count > 6) { neuron6_weights.apply(); } else { meta.result_6 = 0; }
            if (active_hidden_count > 7) { neuron7_weights.apply(); } else { meta.result_7 = 0; }
            if (active_hidden_count > 8) { neuron8_weights.apply(); } else { meta.result_8 = 0; }
            if (active_hidden_count > 9) { neuron9_weights.apply(); } else { meta.result_9 = 0; }
            if (active_hidden_count > 10) { neuron10_weights.apply(); } else { meta.result_10 = 0; }
            if (active_hidden_count > 11) { neuron11_weights.apply(); } else { meta.result_11 = 0; }
            if (active_hidden_count > 12) { neuron12_weights.apply(); } else { meta.result_12 = 0; }
            if (active_hidden_count > 13) { neuron13_weights.apply(); } else { meta.result_13 = 0; }
            if (active_hidden_count > 14) { neuron14_weights.apply(); } else { meta.result_14 = 0; }
            if (active_hidden_count > 15) { neuron15_weights.apply(); } else { meta.result_15 = 0; }
            if (active_hidden_count > 16) { neuron16_weights.apply(); } else { meta.result_16 = 0; }
            if (active_hidden_count > 17) { neuron17_weights.apply(); } else { meta.result_17 = 0; }
            if (active_hidden_count > 18) { neuron18_weights.apply(); } else { meta.result_18 = 0; }
            if (active_hidden_count > 19) { neuron19_weights.apply(); } else { meta.result_19 = 0; }
            if (active_hidden_count > 20) { neuron20_weights.apply(); } else { meta.result_20 = 0; }
            if (active_hidden_count > 21) { neuron21_weights.apply(); } else { meta.result_21 = 0; }
            if (active_hidden_count > 22) { neuron22_weights.apply(); } else { meta.result_22 = 0; }
            if (active_hidden_count > 23) { neuron23_weights.apply(); } else { meta.result_23 = 0; }
            if (active_hidden_count > 24) { neuron24_weights.apply(); } else { meta.result_24 = 0; }
            if (active_hidden_count > 25) { neuron25_weights.apply(); } else { meta.result_25 = 0; }
            if (active_hidden_count > 26) { neuron26_weights.apply(); } else { meta.result_26 = 0; }
            if (active_hidden_count > 27) { neuron27_weights.apply(); } else { meta.result_27 = 0; }
            if (active_hidden_count > 28) { neuron28_weights.apply(); } else { meta.result_28 = 0; }
            if (active_hidden_count > 29) { neuron29_weights.apply(); } else { meta.result_29 = 0; }
            if (active_hidden_count > 30) { neuron30_weights.apply(); } else { meta.result_30 = 0; }
            if (active_hidden_count > 31) { neuron31_weights.apply(); } else { meta.result_31 = 0; }

            // DEBUG: capture hidden layer outputs
            debug_hidden.write(0, meta.result_0);
            debug_hidden.write(1, meta.result_1);
            debug_hidden.write(2, meta.result_2);
            debug_hidden.write(3, meta.result_3);
            debug_hidden.write(4, meta.result_4);
            debug_hidden.write(5, meta.result_5);
            debug_hidden.write(6, meta.result_6);
            debug_hidden.write(7, meta.result_7);
            debug_hidden.write(8, meta.result_8);
            debug_hidden.write(9, meta.result_9);
            debug_hidden.write(10, meta.result_10);
            debug_hidden.write(11, meta.result_11);
            debug_hidden.write(12, meta.result_12);
            debug_hidden.write(13, meta.result_13);
            debug_hidden.write(14, meta.result_14);
            debug_hidden.write(15, meta.result_15);
            debug_hidden.write(16, meta.result_16);
            debug_hidden.write(17, meta.result_17);
            debug_hidden.write(18, meta.result_18);
            debug_hidden.write(19, meta.result_19);
            debug_hidden.write(20, meta.result_20);
            debug_hidden.write(21, meta.result_21);
            debug_hidden.write(22, meta.result_22);
            debug_hidden.write(23, meta.result_23);
            debug_hidden.write(24, meta.result_24);
            debug_hidden.write(25, meta.result_25);
            debug_hidden.write(26, meta.result_26);
            debug_hidden.write(27, meta.result_27);
            debug_hidden.write(28, meta.result_28);
            debug_hidden.write(29, meta.result_29);
            debug_hidden.write(30, meta.result_30);
            debug_hidden.write(31, meta.result_31);

            // 3. Run Output Layer (Final Decision)
            output_weights.apply();
            
            // STEP D: Threshold Check
            // 1. Read threshold as bit<32> then convert to signed
            bit<32> threshold_unsigned;
            threshold_reg.read(threshold_unsigned, 0);
            int<32> threshold_val = (int<32>)threshold_unsigned;  // Convert to signed
            debug_threshold.write(0, threshold_val);  // DEBUG
            
            // 3. Compare Signed Integers  
            // Forward normal traffic, drop attacks by setting invalid egress port
            bool is_normal = (int<32>)meta.nn_result <= threshold_val;
            standard_metadata.egress_spec = is_normal ? (bit<9>)1 : (bit<9>)511;
            debug_branch.write(0, is_normal ? (int<32>)0 : (int<32>)1);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // If egress_spec is 511, actually drop the packet
        if (standard_metadata.egress_spec == 511) {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
