#include <core.p4>

#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/stats/stats_mac_ip_src.p4"
#include "includes/stats/stats_ip_src.p4"
#include "includes/stats/stats_ip.p4"
#include "includes/stats/stats_five_t.p4"
#include "includes/math/sqr.p4"

// ---------------------------------------------------------------------------
// Pipeline - Ingress
// ---------------------------------------------------------------------------

control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) in_counter;

    c_stats_mac_ip_src()    stats_mac_ip_src;
    c_stats_ip()            stats_ip;

    c_sqr()                 pkt_len_sqr;

    Register<bit<16>, bit<1>>(1) reg_decay_cntr;    // Current decay counter value.
    // Register<bit<32>, bit<1>>(1) reg_pkt_len_sqr;   // Squared packet length.

    RegisterAction<_, bit<1>, bit<16>>(reg_decay_cntr) ract_decay_cntr_check = {
        void apply(inout bit<16> val, out bit<16> res) {
            if (val < 24576) {
                val = val + 8192;
            } else {
                val = 0;
            }
            res = val;
        }
    };

    /*
    MathUnit<bit<32>>(MathOp_t.SQR, 1) sqr_pkt_len;
    RegisterAction<_, bit<1>, bit<32>>(reg_pkt_len_sqr) ract_pkt_len_sqr_calc = {
        void apply(inout bit<32> val, out bit<32> res) {
            val = sqr_pkt_len.execute((bit<32>)hdr.ipv4.len);
            res = val;
        }
    };
    */

    action decay_cntr_check() {
        hdr.meta.decay_cntr = ract_decay_cntr_check.execute(0);
    }

    // Timestamp bit-slicing from 48 bits to 32 bits.
    // Necessary to allow usage in reg. actions, which only support max 32 bits.
    action ts_conversion() {
        hdr.meta.curr_ts = ig_intr_md.ingress_mac_tstamp[47:16];
    }

    /*
    action pkt_len_sqr_calc() {
        hdr.meta.pkt_len_sqr = ract_pkt_len_sqr_calc.execute(0);
    }
    */

    action set_out_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        // in_counter.count();
    }

    action miss() {}

    action set_custom_hdrs() {
        hdr.meta.setValid();
        hdr.peregrine.setValid();
        hdr.peregrine.decay = hdr.meta.decay_cntr;
        hdr.peregrine.mac_ip_src_hash = ig_md.stats_mac_ip_src.hash_0;
        hdr.peregrine.ip_hash = ig_md.stats_ip.hash_0;
    }

	table fwd {
		key = {
			ig_intr_md.ingress_port : exact;
            // hdr.peregrine.ml_exec : exact;
		}
		actions = {
            set_out_port;
            miss;
        }
        // counters = in_counter;
        const default_action = miss;
        size = 1;
        const entries = {
            (0) : set_out_port(OUT_PORT);
        }
	}

    apply {
        if (hdr.ipv4.isValid()) {
            if (!hdr.peregrine.isValid()) {
                decay_cntr_check();

                // Timestamp bit-slicing.
                ts_conversion();

                // Squared packet len calculation (math_unit).
                // pkt_len_sqr_calc();

                // Squared packet len calculation (sharma).
                pkt_len_sqr.apply((bit<32>)hdr.ipv4.len, hdr.meta.pkt_len_sqr);

                // Calculate stats.
                stats_mac_ip_src.apply(hdr, ig_md);
                stats_ip.apply(hdr, ig_md);

                set_custom_hdrs();
            }
            fwd.apply();
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline - Egress
// ---------------------------------------------------------------------------

control SwitchEgress(
    inout header_t hdr,
    inout egress_metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    c_stats_ip_src() stats_ip_src;
    c_stats_five_t() stats_five_t;

    action trunc_pkt() {
        // Truncate packet (ethernet + ipv4 + peregrine).
        // eg_dprsr_md.mtu_trunc_len = 146;
        hdr.peregrine.ip_src_hash = eg_md.stats_ip_src.hash_0;
        hdr.peregrine.five_t_hash = eg_md.stats_five_t.hash_0;
        hdr.peregrine.setValid();
    }

	apply {
        // Calculate stats.
        stats_ip_src.apply(hdr, eg_md);
        stats_five_t.apply(hdr, eg_md);

        // Truncate packet, set custom_headers.
        trunc_pkt();
    }
}

// ---------------------------------------------------------------------------
// Instantiation
// ---------------------------------------------------------------------------

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
