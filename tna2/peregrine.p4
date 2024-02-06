#include <core.p4>
#include <t2na.p4>

#include "includes/parser.p4"
#include "includes/deparser.p4"
#include "includes/stats/stats_mac_ip_src.p4"
#include "includes/stats/stats_ip_src.p4"
#include "includes/stats/stats_ip.p4"
#include "includes/stats/stats_five_t.p4"

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

    // Control block instantiations.

    c_stats_mac_ip_src()    stats_mac_ip_src;
    c_stats_ip_src()        stats_ip_src;
    c_stats_ip()            stats_ip;
    c_stats_five_t()        stats_five_t;

    Register<decay_cntr, _>(1)  reg_decay_cntr;         // Current decay counter value.
    Register<bit<32>, _>(1)     reg_pkt_cnt_global;     // Global packet counter.
    Register<bit<32>, _>(1)     reg_pkt_len_squared;    // Squared packet length.

    RegisterAction<decay_cntr, _, bit<16>>(reg_decay_cntr) ract_decay_cntr_check = {
        void apply(inout decay_cntr decay, out bit<16> result) {
            if (decay.cur_pkt < SAMPLING) {
                if (decay.value < 24576) {
                    decay.value = decay.value + 8192;
                } else {
                    decay.value = 0;
                }
                decay.cur_pkt = decay.cur_pkt + 1;
            } else {
                decay.cur_pkt = 1;
            }
            result = decay.value;
        }
    };

    RegisterAction<_, _, bit<32>>(reg_pkt_cnt_global) ract_pkt_cnt_global = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = value + 1;
            result = value;
        }
    };

    MathUnit<bit<32>>(MathOp_t.SQR, 1) square_pkt_len;
    RegisterAction<_, _, bit<32>>(reg_pkt_len_squared) ract_pkt_len_squared_calc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = square_pkt_len.execute((bit<32>)hdr.ipv4.len);
            result = value;
        }
    };

    action decay_cntr_check() {
        ig_md.meta.decay_cntr = ract_decay_cntr_check.execute(0);
    }

    // Timestamp bit-slicing from 48 bits to 32 bits.
    // Necessary to allow usage in reg. actions, which only support max 32 bits.
    action ts_conversion() {
        ig_md.meta.current_ts = ig_intr_md.ingress_mac_tstamp[47:16];
    }

    action pkt_cnt_global_calc() {
        ig_md.meta.pkt_cnt_global = ract_pkt_cnt_global.execute(0);
    }

    action pkt_len_squared_calc() {
        ig_md.meta.pkt_len_squared = ract_pkt_len_squared_calc.execute(0);
    }

    action set_out_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.peregrine.decay = ig_md.meta.decay_cntr;
        hdr.peregrine.pkt_cnt_global = ig_md.meta.pkt_cnt_global;
    }

    action set_peregrine_mac_ip_src() {
        hdr.peregrine.setValid();
        hdr.peregrine.mac_ip_src_pkt_cnt = ig_md.stats_mac_ip_src.pkt_cnt;
        /* hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.mean; */
        /* hdr.peregrine.mac_ip_src_std_dev = ig_md.stats_mac_ip_src.std_dev; */
        hdr.peregrine.ip_src_pkt_cnt = ig_md.stats_ip_src.pkt_cnt;
        /* hdr.peregrine.ip_src_mean = ig_md.stats_ip_src.mean; */
        /* hdr.peregrine.ip_src_std_dev = ig_md.stats_ip_src.std_dev; */
    }

    action set_peregrine_ip() {
        hdr.peregrine.ip_pkt_cnt = ig_md.stats_ip.pkt_cnt_0;
        hdr.peregrine.ip_mean = ig_md.stats_ip.mean_0;
        hdr.peregrine.ip_std_dev = ig_md.stats_ip.std_dev_0;
        hdr.peregrine.ip_magnitude = ig_md.stats_ip.magnitude;
        hdr.peregrine.ip_radius = ig_md.stats_ip.radius;
        /* hdr.peregrine.ip_cov = ig_md.stats_ip.cov; */
        /* hdr.peregrine.ip_pcc = ig_md.stats_ip.pcc; */
    }

    action set_peregrine_five_t() {
        hdr.peregrine.five_t_pkt_cnt = ig_md.stats_five_t.pkt_cnt_0;
        hdr.peregrine.five_t_mean = ig_md.stats_five_t.mean_0;
        hdr.peregrine.five_t_std_dev = ig_md.stats_five_t.std_dev_0;
        hdr.peregrine.five_t_magnitude = ig_md.stats_five_t.magnitude;
        hdr.peregrine.five_t_radius = ig_md.stats_five_t.radius;
        /* hdr.peregrine.five_t_cov = ig_md.stats_five_t.cov; */
        /* hdr.peregrine.five_t_pcc = ig_md.stats_five_t.pcc; */
    }

    action miss() {}

	table fwd {
		key = {
			ig_intr_md.ingress_port : exact;
		}
		actions = {
            set_out_port;
            miss;
        }
        const default_action = miss;
        size = 2;
	}

    apply {
        if (hdr.ipv4.isValid()) {

            // Global packet count calculation.
            pkt_cnt_global_calc();

            decay_cntr_check();

            // Timestamp bit-slicing.
            ts_conversion();

            // Squared packet len calculation.
            pkt_len_squared_calc();

            // Calculate stats.
            stats_mac_ip_src.apply(hdr, ig_md);
            stats_ip_src.apply(hdr, ig_md);
            stats_ip.apply(hdr, ig_md);
            stats_five_t.apply(hdr, ig_md);

            if (ig_md.meta.pkt_cnt_global % SAMPLING == 0) {
                set_peregrine_mac_ip_src();
                set_peregrine_ip();
                set_peregrine_five_t();
                fwd.apply();
            }
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
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

	apply {}
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
