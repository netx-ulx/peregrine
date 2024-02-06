#include <core.p4>
#include <tna.p4>
#include "includes/headers.p4"
#include "includes/constants.p4"
#include "includes/parser_b.p4"
#include "includes/deparser_b.p4"
#include "includes/stats/stats_mac_ip_src_b.p4"
#include "includes/stats/stats_ip_src_b.p4"
#include "includes/stats/stats_ip_b.p4"
#include "includes/stats/stats_five_t_b.p4"

// ---------------------------------------------------------------------------
// Pipeline B
// ---------------------------------------------------------------------------

control SwitchIngress_b(
        inout header_t hdr,
        inout ingress_metadata_b_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Control block instantiations.

    c_stats_mac_ip_src_b()      stats_mac_ip_src_b;
    c_stats_ip_src_b()          stats_ip_src_b;
    c_stats_ip_b()              stats_ip_b;
    c_stats_five_t_b()          stats_five_t_b;

    action modify_eg_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.copy_to_cpu = 1;
    }

    table fwd_recirculation {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            NoAction;
            modify_eg_port;
        }

        const default_action = NoAction;
        size = 24;
    }

    action set_peregrine_ip_b() {
        hdr.peregrine.ip_magnitude = ig_md.stats_ip.magnitude;
        hdr.peregrine.ip_radius = ig_md.stats_ip.radius;
    }

    action set_peregrine_ip_b_64() {
        hdr.peregrine.ip_sum_res_prod_cov = ig_md.stats_ip.cov;
        hdr.peregrine.ip_pcc = ig_md.stats_ip.pcc;
    }

    action set_peregrine_five_t_b() {
        hdr.peregrine.five_t_magnitude = ig_md.stats_five_t.magnitude;
        hdr.peregrine.five_t_radius = ig_md.stats_five_t.radius;
    }

    action set_peregrine_five_t_b_64() {
        hdr.peregrine.five_t_sum_res_prod_cov = ig_md.stats_five_t.cov;
        hdr.peregrine.five_t_pcc = ig_md.stats_five_t.pcc;
    }

    apply {

        // Calculate stats.
        stats_mac_ip_src_b.apply(hdr, ig_md);
        stats_ip_src_b.apply(hdr, ig_md);
        stats_ip_b.apply(hdr, ig_md);
        stats_five_t_b.apply(hdr, ig_md);

        fwd_recirculation.apply();
        set_peregrine_ip_b();
        set_peregrine_ip_b_64();
        set_peregrine_five_t_b();
        set_peregrine_five_t_b_64();
    }
}

control SwitchEgress_b(
    inout header_t hdr,
    inout egress_metadata_b_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    apply {}

}
