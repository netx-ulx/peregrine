#include "headers.p4"

#ifndef _DEPARSER_A_
#define _DEPARSER_A_

// ---------------------------------------------------------------------------
// Ingress Deparser for Pipeline A
// ---------------------------------------------------------------------------
control SwitchIngressDeparser_a(packet_out pkt, inout header_t hdr, in ingress_metadata_a_t ig_md, in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.icmp);
        pkt.emit(hdr.peregrine);
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser for Pipeline A
// ---------------------------------------------------------------------------

control SwitchEgressDeparser_a(packet_out pkt, inout header_t hdr, in egress_metadata_a_t eg_md, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.icmp);
        pkt.emit(hdr.peregrine);
    }
}

#endif
