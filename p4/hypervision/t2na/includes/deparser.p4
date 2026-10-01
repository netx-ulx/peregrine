#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"

#ifndef _DEPARSER_
#define _DEPARSER_

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control IngressDeparser(packet_out pkt,
						inout header_t hdr,
						in ig_meta_t ig_md,
						in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.icmp);
		pkt.emit(hdr.hv_0);
		pkt.emit(hdr.hv_1);
		pkt.emit(hdr.hv_2);
		pkt.emit(hdr.hv_3);
		pkt.emit(hdr.hv_bin_len);
		pkt.emit(hdr.meta);
	}
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------

control EgressDeparser(packet_out pkt,
					   inout header_t hdr,
					   in eg_meta_t eg_md,
					   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.icmp);
		pkt.emit(hdr.hv_0);
		pkt.emit(hdr.hv_1);
		pkt.emit(hdr.hv_2);
		pkt.emit(hdr.hv_3);
		pkt.emit(hdr.hv_bin_len);
		pkt.emit(hdr.hv_bin_ts);
	}
}

#endif
