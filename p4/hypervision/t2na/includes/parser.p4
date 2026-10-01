#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "constants.p4"

#ifndef _PARSER_
#define _PARSER_

// ---------------------------------------------------------------------------
// Ingress Parser
// ---------------------------------------------------------------------------

parser IngressParser(packet_in pkt,
					 out header_t hdr,
					 out ig_meta_t ig_md,
					 out ingress_intrinsic_metadata_t ig_intr_md) {

	state start {
		pkt.extract(ig_intr_md);
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4 : parse_ipv4;
			default : accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTO_UDP : parse_udp;
			IP_PROTO_TCP : parse_tcp;
			IP_PROTO_ICMP: parse_icmp;
			default : accept;
		}
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		ig_md.l4_src_port = hdr.udp.src_port;
		ig_md.l4_dst_port = hdr.udp.dst_port;
		ig_md.ports = hdr.udp.src_port ++ hdr.udp.dst_port;
		transition accept;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		ig_md.l4_src_port = hdr.tcp.src_port;
		ig_md.l4_dst_port = hdr.tcp.dst_port;
		ig_md.ports = hdr.tcp.src_port ++ hdr.tcp.dst_port;
		transition accept;
	}

	state parse_icmp {
		pkt.extract(hdr.icmp);
		transition accept;
	}
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

parser EgressParser(packet_in pkt,
					out header_t hdr,
					out eg_meta_t eg_md,
					out egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		pkt.extract(eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4 : parse_ipv4;
			default : accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTO_UDP : parse_udp;
			IP_PROTO_TCP : parse_tcp;
			IP_PROTO_ICMP: parse_icmp;
			default : accept;
		}
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		transition parse_hv_0;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition parse_hv_0;
	}

	state parse_icmp {
		pkt.extract(hdr.icmp);
		transition parse_hv_0;
	}

	state parse_hv_0 {
		pkt.extract(hdr.hv_0);
		transition parse_hv_1;
	}

	state parse_hv_1 {
		pkt.extract(hdr.hv_1);
		transition parse_hv_2;
	}

	state parse_hv_2 {
		pkt.extract(hdr.hv_2);
		transition parse_hv_3;
	}

	state parse_hv_3 {
		pkt.extract(hdr.hv_3);
		transition parse_hv_bin_len;
	}

	state parse_hv_bin_len {
		pkt.extract(hdr.hv_bin_len);
		transition parse_meta;
	}

	state parse_meta {
		pkt.extract(hdr.meta);
		transition accept;
	}
}

#endif
