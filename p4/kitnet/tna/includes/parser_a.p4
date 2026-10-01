#include <tna.p4>
#include "headers.p4"
#include "constants.p4"

#ifndef _PARSER_A_
#define _PARSER_A_

// ---------------------------------------------------------------------------
// Ingress Parser for Pipeline A
// ---------------------------------------------------------------------------

parser SwitchIngressParser_a(packet_in pkt, out header_t hdr, out ingress_metadata_a_t ig_md, out ingress_intrinsic_metadata_t ig_intr_md) {

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
        // Constant value used as a key in the sampling rate table.
        // Defined here due to stage limitations.
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP : parse_udp;
            IP_PROTO_TCP : parse_tcp;
            IP_PROTO_ICMP: parse_icmp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        ig_md.meta.l4_src_port = hdr.udp.src_port;
        ig_md.meta.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        ig_md.meta.l4_src_port = hdr.tcp.src_port;
        ig_md.meta.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Parser for Pipeline A
// ---------------------------------------------------------------------------

parser SwitchEgressParser_a(packet_in pkt, out header_t hdr, out egress_metadata_a_t eg_md, out egress_intrinsic_metadata_t eg_intr_md) {

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
            IP_PROTO_ICMP : parse_icmp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_peregrine;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition parse_peregrine;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition parse_peregrine;
    }

    state parse_peregrine {
        pkt.extract(hdr.peregrine);
        transition accept;
    }
}

#endif
