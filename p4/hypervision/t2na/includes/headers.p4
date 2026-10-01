#ifndef _HEADERS_
#define _HEADERS_

header ethernet_t {
	bit<48> dst_addr;
	bit<48> src_addr;
	bit<16> ether_type;
}

header ipv4_t {
	bit<4>	version;
	bit<4>	ihl;
	bit<8>	diffserv;
	bit<16> len;
	bit<16> identification;
	bit<3>	flags;
	bit<13> frag_offset;
	bit<8>	ttl;
	bit<8>	protocol;
	bit<16> hdr_checksum;
	bit<32> src_addr;
	bit<32> dst_addr;
}

header tcp_t {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32>	ack_no;
	bit<4>	data_offset;
	bit<4>	res;
	bit<1>	cwr;
	bit<1>	ece;
	bit<1>	urg;
	bit<1>	ack;
	bit<1>	psh;
	bit<1>	rst;
	bit<1>	syn;
	bit<1>	fin;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

header udp_t {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> length_;
	bit<16> checksum;
}

header icmp_t {
	bit<8> type;
	bit<8> code;
	bit<16> hdrChecksum;
}

// 424 bits / 53 bytes
header hv_t {
	bit<32> ts_start;
	bit<32> ts_end;
	bit<32> ts_agg;
	bit<32> ip_src;
	bit<32> ip_dst;
	bit<32> proto;
	bit<32> ports;
	bit<32> syn;
	bit<32> ack;
	bit<32> fin;
	bit<32> rst;
	bit<32> cnt;
	bit<32> len;
	bit<8>	long;
}

// 1280 bits / 160 bytes
header hv_bin_t {
	bit<32> a_0_0;
	bit<32> b_0_0;
	bit<32> a_0_1;
	bit<32> b_0_1;
	bit<32> a_0_2;
	bit<32> b_0_2;
	bit<32> a_0_3;
	bit<32> b_0_3;
	bit<32> a_1_0;
	bit<32> b_1_0;
	bit<32> a_1_1;
	bit<32> b_1_1;
	bit<32> a_1_2;
	bit<32> b_1_2;
	bit<32> a_1_3;
	bit<32> b_1_3;
	bit<32> a_2_0;
	bit<32> b_2_0;
	bit<32> a_2_1;
	bit<32> b_2_1;
	bit<32> a_2_2;
	bit<32> b_2_2;
	bit<32> a_2_3;
	bit<32> b_2_3;
	bit<32> a_3_0;
	bit<32> b_3_0;
	bit<32> a_3_1;
	bit<32> b_3_1;
	bit<32> a_3_2;
	bit<32> b_3_2;
	bit<32> a_3_3;
	bit<32> b_3_3;
	bit<32> a_4_0;
	bit<32> b_4_0;
	bit<32> a_4_1;
	bit<32> b_4_1;
	bit<32> a_4_2;
	bit<32> b_4_2;
	bit<32> a_4_3;
	bit<32> b_4_3;
}

header meta_t {
	bit<16> hash_flow;
	bit<16> index_cntr;
	bit<32> cur_ts;
	bit<32> flow_end_old;
}

struct ig_meta_t {
	bit<16> l4_src_port;
	bit<16> l4_dst_port;
	bit<8>	custom_hdr_toggle;
	bit<32> ports;
	bit<32> ts_agg_tmp;
	bit<8>	flag_toggle;
}

struct eg_meta_t {
	bit<32> cur_ts_interval;
}

struct flow_ts {
	bit<32> start;
	bit<32> end;
}

struct flow_ip {
	bit<32> src;
	bit<32> dst;
}

struct flow_port {
	bit<32> proto;
	bit<32> ports;
}

struct flow_flags {
	bit<32> flag_a;
	bit<32> flag_b;
}

struct flow_data {
	bit<32> cnt;
	bit<32> len;
}

struct bin_len {
	bit<32> bin_a;
	bit<32> bin_b;
}

struct bin_ts {
	bit<32> bin_a;
	bit<32> bin_b;
}

struct header_t {
	ethernet_t		ethernet;
	ipv4_t			ipv4;
	tcp_t			tcp;
	udp_t			udp;
	icmp_t			icmp;
	hv_t			hv_0;
	hv_t			hv_1;
	hv_t			hv_2;
	hv_t			hv_3;
	hv_bin_t		hv_bin_len;
	hv_bin_t		hv_bin_ts;
	meta_t			meta;
}

#endif
