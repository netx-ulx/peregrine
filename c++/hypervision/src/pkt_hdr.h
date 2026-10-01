#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include <string>

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define MAX_PACKET_SIZE 10000

namespace hypervision {

typedef uint8_t mac_t[6];
typedef uint32_t ipv4_t;
typedef uint16_t port_t;

struct eth_hdr_t {
	mac_t dst_mac;
	mac_t src_mac;
	uint16_t eth_type;
} __attribute__((packed));

struct ipv4_hdr_t {
	uint8_t ihl : 4;
	uint8_t version : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	ipv4_t src_ip;
	ipv4_t dst_ip;
} __attribute__((packed));

struct tcp_hdr_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_no;
	uint32_t ack_no;
	uint16_t opts;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_ptr;
} __attribute__((packed));

struct udp_hdr_t {
	port_t src_port;
	port_t dst_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

struct icmp_hdr_t {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
} __attribute__((packed));

// 424 bits / 53 bytes
struct hv_hdr_t {
	uint32_t ts_start;
	uint32_t ts_end;
	uint32_t ts_agg;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint32_t proto;
	uint32_t ports;
	uint32_t syn;
	uint32_t ack;
	uint32_t fin;
	uint32_t rst;
	uint32_t cnt;
	uint32_t len;
	uint8_t  flow_long;
} __attribute__((packed));

// 1280 bits / 160 bytes
struct hv_bin_hdr_t {
	uint32_t a_0_0;
	uint32_t b_0_0;
	uint32_t a_0_1;
	uint32_t b_0_1;
	uint32_t a_0_2;
	uint32_t b_0_2;
	uint32_t a_0_3;
	uint32_t b_0_3;
	uint32_t a_1_0;
	uint32_t b_1_0;
	uint32_t a_1_1;
	uint32_t b_1_1;
	uint32_t a_1_2;
	uint32_t b_1_2;
	uint32_t a_1_3;
	uint32_t b_1_3;
	uint32_t a_2_0;
	uint32_t b_2_0;
	uint32_t a_2_1;
	uint32_t b_2_1;
	uint32_t a_2_2;
	uint32_t b_2_2;
	uint32_t a_2_3;
	uint32_t b_2_3;
	uint32_t a_3_0;
	uint32_t b_3_0;
	uint32_t a_3_1;
	uint32_t b_3_1;
	uint32_t a_3_2;
	uint32_t b_3_2;
	uint32_t a_3_3;
	uint32_t b_3_3;
	uint32_t a_4_0;
	uint32_t b_4_0;
	uint32_t a_4_1;
	uint32_t b_4_1;
	uint32_t a_4_2;
	uint32_t b_4_2;
	uint32_t a_4_3;
	uint32_t b_4_3;
} __attribute__((packed));

struct pkt_hdr_t {
	uint8_t buffer[MAX_PACKET_SIZE];

	eth_hdr_t* get_l2() const { return (eth_hdr_t*)((uint8_t*)buffer); }

	size_t get_l2_size() const { return sizeof(eth_hdr_t); }

	ipv4_hdr_t* get_l3() const {
		auto l2_hdr			= get_l2();
		auto l2_hdr_size	= get_l2_size();

		return (ipv4_hdr_t*)((uint8_t*)l2_hdr + l2_hdr_size);
	}

	size_t get_l3_size() const { return sizeof(ipv4_hdr_t); }

	std::pair<void*, uint16_t> get_l4() const {
		auto ip_hdr		= get_l3();
		auto ip_size	= get_l3_size();

		switch (ip_hdr->protocol) {
			case IP_PROTO_TCP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_TCP);
			} break;
			case IP_PROTO_UDP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_UDP);
			} break;
			case IP_PROTO_ICMP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_ICMP);
			} break;
			default: {
				printf("\nError: Not a TCP/UDP/ICMP packet!\n");
				exit(1);
			} break;
		}
	}

	bool has_valid_protocol() const {
		auto ip_hdr = get_l3();

		return (ip_hdr->protocol == IP_PROTO_TCP ||
				ip_hdr->protocol == IP_PROTO_UDP ||
				ip_hdr->protocol == IP_PROTO_ICMP);
	}

	size_t get_l4_size() const {
		auto ip_hdr = get_l3();

		switch (ip_hdr->protocol) {
			case IP_PROTO_TCP: {
				return sizeof(tcp_hdr_t);
			} break;
			case IP_PROTO_UDP: {
				return sizeof(udp_hdr_t);
			} break;
			case IP_PROTO_ICMP: {
				return sizeof(icmp_hdr_t);
			} break;
			default: {
				return 0;
			} break;
		}
	}

	size_t get_hv_hdr_size() const {
		return sizeof(hv_hdr_t);
	}

	hv_hdr_t* get_hv_0_hdr() const {
		auto l4_hdr			= get_l4();
		auto l4_hdr_size	= get_l4_size();

		if (l4_hdr_size == 0) {
			printf(
				"\nError: Not a TCP/UDP/ICMP packet! Can't extract the hv 0 header.\n");
			exit(1);
		}

		auto hv_0_hdr = (uint8_t*)l4_hdr.first + l4_hdr_size;

		return static_cast<hv_hdr_t*>((void*)hv_0_hdr);
	}

	hv_hdr_t* get_hv_1_hdr() const {
		auto hv_0_hdr	= get_hv_0_hdr();
		auto hv_1_hdr	= (uint8_t*)hv_0_hdr + sizeof(hv_hdr_t);

		return static_cast<hv_hdr_t*>((void*)hv_1_hdr);
	}

	hv_hdr_t* get_hv_2_hdr() const {
		auto hv_1_hdr	= get_hv_1_hdr();
		auto hv_2_hdr	= (uint8_t*)hv_1_hdr + sizeof(hv_hdr_t);

		return static_cast<hv_hdr_t*>((void*)hv_2_hdr);
	}

	hv_hdr_t* get_hv_3_hdr() const {
		auto hv_2_hdr	= get_hv_2_hdr();
		auto hv_3_hdr	= (uint8_t*)hv_2_hdr + sizeof(hv_hdr_t);

		return static_cast<hv_hdr_t*>((void*)hv_3_hdr);
	}

	size_t get_hv_bin_hdr_size() const {
		return sizeof(hv_bin_hdr_t);
	}

	hv_bin_hdr_t* get_hv_bin_len_hdr() const {
		auto hv_3_hdr		= get_hv_3_hdr();
		auto hv_bin_len_hdr = (uint8_t*)hv_3_hdr + sizeof(hv_hdr_t);

		return static_cast<hv_bin_hdr_t*>((void*)hv_bin_len_hdr);
	}

	hv_bin_hdr_t* get_hv_bin_ts_hdr() const {
		auto hv_bin_len_hdr = get_hv_bin_len_hdr();
		auto hv_bin_ts_hdr	= (uint8_t*)hv_bin_len_hdr + sizeof(hv_bin_hdr_t);

		return static_cast<hv_bin_hdr_t*>((void*)hv_bin_ts_hdr);
	}

	void print_hdr_base() {
		auto eth_hdr	= get_l2();
		auto ip_hdr		= get_l3();
		auto l4_hdr		= get_l4();

		printf("### Ethernet ###\n");
		printf("# src	%02x:%02x:%02x:%02x:%02x:%02x\n",
				eth_hdr->src_mac[0], eth_hdr->src_mac[1], eth_hdr->src_mac[2],
				eth_hdr->src_mac[3], eth_hdr->src_mac[4], eth_hdr->src_mac[5]);
		printf("# dst	%02x:%02x:%02x:%02x:%02x:%02x\n",
				eth_hdr->dst_mac[0], eth_hdr->dst_mac[1], eth_hdr->dst_mac[2],
				eth_hdr->dst_mac[3], eth_hdr->dst_mac[4], eth_hdr->dst_mac[5]);
		printf("# type	0x%x\n", ntohs(eth_hdr->eth_type));

		printf("### IP ###\n");
		printf("# ihl		%u\n", (ip_hdr->ihl & 0x0f));
		printf("# version	%u\n", (ip_hdr->ihl & 0xf0) >> 4);
		printf("# tos		%u\n", ip_hdr->version);
		printf("# len		%u\n", ntohs(ip_hdr->tot_len));
		printf("# id		%u\n", ntohs(ip_hdr->id));
		printf("# off		%u\n", ntohs(ip_hdr->frag_off));
		printf("# ttl		%u\n", ip_hdr->ttl);
		printf("# proto		%u\n", ip_hdr->protocol);
		printf("# chksum	0x%x\n", ntohs(ip_hdr->check));
		printf("# src		%u.%u.%u.%u\n",
				(ip_hdr->src_ip >> 0) & 0xff, (ip_hdr->src_ip >> 8) & 0xff,
				(ip_hdr->src_ip >> 16) & 0xff, (ip_hdr->src_ip >> 24) & 0xff);
		printf("# dst		%u.%u.%u.%u\n",
				(ip_hdr->dst_ip >> 0) & 0xff, (ip_hdr->dst_ip >> 8) & 0xff,
				(ip_hdr->dst_ip >> 16) & 0xff, (ip_hdr->dst_ip >> 24) & 0xff);

		switch (l4_hdr.second) {
			case IP_PROTO_TCP: {
				auto tcp_hdr = static_cast<tcp_hdr_t*>(l4_hdr.first);
				printf("### TCP ###\n");
				printf("# sport		%u\n", ntohs(tcp_hdr->src_port));
				printf("# dport		%u\n", ntohs(tcp_hdr->dst_port));
			} break;
			case IP_PROTO_UDP: {
				auto udp_hdr = static_cast<udp_hdr_t*>(l4_hdr.first);
				printf("### UDP ###\n");
				printf("# sport		%u\n", ntohs(udp_hdr->src_port));
				printf("# dport		%u\n", ntohs(udp_hdr->dst_port));
			} break;
			case IP_PROTO_ICMP: {
				auto icmp_hdr = static_cast<icmp_hdr_t*>(l4_hdr.first);
				printf("### ICMP ###\n");
				printf("# type		%u\n", icmp_hdr->type);
				printf("# code		%u\n", icmp_hdr->code);
			} break;
			default: {
				printf("\nError: Not a TCP/UDP/ICMP packet.\n");
			} break;
		}
	}

	void print_hv_hdrs() {
		if (!has_valid_protocol()) { return; }

		auto hv_0_hdr = get_hv_0_hdr();
		auto hv_1_hdr = get_hv_0_hdr();
		auto hv_2_hdr = get_hv_0_hdr();
		auto hv_3_hdr = get_hv_0_hdr();

		printf("### hv 0 ###\n");
		printf("# ts_start	%u\n", ntohl(hv_0_hdr->ts_start));
		printf("# ts_end	%u\n", ntohl(hv_0_hdr->ts_end));
		printf("# ts_agg	%u\n", ntohl(hv_0_hdr->ts_agg));
		printf("# ip_src	%u.%u.%u.%u\n",
			   (hv_0_hdr->ip_src >> 0) & 0xff,
			   (hv_0_hdr->ip_src >> 8) & 0xff,
			   (hv_0_hdr->ip_src >> 16) & 0xff,
			   (hv_0_hdr->ip_src >> 24) & 0xff);
		printf("# ip_dst	%u.%u.%u.%u\n",
			   (hv_0_hdr->ip_dst >> 0) & 0xff,
			   (hv_0_hdr->ip_dst >> 8) & 0xff,
			   (hv_0_hdr->ip_dst >> 16) & 0xff,
			   (hv_0_hdr->ip_dst >> 24) & 0xff);
		printf("# proto		%u\n", ntohl(hv_0_hdr->proto));
		printf("# ports		%u\n", ntohl(hv_0_hdr->ports));
		printf("# syn		%u\n", ntohl(hv_0_hdr->syn));
		printf("# ack		%u\n", ntohl(hv_0_hdr->ack));
		printf("# fin		%u\n", ntohl(hv_0_hdr->fin));
		printf("# rst		%u\n", ntohl(hv_0_hdr->rst));
		printf("# cnt		%u\n", ntohl(hv_0_hdr->cnt));
		printf("# len		%u\n", ntohl(hv_0_hdr->len));
		printf("# long		%u\n", ntohl(hv_0_hdr->flow_long));

		printf("### hv 1 ###\n");
		printf("# ts_start	%u\n", ntohl(hv_1_hdr->ts_start));
		printf("# ts_end	%u\n", ntohl(hv_1_hdr->ts_end));
		printf("# ts_agg	%u\n", ntohl(hv_1_hdr->ts_agg));
		printf("# ip_src	%u.%u.%u.%u\n",
			   (hv_1_hdr->ip_src >> 0) & 0xff,
			   (hv_1_hdr->ip_src >> 8) & 0xff,
			   (hv_1_hdr->ip_src >> 16) & 0xff,
			   (hv_1_hdr->ip_src >> 24) & 0xff);
		printf("# ip_dst	%u.%u.%u.%u\n",
			   (hv_1_hdr->ip_dst >> 0) & 0xff,
			   (hv_1_hdr->ip_dst >> 8) & 0xff,
			   (hv_1_hdr->ip_dst >> 16) & 0xff,
			   (hv_1_hdr->ip_dst >> 24) & 0xff);
		printf("# proto		%u\n", ntohl(hv_1_hdr->proto));
		printf("# ports		%u\n", ntohl(hv_1_hdr->ports));
		printf("# syn		%u\n", ntohl(hv_1_hdr->syn));
		printf("# ack		%u\n", ntohl(hv_1_hdr->ack));
		printf("# fin		%u\n", ntohl(hv_1_hdr->fin));
		printf("# rst		%u\n", ntohl(hv_1_hdr->rst));
		printf("# cnt		%u\n", ntohl(hv_1_hdr->cnt));
		printf("# len		%u\n", ntohl(hv_1_hdr->len));
		printf("# long		%u\n", ntohl(hv_1_hdr->flow_long));

		printf("### hv 2 ###\n");
		printf("# ts_start	%u\n", ntohl(hv_2_hdr->ts_start));
		printf("# ts_end	%u\n", ntohl(hv_2_hdr->ts_end));
		printf("# ts_agg	%u\n", ntohl(hv_2_hdr->ts_agg));
		printf("# ip_src	%u.%u.%u.%u\n",
			   (hv_2_hdr->ip_src >> 0) & 0xff,
			   (hv_2_hdr->ip_src >> 8) & 0xff,
			   (hv_2_hdr->ip_src >> 16) & 0xff,
			   (hv_2_hdr->ip_src >> 24) & 0xff);
		printf("# ip_dst	%u.%u.%u.%u\n",
			   (hv_2_hdr->ip_dst >> 0) & 0xff,
			   (hv_2_hdr->ip_dst >> 8) & 0xff,
			   (hv_2_hdr->ip_dst >> 16) & 0xff,
			   (hv_2_hdr->ip_dst >> 24) & 0xff);
		printf("# proto		%u\n", ntohl(hv_2_hdr->proto));
		printf("# ports		%u\n", ntohl(hv_2_hdr->ports));
		printf("# syn		%u\n", ntohl(hv_2_hdr->syn));
		printf("# ack		%u\n", ntohl(hv_2_hdr->ack));
		printf("# fin		%u\n", ntohl(hv_2_hdr->fin));
		printf("# rst		%u\n", ntohl(hv_2_hdr->rst));
		printf("# cnt		%u\n", ntohl(hv_2_hdr->cnt));
		printf("# len		%u\n", ntohl(hv_2_hdr->len));
		printf("# long		%u\n", ntohl(hv_2_hdr->flow_long));

		printf("### hv 3 ###\n");
		printf("# ts_start	%u\n", ntohl(hv_3_hdr->ts_start));
		printf("# ts_end	%u\n", ntohl(hv_3_hdr->ts_end));
		printf("# ts_agg	%u\n", ntohl(hv_3_hdr->ts_agg));
		printf("# ip_src	%u.%u.%u.%u\n",
			   (hv_3_hdr->ip_src >> 0) & 0xff,
			   (hv_3_hdr->ip_src >> 8) & 0xff,
			   (hv_3_hdr->ip_src >> 16) & 0xff,
			   (hv_3_hdr->ip_src >> 24) & 0xff);
		printf("# ip_dst	%u.%u.%u.%u\n",
			   (hv_3_hdr->ip_dst >> 0) & 0xff,
			   (hv_3_hdr->ip_dst >> 8) & 0xff,
			   (hv_3_hdr->ip_dst >> 16) & 0xff,
			   (hv_3_hdr->ip_dst >> 24) & 0xff);
		printf("# proto		%u\n", ntohl(hv_3_hdr->proto));
		printf("# ports		%u\n", ntohl(hv_3_hdr->ports));
		printf("# syn		%u\n", ntohl(hv_3_hdr->syn));
		printf("# ack		%u\n", ntohl(hv_3_hdr->ack));
		printf("# fin		%u\n", ntohl(hv_3_hdr->fin));
		printf("# rst		%u\n", ntohl(hv_3_hdr->rst));
		printf("# cnt		%u\n", ntohl(hv_3_hdr->cnt));
		printf("# len		%u\n", ntohl(hv_3_hdr->len));
		printf("# long		%u\n", ntohl(hv_3_hdr->flow_long));
	}

	void print_hv_bin_len_hdr() {
		if (!has_valid_protocol()) { return; }

		auto bin_len_hdr = get_hv_bin_len_hdr();

		printf("### hv bin len ###\n");
		printf("# 0_0_a		%u\n", ntohl(bin_len_hdr->a_0_0));
		printf("# 0_0_b		%u\n", ntohl(bin_len_hdr->b_0_0));
		printf("# 0_1_a		%u\n", ntohl(bin_len_hdr->a_0_1));
		printf("# 0_1_b		%u\n", ntohl(bin_len_hdr->b_0_1));
		printf("# 0_2_a		%u\n", ntohl(bin_len_hdr->a_0_2));
		printf("# 0_2_b		%u\n", ntohl(bin_len_hdr->b_0_2));
		printf("# 0_3_a		%u\n", ntohl(bin_len_hdr->a_0_3));
		printf("# 0_3_b		%u\n", ntohl(bin_len_hdr->b_0_3));
		printf("# 1_0_a		%u\n", ntohl(bin_len_hdr->a_1_0));
		printf("# 1_0_b		%u\n", ntohl(bin_len_hdr->b_1_0));
		printf("# 1_1_a		%u\n", ntohl(bin_len_hdr->a_1_1));
		printf("# 1_1_b		%u\n", ntohl(bin_len_hdr->b_1_1));
		printf("# 1_2_a		%u\n", ntohl(bin_len_hdr->a_1_2));
		printf("# 1_2_b		%u\n", ntohl(bin_len_hdr->b_1_2));
		printf("# 1_3_a		%u\n", ntohl(bin_len_hdr->a_1_3));
		printf("# 1_3_b		%u\n", ntohl(bin_len_hdr->b_1_3));
		printf("# 2_0_a		%u\n", ntohl(bin_len_hdr->a_2_0));
		printf("# 2_0_b		%u\n", ntohl(bin_len_hdr->b_2_0));
		printf("# 2_1_a		%u\n", ntohl(bin_len_hdr->a_2_1));
		printf("# 2_1_b		%u\n", ntohl(bin_len_hdr->b_2_1));
		printf("# 2_2_a		%u\n", ntohl(bin_len_hdr->a_2_2));
		printf("# 2_2_b		%u\n", ntohl(bin_len_hdr->b_2_2));
		printf("# 2_3_a		%u\n", ntohl(bin_len_hdr->a_2_3));
		printf("# 2_3_b		%u\n", ntohl(bin_len_hdr->b_2_3));
		printf("# 3_0_a		%u\n", ntohl(bin_len_hdr->a_3_0));
		printf("# 3_0_b		%u\n", ntohl(bin_len_hdr->b_3_0));
		printf("# 3_1_a		%u\n", ntohl(bin_len_hdr->a_3_1));
		printf("# 3_1_b		%u\n", ntohl(bin_len_hdr->b_3_1));
		printf("# 3_2_a		%u\n", ntohl(bin_len_hdr->a_3_2));
		printf("# 3_2_b		%u\n", ntohl(bin_len_hdr->b_3_2));
		printf("# 3_3_a		%u\n", ntohl(bin_len_hdr->a_3_3));
		printf("# 3_3_b		%u\n", ntohl(bin_len_hdr->b_3_3));
		printf("# 4_0_a		%u\n", ntohl(bin_len_hdr->a_4_0));
		printf("# 4_0_b		%u\n", ntohl(bin_len_hdr->b_4_0));
		printf("# 4_1_a		%u\n", ntohl(bin_len_hdr->a_4_1));
		printf("# 4_1_b		%u\n", ntohl(bin_len_hdr->b_4_1));
		printf("# 4_2_a		%u\n", ntohl(bin_len_hdr->a_4_2));
		printf("# 4_2_b		%u\n", ntohl(bin_len_hdr->b_4_2));
		printf("# 4_3_a		%u\n", ntohl(bin_len_hdr->a_4_3));
		printf("# 4_3_b		%u\n", ntohl(bin_len_hdr->b_4_3));
	}

	void print_hv_bin_ts_hdr() {
		if (!has_valid_protocol()) { return; }

		auto bin_ts_hdr = get_hv_bin_ts_hdr();

		printf("### hv bin ts ###\n");
		printf("# 0_0_a		%u\n", ntohl(bin_ts_hdr->a_0_0));
		printf("# 0_0_b		%u\n", ntohl(bin_ts_hdr->b_0_0));
		printf("# 0_1_a		%u\n", ntohl(bin_ts_hdr->a_0_1));
		printf("# 0_1_b		%u\n", ntohl(bin_ts_hdr->b_0_1));
		printf("# 0_2_a		%u\n", ntohl(bin_ts_hdr->a_0_2));
		printf("# 0_2_b		%u\n", ntohl(bin_ts_hdr->b_0_2));
		printf("# 0_3_a		%u\n", ntohl(bin_ts_hdr->a_0_3));
		printf("# 0_3_b		%u\n", ntohl(bin_ts_hdr->b_0_3));
		printf("# 1_0_a		%u\n", ntohl(bin_ts_hdr->a_1_0));
		printf("# 1_0_b		%u\n", ntohl(bin_ts_hdr->b_1_0));
		printf("# 1_1_a		%u\n", ntohl(bin_ts_hdr->a_1_1));
		printf("# 1_1_b		%u\n", ntohl(bin_ts_hdr->b_1_1));
		printf("# 1_2_a		%u\n", ntohl(bin_ts_hdr->a_1_2));
		printf("# 1_2_b		%u\n", ntohl(bin_ts_hdr->b_1_2));
		printf("# 1_3_a		%u\n", ntohl(bin_ts_hdr->a_1_3));
		printf("# 1_3_b		%u\n", ntohl(bin_ts_hdr->b_1_3));
		printf("# 2_0_a		%u\n", ntohl(bin_ts_hdr->a_2_0));
		printf("# 2_0_b		%u\n", ntohl(bin_ts_hdr->b_2_0));
		printf("# 2_1_a		%u\n", ntohl(bin_ts_hdr->a_2_1));
		printf("# 2_1_b		%u\n", ntohl(bin_ts_hdr->b_2_1));
		printf("# 2_2_a		%u\n", ntohl(bin_ts_hdr->a_2_2));
		printf("# 2_2_b		%u\n", ntohl(bin_ts_hdr->b_2_2));
		printf("# 2_3_a		%u\n", ntohl(bin_ts_hdr->a_2_3));
		printf("# 2_3_b		%u\n", ntohl(bin_ts_hdr->b_2_3));
		printf("# 3_0_a		%u\n", ntohl(bin_ts_hdr->a_3_0));
		printf("# 3_0_b		%u\n", ntohl(bin_ts_hdr->b_3_0));
		printf("# 3_1_a		%u\n", ntohl(bin_ts_hdr->a_3_1));
		printf("# 3_1_b		%u\n", ntohl(bin_ts_hdr->b_3_1));
		printf("# 3_2_a		%u\n", ntohl(bin_ts_hdr->a_3_2));
		printf("# 3_2_b		%u\n", ntohl(bin_ts_hdr->b_3_2));
		printf("# 3_3_a		%u\n", ntohl(bin_ts_hdr->a_3_3));
		printf("# 3_3_b		%u\n", ntohl(bin_ts_hdr->b_3_3));
		printf("# 4_0_a		%u\n", ntohl(bin_ts_hdr->a_4_0));
		printf("# 4_0_b		%u\n", ntohl(bin_ts_hdr->b_4_0));
		printf("# 4_1_a		%u\n", ntohl(bin_ts_hdr->a_4_1));
		printf("# 4_1_b		%u\n", ntohl(bin_ts_hdr->b_4_1));
		printf("# 4_2_a		%u\n", ntohl(bin_ts_hdr->a_4_2));
		printf("# 4_2_b		%u\n", ntohl(bin_ts_hdr->b_4_2));
		printf("# 4_3_a		%u\n", ntohl(bin_ts_hdr->a_4_3));
		printf("# 4_3_b		%u\n", ntohl(bin_ts_hdr->b_4_3));
	}
} __attribute__((packed));

};	// namespace hypervision
