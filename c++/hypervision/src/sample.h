#pragma once

#include <array>
#include <vector>
#include <netinet/in.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <iostream>

#include "pkt_hdr.h"
#include "pkt_info.hpp"

namespace hypervision {

struct sample_t {
	bool valid;

	double			ts_start_0;
	double			ts_end_0;
	double			ts_agg_0;
	unsigned long	ip_src_0;
	unsigned long	ip_dst_0;
	uint32_t		proto_0;
	uint32_t		ports_0;
	uint32_t		syn_0;
	uint32_t		ack_0;
	uint32_t		fin_0;
	uint32_t		rst_0;
	uint32_t		cnt_0;
	uint32_t		len_0;
	uint16_t		long_0;
	double			ts_start_1;
	double			ts_end_1;
	double			ts_agg_1;
	unsigned long	ip_src_1;
	unsigned long	ip_dst_1;
	uint32_t		proto_1;
	uint32_t		ports_1;
	uint32_t		syn_1;
	uint32_t		ack_1;
	uint32_t		fin_1;
	uint32_t		rst_1;
	uint32_t		cnt_1;
	uint32_t		len_1;
	uint16_t		long_1;
	double			ts_start_2;
	double			ts_end_2;
	double			ts_agg_2;
	unsigned long	ip_src_2;
	unsigned long	ip_dst_2;
	uint32_t		proto_2;
	uint32_t		ports_2;
	uint32_t		syn_2;
	uint32_t		ack_2;
	uint32_t		fin_2;
	uint32_t		rst_2;
	uint32_t		cnt_2;
	uint32_t		len_2;
	uint16_t		long_2;
	double			ts_start_3;
	double			ts_end_3;
	double			ts_agg_3;
	unsigned long	ip_src_3;
	unsigned long	ip_dst_3;
	uint32_t		proto_3;
	uint32_t		ports_3;
	uint32_t		syn_3;
	uint32_t		ack_3;
	uint32_t		fin_3;
	uint32_t		rst_3;
	uint32_t		cnt_3;
	uint32_t		len_3;
	uint16_t		long_3;

	uint32_t bin_len_0_0_a;
	uint32_t bin_len_0_0_b;
	uint32_t bin_len_0_1_a;
	uint32_t bin_len_0_1_b;
	uint32_t bin_len_0_2_a;
	uint32_t bin_len_0_2_b;
	uint32_t bin_len_0_3_a;
	uint32_t bin_len_0_3_b;
	uint32_t bin_len_1_0_a;
	uint32_t bin_len_1_0_b;
	uint32_t bin_len_1_1_a;
	uint32_t bin_len_1_1_b;
	uint32_t bin_len_1_2_a;
	uint32_t bin_len_1_2_b;
	uint32_t bin_len_1_3_a;
	uint32_t bin_len_1_3_b;
	uint32_t bin_len_2_0_a;
	uint32_t bin_len_2_0_b;
	uint32_t bin_len_2_1_a;
	uint32_t bin_len_2_1_b;
	uint32_t bin_len_2_2_a;
	uint32_t bin_len_2_2_b;
	uint32_t bin_len_2_3_a;
	uint32_t bin_len_2_3_b;
	uint32_t bin_len_3_0_a;
	uint32_t bin_len_3_0_b;
	uint32_t bin_len_3_1_a;
	uint32_t bin_len_3_1_b;
	uint32_t bin_len_3_2_a;
	uint32_t bin_len_3_2_b;
	uint32_t bin_len_3_3_a;
	uint32_t bin_len_3_3_b;
	uint32_t bin_len_4_0_a;
	uint32_t bin_len_4_0_b;
	uint32_t bin_len_4_1_a;
	uint32_t bin_len_4_1_b;
	uint32_t bin_len_4_2_a;
	uint32_t bin_len_4_2_b;
	uint32_t bin_len_4_3_a;
	uint32_t bin_len_4_3_b;

	uint32_t bin_ts_0_0_a;
	uint32_t bin_ts_0_0_b;
	uint32_t bin_ts_0_1_a;
	uint32_t bin_ts_0_1_b;
	uint32_t bin_ts_0_2_a;
	uint32_t bin_ts_0_2_b;
	uint32_t bin_ts_0_3_a;
	uint32_t bin_ts_0_3_b;
	uint32_t bin_ts_1_0_a;
	uint32_t bin_ts_1_0_b;
	uint32_t bin_ts_1_1_a;
	uint32_t bin_ts_1_1_b;
	uint32_t bin_ts_1_2_a;
	uint32_t bin_ts_1_2_b;
	uint32_t bin_ts_1_3_a;
	uint32_t bin_ts_1_3_b;
	uint32_t bin_ts_2_0_a;
	uint32_t bin_ts_2_0_b;
	uint32_t bin_ts_2_1_a;
	uint32_t bin_ts_2_1_b;
	uint32_t bin_ts_2_2_a;
	uint32_t bin_ts_2_2_b;
	uint32_t bin_ts_2_3_a;
	uint32_t bin_ts_2_3_b;
	uint32_t bin_ts_3_0_a;
	uint32_t bin_ts_3_0_b;
	uint32_t bin_ts_3_1_a;
	uint32_t bin_ts_3_1_b;
	uint32_t bin_ts_3_2_a;
	uint32_t bin_ts_3_2_b;
	uint32_t bin_ts_3_3_a;
	uint32_t bin_ts_3_3_b;
	uint32_t bin_ts_4_0_a;
	uint32_t bin_ts_4_0_b;
	uint32_t bin_ts_4_1_a;
	uint32_t bin_ts_4_1_b;
	uint32_t bin_ts_4_2_a;
	uint32_t bin_ts_4_2_b;
	uint32_t bin_ts_4_3_a;
	uint32_t bin_ts_4_3_b;

	sample_t(pkt_hdr_t* pkt, size_t pkt_size) {
		valid = pkt->has_valid_protocol();

		if (!valid) {
			printf("Error: Invalid protocol packet. Ignoring.\n");
			return;
		}

		valid = (pkt_size >= (pkt->get_l2_size()
							  + pkt->get_l3_size()
							  + pkt->get_l4_size()
							  + 4 * pkt->get_hv_hdr_size()
							  + 2 * pkt->get_hv_bin_hdr_size()));

		size_t min_size = pkt->get_l2_size()
						  + pkt->get_l3_size()
						  + pkt->get_l4_size()
						  + 4 * pkt->get_hv_hdr_size()
						  + 2 * pkt->get_hv_bin_hdr_size();

		if (!valid) {
			printf("Error: Packet too small (%lu bytes). Ignoring.\n", pkt_size);
			printf("Min pkt size: %lu", min_size);
			return;
		}

		#ifdef DEBUG
			pkt->print_hdr_base();
			pkt->print_hv_hdrs();
			pkt->print_hv_bin_len_hdr();
			pkt->print_hv_bin_ts_hdr();
		#endif

		auto l2 = pkt->get_l2();
		auto l3 = pkt->get_l3();

		auto hv_0_hdr		= pkt->get_hv_0_hdr();
		auto hv_1_hdr		= pkt->get_hv_1_hdr();
		auto hv_2_hdr		= pkt->get_hv_2_hdr();
		auto hv_3_hdr		= pkt->get_hv_3_hdr();
		auto bin_len_hdr	= pkt->get_hv_bin_len_hdr();
		auto bin_ts_hdr		= pkt->get_hv_bin_ts_hdr();

		ts_start_0	= ntohl(hv_0_hdr->ts_start);
		ts_end_0	= ntohl(hv_0_hdr->ts_end);
		ts_agg_0	= ntohl(hv_0_hdr->ts_agg);
		ip_src_0	= hv_0_hdr->ip_src;
		ip_dst_0	= hv_0_hdr->ip_dst;
		proto_0		= ntohl(hv_0_hdr->proto);
		ports_0		= ntohl(hv_0_hdr->ports);
		syn_0		= ntohl(hv_0_hdr->syn);
		ack_0		= ntohl(hv_0_hdr->ack);
		fin_0		= ntohl(hv_0_hdr->fin);
		rst_0		= ntohl(hv_0_hdr->rst);
		cnt_0		= ntohl(hv_0_hdr->cnt);
		len_0		= ntohl(hv_0_hdr->len);
		long_0		= ntohl(hv_0_hdr->flow_long);

		ts_start_1	= ntohl(hv_1_hdr->ts_start);
		ts_end_1	= ntohl(hv_1_hdr->ts_end);
		ts_agg_1	= ntohl(hv_1_hdr->ts_agg);
		ip_src_1	= hv_1_hdr->ip_src;
		ip_dst_1	= hv_1_hdr->ip_dst;
		proto_1		= ntohl(hv_1_hdr->proto);
		ports_1		= ntohl(hv_1_hdr->ports);
		syn_1		= ntohl(hv_1_hdr->syn);
		ack_1		= ntohl(hv_1_hdr->ack);
		fin_1		= ntohl(hv_1_hdr->fin);
		rst_1		= ntohl(hv_1_hdr->rst);
		cnt_1		= ntohl(hv_1_hdr->cnt);
		len_1		= ntohl(hv_1_hdr->len);
		long_1		= ntohl(hv_1_hdr->flow_long);

		ts_start_2	= ntohl(hv_2_hdr->ts_start);
		ts_end_2	= ntohl(hv_2_hdr->ts_end);
		ts_agg_2	= ntohl(hv_2_hdr->ts_agg);
		ip_src_2	= hv_2_hdr->ip_src;
		ip_dst_2	= hv_2_hdr->ip_dst;
		proto_2		= ntohl(hv_2_hdr->proto);
		ports_2		= ntohl(hv_2_hdr->ports);
		syn_2		= ntohl(hv_2_hdr->syn);
		ack_2		= ntohl(hv_2_hdr->ack);
		fin_2		= ntohl(hv_2_hdr->fin);
		rst_2		= ntohl(hv_2_hdr->rst);
		cnt_2		= ntohl(hv_2_hdr->cnt);
		len_2		= ntohl(hv_2_hdr->len);
		long_2		= ntohl(hv_2_hdr->flow_long);

		ts_start_3	= ntohl(hv_3_hdr->ts_start);
		ts_end_3	= ntohl(hv_3_hdr->ts_end);
		ts_agg_3	= ntohl(hv_3_hdr->ts_agg);
		ip_src_3	= hv_3_hdr->ip_src;
		ip_dst_3	= hv_3_hdr->ip_dst;
		proto_3		= ntohl(hv_3_hdr->proto);
		ports_3		= ntohl(hv_3_hdr->ports);
		syn_3		= ntohl(hv_3_hdr->syn);
		ack_3		= ntohl(hv_3_hdr->ack);
		fin_3		= ntohl(hv_3_hdr->fin);
		rst_3		= ntohl(hv_3_hdr->rst);
		cnt_3		= ntohl(hv_3_hdr->cnt);
		len_3		= ntohl(hv_3_hdr->len);
		long_3		= ntohl(hv_3_hdr->flow_long);

		bin_len_0_0_a	= ntohl(bin_len_hdr->a_0_0);
		bin_len_0_0_b	= ntohl(bin_len_hdr->b_0_0);
		bin_len_0_1_a	= ntohl(bin_len_hdr->a_0_1);
		bin_len_0_1_b	= ntohl(bin_len_hdr->b_0_1);
		bin_len_0_2_a	= ntohl(bin_len_hdr->a_0_2);
		bin_len_0_2_b	= ntohl(bin_len_hdr->b_0_2);
		bin_len_0_3_a	= ntohl(bin_len_hdr->a_0_3);
		bin_len_0_3_b	= ntohl(bin_len_hdr->b_0_3);
		bin_len_1_0_a	= ntohl(bin_len_hdr->a_1_0);
		bin_len_1_0_b	= ntohl(bin_len_hdr->b_1_0);
		bin_len_1_1_a	= ntohl(bin_len_hdr->a_1_1);
		bin_len_1_1_b	= ntohl(bin_len_hdr->b_1_1);
		bin_len_1_2_a	= ntohl(bin_len_hdr->a_1_2);
		bin_len_1_2_b	= ntohl(bin_len_hdr->b_1_2);
		bin_len_1_3_a	= ntohl(bin_len_hdr->a_1_3);
		bin_len_1_3_b	= ntohl(bin_len_hdr->b_1_3);
		bin_len_2_0_a	= ntohl(bin_len_hdr->a_2_0);
		bin_len_2_0_b	= ntohl(bin_len_hdr->b_2_0);
		bin_len_2_1_a	= ntohl(bin_len_hdr->a_2_1);
		bin_len_2_1_b	= ntohl(bin_len_hdr->b_2_1);
		bin_len_2_2_a	= ntohl(bin_len_hdr->a_2_2);
		bin_len_2_2_b	= ntohl(bin_len_hdr->b_2_2);
		bin_len_2_3_a	= ntohl(bin_len_hdr->a_2_3);
		bin_len_2_3_b	= ntohl(bin_len_hdr->b_2_3);
		bin_len_3_0_a	= ntohl(bin_len_hdr->a_3_0);
		bin_len_3_0_b	= ntohl(bin_len_hdr->b_3_0);
		bin_len_3_1_a	= ntohl(bin_len_hdr->a_3_1);
		bin_len_3_1_b	= ntohl(bin_len_hdr->b_3_1);
		bin_len_3_2_a	= ntohl(bin_len_hdr->a_3_2);
		bin_len_3_2_b	= ntohl(bin_len_hdr->b_3_2);
		bin_len_3_3_a	= ntohl(bin_len_hdr->a_3_3);
		bin_len_3_3_b	= ntohl(bin_len_hdr->b_3_3);
		bin_len_4_0_a	= ntohl(bin_len_hdr->a_4_0);
		bin_len_4_0_b	= ntohl(bin_len_hdr->b_4_0);
		bin_len_4_1_a	= ntohl(bin_len_hdr->a_4_1);
		bin_len_4_1_b	= ntohl(bin_len_hdr->b_4_1);
		bin_len_4_2_a	= ntohl(bin_len_hdr->a_4_2);
		bin_len_4_2_b	= ntohl(bin_len_hdr->b_4_2);
		bin_len_4_3_a	= ntohl(bin_len_hdr->a_4_3);
		bin_len_4_3_b	= ntohl(bin_len_hdr->b_4_3);

		bin_ts_0_0_a	= ntohl(bin_ts_hdr->a_0_0);
		bin_ts_0_0_b	= ntohl(bin_ts_hdr->b_0_0);
		bin_ts_0_1_a	= ntohl(bin_ts_hdr->a_0_1);
		bin_ts_0_1_b	= ntohl(bin_ts_hdr->b_0_1);
		bin_ts_0_2_a	= ntohl(bin_ts_hdr->a_0_2);
		bin_ts_0_2_b	= ntohl(bin_ts_hdr->b_0_2);
		bin_ts_0_3_a	= ntohl(bin_ts_hdr->a_0_3);
		bin_ts_0_3_b	= ntohl(bin_ts_hdr->b_0_3);
		bin_ts_1_0_a	= ntohl(bin_ts_hdr->a_1_0);
		bin_ts_1_0_b	= ntohl(bin_ts_hdr->b_1_0);
		bin_ts_1_1_a	= ntohl(bin_ts_hdr->a_1_1);
		bin_ts_1_1_b	= ntohl(bin_ts_hdr->b_1_1);
		bin_ts_1_2_a	= ntohl(bin_ts_hdr->a_1_2);
		bin_ts_1_2_b	= ntohl(bin_ts_hdr->b_1_2);
		bin_ts_1_3_a	= ntohl(bin_ts_hdr->a_1_3);
		bin_ts_1_3_b	= ntohl(bin_ts_hdr->b_1_3);
		bin_ts_2_0_a	= ntohl(bin_ts_hdr->a_2_0);
		bin_ts_2_0_b	= ntohl(bin_ts_hdr->b_2_0);
		bin_ts_2_1_a	= ntohl(bin_ts_hdr->a_2_1);
		bin_ts_2_1_b	= ntohl(bin_ts_hdr->b_2_1);
		bin_ts_2_2_a	= ntohl(bin_ts_hdr->a_2_2);
		bin_ts_2_2_b	= ntohl(bin_ts_hdr->b_2_2);
		bin_ts_2_3_a	= ntohl(bin_ts_hdr->a_2_3);
		bin_ts_2_3_b	= ntohl(bin_ts_hdr->b_2_3);
		bin_ts_3_0_a	= ntohl(bin_ts_hdr->a_3_0);
		bin_ts_3_0_b	= ntohl(bin_ts_hdr->b_3_0);
		bin_ts_3_1_a	= ntohl(bin_ts_hdr->a_3_1);
		bin_ts_3_1_b	= ntohl(bin_ts_hdr->b_3_1);
		bin_ts_3_2_a	= ntohl(bin_ts_hdr->a_3_2);
		bin_ts_3_2_b	= ntohl(bin_ts_hdr->b_3_2);
		bin_ts_3_3_a	= ntohl(bin_ts_hdr->a_3_3);
		bin_ts_3_3_b	= ntohl(bin_ts_hdr->b_3_3);
		bin_ts_4_0_a	= ntohl(bin_ts_hdr->a_4_0);
		bin_ts_4_0_b	= ntohl(bin_ts_hdr->b_4_0);
		bin_ts_4_1_a	= ntohl(bin_ts_hdr->a_4_1);
		bin_ts_4_1_b	= ntohl(bin_ts_hdr->b_4_1);
		bin_ts_4_2_a	= ntohl(bin_ts_hdr->a_4_2);
		bin_ts_4_2_b	= ntohl(bin_ts_hdr->b_4_2);
		bin_ts_4_3_a	= ntohl(bin_ts_hdr->a_4_3);
		bin_ts_4_3_b	= ntohl(bin_ts_hdr->b_4_3);
	}

	sample_t(std::array<std::string, 56> hv_hdr,
			 std::array<std::string, 40> hv_bin_len_hdr,
			 std::array<std::string, 40> hv_bin_ts_hdr) {

		unsigned int o1 = 0, o2 = 0, o3 = 0, o4 = 0;
		char c1 = 0, c2 = 0, c3 = 0;

		ts_start_0	= std::stod(hv_hdr[0]);
		ts_end_0	= std::stod(hv_hdr[1]);
		ts_agg_0	= std::stod(hv_hdr[2]);
		// ip_src_0	= ntohl(std::stoul(hv_hdr[3]));
		std::sscanf(hv_hdr[3].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_src_0 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		// ip_dst_0	= ntohl(std::stoul(hv_hdr[4]));
		std::sscanf(hv_hdr[4].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_dst_0 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		proto_0		= std::stoi(hv_hdr[5]);
		ports_0		= std::stol(hv_hdr[6]);
		syn_0		= std::stoi(hv_hdr[7]);
		ack_0		= std::stoi(hv_hdr[8]);
		fin_0		= std::stoi(hv_hdr[9]);
		rst_0		= std::stoi(hv_hdr[10]);
		cnt_0		= std::stoi(hv_hdr[11]);
		len_0		= std::stoi(hv_hdr[12]);
		long_0		= std::stoi(hv_hdr[13]);

		ts_start_1	= std::stod(hv_hdr[14]);
		ts_end_1	= std::stod(hv_hdr[15]);
		ts_agg_1	= std::stod(hv_hdr[16]);
		// ip_src_1	= ntohl(std::stoul(hv_hdr[17]));
		std::sscanf(hv_hdr[17].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_src_1 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		// ip_dst_1	= ntohl(std::stoul(hv_hdr[18]));
		std::sscanf(hv_hdr[18].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_dst_1 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		proto_1		= std::stoi(hv_hdr[19]);
		ports_1		= std::stol(hv_hdr[20]);
		syn_1		= std::stoi(hv_hdr[21]);
		ack_1		= std::stoi(hv_hdr[22]);
		fin_1		= std::stoi(hv_hdr[23]);
		rst_1		= std::stoi(hv_hdr[24]);
		cnt_1		= std::stoi(hv_hdr[25]);
		len_1		= std::stoi(hv_hdr[26]);
		long_1		= std::stoi(hv_hdr[27]);

		ts_start_2	= std::stod(hv_hdr[28]);
		ts_end_2	= std::stod(hv_hdr[29]);
		ts_agg_2	= std::stod(hv_hdr[30]);
		// ip_src_2	= ntohl(std::stoul(hv_hdr[31]));
		std::sscanf(hv_hdr[31].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_src_2 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		// ip_dst_2	= ntohl(std::stoul(hv_hdr[32]));
		std::sscanf(hv_hdr[32].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_dst_2 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		proto_2		= std::stoi(hv_hdr[33]);
		ports_2		= std::stol(hv_hdr[34]);
		syn_2		= std::stoi(hv_hdr[35]);
		ack_2		= std::stoi(hv_hdr[36]);
		fin_2		= std::stoi(hv_hdr[37]);
		rst_2		= std::stoi(hv_hdr[38]);
		cnt_2		= std::stoi(hv_hdr[39]);
		len_2		= std::stoi(hv_hdr[40]);
		long_2		= std::stoi(hv_hdr[41]);

		ts_start_3	= std::stod(hv_hdr[42]);
		ts_end_3	= std::stod(hv_hdr[43]);
		ts_agg_3	= std::stod(hv_hdr[44]);
		// ip_src_3	= ntohl(std::stoul(hv_hdr[45]));
		std::sscanf(hv_hdr[45].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_src_3 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		// ip_dst_3	= ntohl(std::stoul(hv_hdr[46]));
		std::sscanf(hv_hdr[46].c_str(), "%u%c%u%c%u%c%u", &o1, &c1, &o2, &c2, &o3, &c3, &o4);
		ip_dst_3 = (static_cast<unsigned long>(o1) << 24)
                 | (static_cast<unsigned long>(o2) << 16)
                 | (static_cast<unsigned long>(o3) <<  8)
                 |  static_cast<unsigned long>(o4);
		proto_3		= std::stoi(hv_hdr[47]);
		ports_3		= std::stol(hv_hdr[48]);
		syn_3		= std::stoi(hv_hdr[49]);
		ack_3		= std::stoi(hv_hdr[50]);
		fin_3		= std::stoi(hv_hdr[51]);
		rst_3		= std::stoi(hv_hdr[52]);
		cnt_3		= std::stoi(hv_hdr[53]);
		len_3		= std::stoi(hv_hdr[54]);
		long_3		= std::stoi(hv_hdr[55]);

		bin_len_0_0_a	= std::stoi(hv_bin_len_hdr[0]);
		bin_len_0_0_b	= std::stoi(hv_bin_len_hdr[1]);
		bin_len_0_1_a	= std::stoi(hv_bin_len_hdr[2]);
		bin_len_0_1_b	= std::stoi(hv_bin_len_hdr[3]);
		bin_len_0_2_a	= std::stoi(hv_bin_len_hdr[4]);
		bin_len_0_2_b	= std::stoi(hv_bin_len_hdr[5]);
		bin_len_0_3_a	= std::stoi(hv_bin_len_hdr[6]);
		bin_len_0_3_b	= std::stoi(hv_bin_len_hdr[7]);
		bin_len_1_0_a	= std::stoi(hv_bin_len_hdr[8]);
		bin_len_1_0_b	= std::stoi(hv_bin_len_hdr[9]);
		bin_len_1_1_a	= std::stoi(hv_bin_len_hdr[10]);
		bin_len_1_1_b	= std::stoi(hv_bin_len_hdr[11]);
		bin_len_1_2_a	= std::stoi(hv_bin_len_hdr[12]);
		bin_len_1_2_b	= std::stoi(hv_bin_len_hdr[13]);
		bin_len_1_3_a	= std::stoi(hv_bin_len_hdr[14]);
		bin_len_1_3_b	= std::stoi(hv_bin_len_hdr[15]);
		bin_len_2_0_a	= std::stoi(hv_bin_len_hdr[16]);
		bin_len_2_0_b	= std::stoi(hv_bin_len_hdr[17]);
		bin_len_2_1_a	= std::stoi(hv_bin_len_hdr[18]);
		bin_len_2_1_b	= std::stoi(hv_bin_len_hdr[19]);
		bin_len_2_2_a	= std::stoi(hv_bin_len_hdr[20]);
		bin_len_2_2_b	= std::stoi(hv_bin_len_hdr[21]);
		bin_len_2_3_a	= std::stoi(hv_bin_len_hdr[22]);
		bin_len_2_3_b	= std::stoi(hv_bin_len_hdr[23]);
		bin_len_3_0_a	= std::stoi(hv_bin_len_hdr[24]);
		bin_len_3_0_b	= std::stoi(hv_bin_len_hdr[25]);
		bin_len_3_1_a	= std::stoi(hv_bin_len_hdr[26]);
		bin_len_3_1_b	= std::stoi(hv_bin_len_hdr[27]);
		bin_len_3_2_a	= std::stoi(hv_bin_len_hdr[28]);
		bin_len_3_2_b	= std::stoi(hv_bin_len_hdr[29]);
		bin_len_3_3_a	= std::stoi(hv_bin_len_hdr[30]);
		bin_len_3_3_b	= std::stoi(hv_bin_len_hdr[31]);
		bin_len_4_0_a	= std::stoi(hv_bin_len_hdr[32]);
		bin_len_4_0_b	= std::stoi(hv_bin_len_hdr[33]);
		bin_len_4_1_a	= std::stoi(hv_bin_len_hdr[34]);
		bin_len_4_1_b	= std::stoi(hv_bin_len_hdr[35]);
		bin_len_4_2_a	= std::stoi(hv_bin_len_hdr[36]);
		bin_len_4_2_b	= std::stoi(hv_bin_len_hdr[37]);
		bin_len_4_3_a	= std::stoi(hv_bin_len_hdr[38]);
		bin_len_4_3_b	= std::stoi(hv_bin_len_hdr[39]);

		bin_ts_0_0_a	= std::stoi(hv_bin_ts_hdr[0]);
		bin_ts_0_0_b	= std::stoi(hv_bin_ts_hdr[1]);
		bin_ts_0_1_a	= std::stoi(hv_bin_ts_hdr[2]);
		bin_ts_0_1_b	= std::stoi(hv_bin_ts_hdr[3]);
		bin_ts_0_2_a	= std::stoi(hv_bin_ts_hdr[4]);
		bin_ts_0_2_b	= std::stoi(hv_bin_ts_hdr[5]);
		bin_ts_0_3_a	= std::stoi(hv_bin_ts_hdr[6]);
		bin_ts_0_3_b	= std::stoi(hv_bin_ts_hdr[7]);
		bin_ts_1_0_a	= std::stoi(hv_bin_ts_hdr[8]);
		bin_ts_1_0_b	= std::stoi(hv_bin_ts_hdr[9]);
		bin_ts_1_1_a	= std::stoi(hv_bin_ts_hdr[10]);
		bin_ts_1_1_b	= std::stoi(hv_bin_ts_hdr[11]);
		bin_ts_1_2_a	= std::stoi(hv_bin_ts_hdr[12]);
		bin_ts_1_2_b	= std::stoi(hv_bin_ts_hdr[13]);
		bin_ts_1_3_a	= std::stoi(hv_bin_ts_hdr[14]);
		bin_ts_1_3_b	= std::stoi(hv_bin_ts_hdr[15]);
		bin_ts_2_0_a	= std::stoi(hv_bin_ts_hdr[16]);
		bin_ts_2_0_b	= std::stoi(hv_bin_ts_hdr[17]);
		bin_ts_2_1_a	= std::stoi(hv_bin_ts_hdr[18]);
		bin_ts_2_1_b	= std::stoi(hv_bin_ts_hdr[19]);
		bin_ts_2_2_a	= std::stoi(hv_bin_ts_hdr[20]);
		bin_ts_2_2_b	= std::stoi(hv_bin_ts_hdr[21]);
		bin_ts_2_3_a	= std::stoi(hv_bin_ts_hdr[22]);
		bin_ts_2_3_b	= std::stoi(hv_bin_ts_hdr[23]);
		bin_ts_3_0_a	= std::stoi(hv_bin_ts_hdr[24]);
		bin_ts_3_0_b	= std::stoi(hv_bin_ts_hdr[25]);
		bin_ts_3_1_a	= std::stoi(hv_bin_ts_hdr[26]);
		bin_ts_3_1_b	= std::stoi(hv_bin_ts_hdr[27]);
		bin_ts_3_2_a	= std::stoi(hv_bin_ts_hdr[28]);
		bin_ts_3_2_b	= std::stoi(hv_bin_ts_hdr[29]);
		bin_ts_3_3_a	= std::stoi(hv_bin_ts_hdr[30]);
		bin_ts_3_3_b	= std::stoi(hv_bin_ts_hdr[31]);
		bin_ts_4_0_a	= std::stoi(hv_bin_ts_hdr[32]);
		bin_ts_4_0_b	= std::stoi(hv_bin_ts_hdr[33]);
		bin_ts_4_1_a	= std::stoi(hv_bin_ts_hdr[34]);
		bin_ts_4_1_b	= std::stoi(hv_bin_ts_hdr[35]);
		bin_ts_4_2_a	= std::stoi(hv_bin_ts_hdr[36]);
		bin_ts_4_2_b	= std::stoi(hv_bin_ts_hdr[37]);
		bin_ts_4_3_a	= std::stoi(hv_bin_ts_hdr[38]);
		bin_ts_4_3_b	= std::stoi(hv_bin_ts_hdr[39]);

		// print_sample();
	}

	void print_sample() {
		std::cout << "--- Sample ---" << std::endl;
		std::cout << "ts_start_0: " << ts_start_0	<< std::endl;
		std::cout << "ts_end_0: "	<< ts_end_0		<< std::endl;
		std::cout << "ts_agg_0: "	<< ts_agg_0		<< std::endl;
		std::cout << "ip_src_0: "	<< ip_src_0		<< std::endl;
		std::cout << "ip_dst_0: "	<< ip_dst_0		<< std::endl;
		std::cout << "proto_0: "	<< proto_0		<< std::endl;
		std::cout << "ports_0: "	<< ports_0		<< std::endl;
		std::cout << "syn_0: "		<< syn_0		<< std::endl;
		std::cout << "ack_0: "		<< ack_0		<< std::endl;
		std::cout << "fin_0: "		<< fin_0		<< std::endl;
		std::cout << "rst_0: "		<< rst_0		<< std::endl;
		std::cout << "cnt_0: "		<< cnt_0		<< std::endl;
		std::cout << "len_0: "		<< len_0		<< std::endl;
		std::cout << "long_0: "		<< long_0		<< std::endl;
		std::cout << "--------------" << std::endl;
		std::cout << "ts_start_1: " << ts_start_1	<< std::endl;
		std::cout << "ts_end_1: "	<< ts_end_1		<< std::endl;
		std::cout << "ts_agg_1: "	<< ts_agg_1		<< std::endl;
		std::cout << "ip_src_1: "	<< ip_src_1		<< std::endl;
		std::cout << "ip_dst_1: "	<< ip_dst_1		<< std::endl;
		std::cout << "proto_1: "	<< proto_1		<< std::endl;
		std::cout << "ports_1: "	<< ports_1		<< std::endl;
		std::cout << "syn_1: "		<< syn_1		<< std::endl;
		std::cout << "ack_1: "		<< ack_1		<< std::endl;
		std::cout << "fin_1: "		<< fin_1		<< std::endl;
		std::cout << "rst_1: "		<< rst_1		<< std::endl;
		std::cout << "cnt_1: "		<< cnt_1		<< std::endl;
		std::cout << "len_1: "		<< len_1		<< std::endl;
		std::cout << "long_1: "		<< long_1		<< std::endl;
		std::cout << "--------------" << std::endl;
		std::cout << "ts_start_2: " << ts_start_2	<< std::endl;
		std::cout << "ts_end_2: "	<< ts_end_2		<< std::endl;
		std::cout << "ts_agg_2: "	<< ts_agg_2		<< std::endl;
		std::cout << "ip_src_2: "	<< ip_src_2		<< std::endl;
		std::cout << "ip_dst_2: "	<< ip_dst_2		<< std::endl;
		std::cout << "proto_2: "	<< proto_2		<< std::endl;
		std::cout << "ports_2: "	<< ports_2		<< std::endl;
		std::cout << "syn_2: "		<< syn_2		<< std::endl;
		std::cout << "ack_2: "		<< ack_2		<< std::endl;
		std::cout << "fin_2: "		<< fin_2		<< std::endl;
		std::cout << "rst_2: "		<< rst_2		<< std::endl;
		std::cout << "cnt_2: "		<< cnt_2		<< std::endl;
		std::cout << "len_2: "		<< len_2		<< std::endl;
		std::cout << "long_2: "		<< long_2		<< std::endl;
		std::cout << "--------------" << std::endl;
		std::cout << "ts_start_3: " << ts_start_3	<< std::endl;
		std::cout << "ts_end_3: "	<< ts_end_3		<< std::endl;
		std::cout << "ts_agg_3: "	<< ts_agg_3		<< std::endl;
		std::cout << "ip_src_3: "	<< ip_src_3		<< std::endl;
		std::cout << "ip_dst_3: "	<< ip_dst_3		<< std::endl;
		std::cout << "proto_3: "	<< proto_3		<< std::endl;
		std::cout << "ports_3: "	<< ports_3		<< std::endl;
		std::cout << "syn_3: "		<< syn_3		<< std::endl;
		std::cout << "ack_3: "		<< ack_3		<< std::endl;
		std::cout << "fin_3: "		<< fin_3		<< std::endl;
		std::cout << "rst_3: "		<< rst_3		<< std::endl;
		std::cout << "cnt_3: "		<< cnt_3		<< std::endl;
		std::cout << "len_3: "		<< len_3		<< std::endl;
		std::cout << "long_3: "		<< long_3		<< std::endl;
		std::cout << "--------------" << std::endl;
		std::cout << "bin_len_0_0_a: " << bin_len_0_0_a	<< std::endl;
		std::cout << "bin_len_0_0_b: " << bin_len_0_0_b	<< std::endl;
		std::cout << "bin_len_0_1_a: " << bin_len_0_1_a	<< std::endl;
		std::cout << "bin_len_0_1_b: " << bin_len_0_1_b	<< std::endl;
		std::cout << "bin_len_0_2_a: " << bin_len_0_2_a	<< std::endl;
		std::cout << "bin_len_0_2_b: " << bin_len_0_2_b	<< std::endl;
		std::cout << "bin_len_0_3_a: " << bin_len_0_3_a	<< std::endl;
		std::cout << "bin_len_0_3_b: " << bin_len_0_3_b	<< std::endl;
		std::cout << "bin_len_1_0_a: " << bin_len_1_0_a	<< std::endl;
		std::cout << "bin_len_1_0_b: " << bin_len_1_0_b	<< std::endl;
		std::cout << "bin_len_1_1_a: " << bin_len_1_1_a	<< std::endl;
		std::cout << "bin_len_1_1_b: " << bin_len_1_1_b	<< std::endl;
		std::cout << "bin_len_1_2_a: " << bin_len_1_2_a	<< std::endl;
		std::cout << "bin_len_1_2_b: " << bin_len_1_2_b	<< std::endl;
		std::cout << "bin_len_1_3_a: " << bin_len_1_3_a	<< std::endl;
		std::cout << "bin_len_1_3_b: " << bin_len_1_3_b	<< std::endl;
		std::cout << "bin_len_2_0_a: " << bin_len_2_0_a	<< std::endl;
		std::cout << "bin_len_2_0_b: " << bin_len_2_0_b	<< std::endl;
		std::cout << "bin_len_2_1_a: " << bin_len_2_1_a	<< std::endl;
		std::cout << "bin_len_2_1_b: " << bin_len_2_1_b	<< std::endl;
		std::cout << "bin_len_2_2_a: " << bin_len_2_2_a	<< std::endl;
		std::cout << "bin_len_2_2_b: " << bin_len_2_2_b	<< std::endl;
		std::cout << "bin_len_2_3_a: " << bin_len_2_3_a	<< std::endl;
		std::cout << "bin_len_2_3_b: " << bin_len_2_3_b	<< std::endl;
		std::cout << "bin_len_3_0_a: " << bin_len_3_0_a	<< std::endl;
		std::cout << "bin_len_3_0_b: " << bin_len_3_0_b	<< std::endl;
		std::cout << "bin_len_3_1_a: " << bin_len_3_1_a	<< std::endl;
		std::cout << "bin_len_3_1_b: " << bin_len_3_1_b	<< std::endl;
		std::cout << "bin_len_3_2_a: " << bin_len_3_2_a	<< std::endl;
		std::cout << "bin_len_3_2_b: " << bin_len_3_2_b	<< std::endl;
		std::cout << "bin_len_3_3_a: " << bin_len_3_3_a	<< std::endl;
		std::cout << "bin_len_3_3_b: " << bin_len_3_3_b	<< std::endl;
		std::cout << "bin_len_4_0_a: " << bin_len_4_0_a	<< std::endl;
		std::cout << "bin_len_4_0_b: " << bin_len_4_0_b	<< std::endl;
		std::cout << "bin_len_4_1_a: " << bin_len_4_1_a	<< std::endl;
		std::cout << "bin_len_4_1_b: " << bin_len_4_1_b	<< std::endl;
		std::cout << "bin_len_4_2_a: " << bin_len_4_2_a	<< std::endl;
		std::cout << "bin_len_4_2_b: " << bin_len_4_2_b	<< std::endl;
		std::cout << "bin_len_4_3_a: " << bin_len_4_3_a	<< std::endl;
		std::cout << "bin_len_4_3_b: " << bin_len_4_3_b	<< std::endl;
		std::cout << "--------------" << std::endl;
		std::cout << "bin_ts_0_0_a: " << bin_ts_0_0_a	<< std::endl;
		std::cout << "bin_ts_0_0_b: " << bin_ts_0_0_b	<< std::endl;
		std::cout << "bin_ts_0_1_a: " << bin_ts_0_1_a	<< std::endl;
		std::cout << "bin_ts_0_1_b: " << bin_ts_0_1_b	<< std::endl;
		std::cout << "bin_ts_0_2_a: " << bin_ts_0_2_a	<< std::endl;
		std::cout << "bin_ts_0_2_b: " << bin_ts_0_2_b	<< std::endl;
		std::cout << "bin_ts_0_3_a: " << bin_ts_0_3_a	<< std::endl;
		std::cout << "bin_ts_0_3_b: " << bin_ts_0_3_b	<< std::endl;
		std::cout << "bin_ts_1_0_a: " << bin_ts_1_0_a	<< std::endl;
		std::cout << "bin_ts_1_0_b: " << bin_ts_1_0_b	<< std::endl;
		std::cout << "bin_ts_1_1_a: " << bin_ts_1_1_a	<< std::endl;
		std::cout << "bin_ts_1_1_b: " << bin_ts_1_1_b	<< std::endl;
		std::cout << "bin_ts_1_2_a: " << bin_ts_1_2_a	<< std::endl;
		std::cout << "bin_ts_1_2_b: " << bin_ts_1_2_b	<< std::endl;
		std::cout << "bin_ts_1_3_a: " << bin_ts_1_3_a	<< std::endl;
		std::cout << "bin_ts_1_3_b: " << bin_ts_1_3_b	<< std::endl;
		std::cout << "bin_ts_2_0_a: " << bin_ts_2_0_a	<< std::endl;
		std::cout << "bin_ts_2_0_b: " << bin_ts_2_0_b	<< std::endl;
		std::cout << "bin_ts_2_1_a: " << bin_ts_2_1_a	<< std::endl;
		std::cout << "bin_ts_2_1_b: " << bin_ts_2_1_b	<< std::endl;
		std::cout << "bin_ts_2_2_a: " << bin_ts_2_2_a	<< std::endl;
		std::cout << "bin_ts_2_2_b: " << bin_ts_2_2_b	<< std::endl;
		std::cout << "bin_ts_2_3_a: " << bin_ts_2_3_a	<< std::endl;
		std::cout << "bin_ts_2_3_b: " << bin_ts_2_3_b	<< std::endl;
		std::cout << "bin_ts_3_0_a: " << bin_ts_3_0_a	<< std::endl;
		std::cout << "bin_ts_3_0_b: " << bin_ts_3_0_b	<< std::endl;
		std::cout << "bin_ts_3_1_a: " << bin_ts_3_1_a	<< std::endl;
		std::cout << "bin_ts_3_1_b: " << bin_ts_3_1_b	<< std::endl;
		std::cout << "bin_ts_3_2_a: " << bin_ts_3_2_a	<< std::endl;
		std::cout << "bin_ts_3_2_b: " << bin_ts_3_2_b	<< std::endl;
		std::cout << "bin_ts_3_3_a: " << bin_ts_3_3_a	<< std::endl;
		std::cout << "bin_ts_3_3_b: " << bin_ts_3_3_b	<< std::endl;
		std::cout << "bin_ts_4_0_a: " << bin_ts_4_0_a	<< std::endl;
		std::cout << "bin_ts_4_0_b: " << bin_ts_4_0_b	<< std::endl;
		std::cout << "bin_ts_4_1_a: " << bin_ts_4_1_a	<< std::endl;
		std::cout << "bin_ts_4_1_b: " << bin_ts_4_1_b	<< std::endl;
		std::cout << "bin_ts_4_2_a: " << bin_ts_4_2_a	<< std::endl;
		std::cout << "bin_ts_4_2_b: " << bin_ts_4_2_b	<< std::endl;
		std::cout << "bin_ts_4_3_a: " << bin_ts_4_3_a	<< std::endl;
		std::cout << "bin_ts_4_3_b: " << bin_ts_4_3_b	<< std::endl;
		std::cout << "--------------" << std::endl;
	}
};

} // namespace hypervision
