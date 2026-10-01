#include <cstddef>
#include "fchv.hpp"
#include "hypervision.hpp"
#include "pkt_info.hpp"
#include "sample.h"

namespace hypervision {

std::atomic<bool> running(true);

std::unordered_map<uint8_t, uint32_t> dict_bin_ts = {
	{0, 16},
	{1, 32},
	{2, 48},
	{3, 64},
	{4, 80},
	{5, 96},
	{6, 112},
	{7, 128},
	{8, 144},
	{9, 160}
};

std::unordered_map<uint8_t, uint32_t> dict_bin_len = {
	{0, 256},
	{1, 512},
	{2, 768},
	{3, 1024},
	{4, 1280},
	{5, 1536},
	{6, 1792},
	{7, 2048},
	{8, 2304},
	{9, 2560}
};

void Hypervision::stream_dp() {
	interface = jin_main["stream_dp"]["interface"];
	Listener p_listener(interface);

	std::thread listener_thread(&Hypervision::listener, this, std::ref(p_listener));

	last_ts = std::chrono::steady_clock::now();
	while (true) {
		cur_ts				= std::chrono::steady_clock::now();
		auto elapsed_time	= std::chrono::duration_cast<std::chrono::seconds>(cur_ts - last_ts);

		if (elapsed_time.count() > max_time &&
					((cur_epoch == 0 && cur_cntr > 1) || cur_epoch > 0)) {
			std::cout << "elapsed time: "			<< elapsed_time.count() << std::endl;
			std::cout << "max time: "				<< max_time << std::endl;
			std::cout << "cur epoch: "				<< cur_epoch << std::endl;
			std::cout << "cur counter: "			<< cur_cntr << std::endl;
			std::cout << "Epoch "					<< std::to_string(cur_epoch)
					  << ": No samples received."	<< std::endl;
			running = false;
			listener_thread.join();
			exit(0);
		} else if (cur_cntr >= epoch_cntr) {
				std::cout << "Epoch "				<< std::to_string(cur_epoch)
						  << ": "					<< std::to_string(sampl_vec.size())
						  << " Samples received."	<< std::endl;
				sampl_vec_cur = sampl_vec;
				sampl_vec.clear();
				cur_epoch++;

				cur_cntr	= 0;
				last_ts		= cur_ts;
		} else {
			continue;
		}

		process_received_pkts();
		stream_graph();
	}
}

void Hypervision::stream_cp() {
	trace		= jin_main["stream_cp"]["trace"];
	hv_dataset	= jin_main["stream_cp"]["hv_dataset"];

	FCHv fc(trace, hv_dataset, flow_timeout, sampl_rate, dp_sim);

	size_t trace_size = fc.trace_size();

	std::cout << "Trace size: " << trace_size << std::endl;

	while (true) {
		pkt_cnt_global++;

		if (pkt_cnt_global % 10000 == 0) {
			std::cout << "Processed pkts: " << pkt_cnt_global << std::endl;
		}

		if (!hv_dataset) {
			trace_index = fc.fe();
		} else {
			trace_index = fc.fe_hv();
		}

		// Non-IP packet / nan fields.
		if (trace_index == 0) {
			continue;
		// Trace end.
		} else if ((size_t)trace_index == trace_size-1) {
			if (dp_sim) {
				fc.reg_read_end_dp(0, 1, 2, 3);
			} else {
				fc.reg_read_end_cp(0, 1, 2, 3);
			}
			std::vector<hypervision::sample_t> cur_sample_vec = fc.cur_samples;
			for (size_t i = 0; i < cur_sample_vec.size(); i++) {
				sampl_vec.push_back(cur_sample_vec[i]);
			}
			sampl_vec_cur = sampl_vec;
			process_received_pkts();
			stream_graph();
			break;
		} else if (trace_index == -1) {
			break;
		}

		int update_status = -1;
		if (dp_sim) {
			update_status = fc.process_dp();
		} else {
			update_status = fc.process_cp();
		}

		if (update_status == 0) {
			std::vector<hypervision::sample_t> cur_sample_vec = fc.cur_samples;

			for (size_t i = 0; i < cur_sample_vec.size(); i++) {
				sampl_vec.push_back(cur_sample_vec[i]);
				cur_cntr++;
			}

			fc.cur_samples.clear();

			if (cur_cntr >= epoch_cntr) {
				std::cout << "Epoch "				<< std::to_string(cur_epoch)
						  << ": "					<< std::to_string(sampl_vec.size())
						  << " Samples received."	<< std::endl;
				sampl_vec_cur = sampl_vec;
				sampl_vec.clear();
				cur_epoch++;
				cur_cntr = 0;
			} else {
				continue;
			}
		} else {
			continue;
		}

		process_received_pkts();
		stream_graph();
	}
}

void Hypervision::stream_graph() {
	#ifdef DEBUG
		LOGF("Construct edge.");
	#endif
	const auto p_edge_constructor = make_shared<edge_constructor>(parse_result);
	p_edge_constructor->config_via_json(jin_main["edge_construct"]);
	p_edge_constructor->do_construct();
	tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

	// PRINT SHORT EDGES
	// for (const auto &p_se: * p_short_edges) {
	//	std::cout << "----- Short edge -----" << std::endl;
	//	for (const auto &p_f: * p_se->p_flow) {
	//		std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
	//		std::cout	<< p_f->ts_start		<< ","
	//					<< p_f->ts_end			<< ","
	//					<< p_f->ts_agg			<< ","
	//					<< get_str_addr(tuple_get_src_addr(p_f->flow_id))	<< ","
	//					<< get_str_addr(tuple_get_dst_addr(p_f->flow_id))	<< ","
	//					<< p_f->proto			<< ","
	//					<< tuple_get_src_port(p_f->flow_id)		<< ","
	//					<< tuple_get_dst_port(p_f->flow_id)		<< ","
	//					<< p_f->flag_syn		<< ","
	//					<< p_f->flag_ack		<< ","
	//					<< p_f->flag_fin		<< ","
	//					<< p_f->flag_rst		<< ","
	//					<< p_f->cnt				<< ","
	//					<< p_f->len				<< ","
	//					<< p_f->flow_long		<< std::endl;
	//	}
	// }
	// PRINT LONG EDGES
	// for (const auto &p_le: * p_long_edges) {
	//	std::cout << "----- Long edge -----" << std::endl;
	//	std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
	//	std::cout	<< p_le->p_flow->ts_start		<< ","
	//				<< p_le->p_flow->ts_end			<< ","
	//				<< p_le->p_flow->ts_agg			<< ","
	//				<< get_str_addr(tuple_get_src_addr(p_le->p_flow->flow_id))	<< ","
	//				<< get_str_addr(tuple_get_dst_addr(p_le->p_flow->flow_id))	<< ","
	//				<< p_le->p_flow->proto			<< ","
	//				<< tuple_get_src_port(p_le->p_flow->flow_id)	<< ","
	//				<< tuple_get_dst_port(p_le->p_flow->flow_id)	<< ","
	//				<< p_le->p_flow->flag_syn		<< ","
	//				<< p_le->p_flow->flag_ack		<< ","
	//				<< p_le->p_flow->flag_fin		<< ","
	//				<< p_le->p_flow->flag_rst		<< ","
	//				<< p_le->p_flow->cnt			<< ","
	//				<< p_le->p_flow->len			<< ","
	//				<< p_le->p_flow->flow_long		<< std::endl;
	// }

	#ifdef DEBUG
		LOGF("Construct Graph.");
	#endif
	const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
	p_graph->config_via_json(jin_main["graph_analyze"]);
	p_graph->parse_edge();
	p_graph->dump_graph_statistic();
	p_graph->dump_vertex_anomly();
	#ifdef DEBUG
		LOGF("Graph Detect.");
	#endif
	p_graph->graph_detect();
	p_loss = p_graph->get_final_pkt_score();

	if (save_result_enable) {
		do_save_stream(save_result_name, save_result_path);
	}

	parse_result.clear();
}

void Hypervision::process_received_pkts(void) {
	for (size_t i = 0; i < sampl_vec_cur.size(); ++i) {
		double						ts_start;
		double						ts_end;
		double						ts_agg;
		pkt_addr4_t					ip_src, ip_dst;
		pkt_port_t					port_src, port_dst;
		pkt_proto_t					proto;
		uint32_t					proto_num = 0;
		uint16_t					proto_stack_code;
		pkt_cnt_t					cnt;
		pkt_len_t					len;
		pkt_code_t					code = 0;
		pkt_flag_t					flag_syn, flag_ack, flag_fin, flag_rst = 0;
		uint16_t					flow_long;
		std::vector<uint32_t>		bin_len(3, 0);
		uint32_t					bin_len_num_pos;
		std::vector<uint32_t>		bin_ts(3, 0);

		if (sampl_vec_cur.at(i).ts_start_0 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_0;
			ts_end		= sampl_vec_cur.at(i).ts_end_0;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_0;
			ip_src		= sampl_vec_cur.at(i).ip_src_0;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_0;
			proto		= sampl_vec_cur.at(i).proto_0;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_0);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).ack_0);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_0);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).rst_0);
			cnt			= sampl_vec_cur.at(i).cnt_0;
			len			= sampl_vec_cur.at(i).len_0;
			flow_long	= sampl_vec_cur.at(i).long_0;

			// std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
			// std::cout << ts_start	<< ","
			//		  << ts_end		<< ","
			//		  << ts_agg		<< ","
			//		  << htonl(ip_src)		<< ","
			//		  << htonl(ip_dst)		<< ","
			//		  << proto		<< ","
			//		  << port_src	<< ","
			//		  << port_dst	<< ","
			//		  << flag_syn	<< ","
			//		  << flag_ack	<< ","
			//		  << flag_fin	<< ","
			//		  << flag_rst	<< ","
			//		  << cnt		<< ","
			//		  << len		<< ","
			//		  << flow_long << std::endl;

			if (sampl_vec_cur.at(i).proto_0 == 1) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
				proto_num = cnt;
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_ICMP);
			} else if (sampl_vec_cur.at(i).proto_0 == 17) {
				set_pkt_type_code(code, pkt_type_t::UDP);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UDP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_0 == 6) {
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_TCP);
				if (flag_syn != 0) {
					code |= 17;
				}
				if (flag_ack != 0) {
					code |= 33;
				}
				if (flag_fin != 0) {
					code |= 65;
				}
				if (flag_rst != 0) {
					code |= 129;
				}
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					proto_num = flag_syn;
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					proto_num = flag_ack;
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					proto_num = flag_fin;
				} else {
					proto_num = flag_rst;
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UNKNOWN);
				proto_num = cnt;
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_0_a,
										   sampl_vec_cur.at(i).bin_len_0_0_b,
										   sampl_vec_cur.at(i).bin_len_1_0_a,
										   sampl_vec_cur.at(i).bin_len_1_0_b,
										   sampl_vec_cur.at(i).bin_len_2_0_a,
										   sampl_vec_cur.at(i).bin_len_2_0_b,
										   sampl_vec_cur.at(i).bin_len_3_0_a,
										   sampl_vec_cur.at(i).bin_len_3_0_b,
										   sampl_vec_cur.at(i).bin_len_4_0_a,
										   sampl_vec_cur.at(i).bin_len_4_0_b);
			bin_len[0] = bin_len_tmp[0];
			bin_len[1] = dict_bin_len[bin_len_tmp[1]];
			bin_len[2] = bin_len_tmp[2];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_0_a,
										  sampl_vec_cur.at(i).bin_ts_0_0_b,
										  sampl_vec_cur.at(i).bin_ts_1_0_a,
										  sampl_vec_cur.at(i).bin_ts_1_0_b,
										  sampl_vec_cur.at(i).bin_ts_2_0_a,
										  sampl_vec_cur.at(i).bin_ts_2_0_b,
										  sampl_vec_cur.at(i).bin_ts_3_0_a,
										  sampl_vec_cur.at(i).bin_ts_3_0_b,
										  sampl_vec_cur.at(i).bin_ts_4_0_a,
										  sampl_vec_cur.at(i).bin_ts_4_0_b);
			bin_ts[0] = bin_ts_tmp[0];
			bin_ts[1] = dict_bin_ts[bin_ts_tmp[1]];
			bin_ts[2] = bin_ts_tmp[2];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_0_a,
												sampl_vec_cur.at(i).bin_len_0_0_b,
												sampl_vec_cur.at(i).bin_len_1_0_a,
												sampl_vec_cur.at(i).bin_len_1_0_b,
												sampl_vec_cur.at(i).bin_len_2_0_a,
												sampl_vec_cur.at(i).bin_len_2_0_b,
												sampl_vec_cur.at(i).bin_len_3_0_a,
												sampl_vec_cur.at(i).bin_len_3_0_b,
												sampl_vec_cur.at(i).bin_len_4_0_a,
												sampl_vec_cur.at(i).bin_len_4_0_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, proto_stack_code, port_src,
								 port_dst, ts_start, ts_end, ts_agg, flag_syn, flag_ack, flag_fin,
								 flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos,
								 bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}

		if (sampl_vec_cur.at(i).ts_start_1 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_1;
			ts_end		= sampl_vec_cur.at(i).ts_end_1;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_1;
			ip_src		= sampl_vec_cur.at(i).ip_src_1;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_1;
			proto		= sampl_vec_cur.at(i).proto_1;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_1 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_1 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_1);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).ack_1);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_1);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).rst_1);
			cnt			= sampl_vec_cur.at(i).cnt_1;
			len			= sampl_vec_cur.at(i).len_1;
			flow_long	= sampl_vec_cur.at(i).long_1;

			if (sampl_vec_cur.at(i).proto_1 == 1) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
				proto_num = cnt;
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_ICMP);
			} else if (sampl_vec_cur.at(i).proto_1 == 17) {
				set_pkt_type_code(code, pkt_type_t::UDP);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UDP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_1 == 6) {
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_TCP);
				if (flag_syn != 0) {
					code |= 17;
				}
				if (flag_ack != 0) {
					code |= 33;
				}
				if (flag_fin != 0) {
					code |= 65;
				}
				if (flag_rst != 0) {
					code |= 129;
				}
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					proto_num = flag_syn;
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					proto_num = flag_ack;
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					proto_num = flag_fin;
				} else {
					proto_num = flag_rst;
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UNKNOWN);
				proto_num = cnt;
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_1_a,
										   sampl_vec_cur.at(i).bin_len_0_1_b,
										   sampl_vec_cur.at(i).bin_len_1_1_a,
										   sampl_vec_cur.at(i).bin_len_1_1_b,
										   sampl_vec_cur.at(i).bin_len_2_1_a,
										   sampl_vec_cur.at(i).bin_len_2_1_b,
										   sampl_vec_cur.at(i).bin_len_3_1_a,
										   sampl_vec_cur.at(i).bin_len_3_1_b,
										   sampl_vec_cur.at(i).bin_len_4_1_a,
										   sampl_vec_cur.at(i).bin_len_4_1_b);
			bin_len[0] = bin_len_tmp[0];
			bin_len[1] = dict_bin_len[bin_len_tmp[1]];
			bin_len[2] = bin_len_tmp[2];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_1_a,
										  sampl_vec_cur.at(i).bin_ts_0_1_b,
										  sampl_vec_cur.at(i).bin_ts_1_1_a,
										  sampl_vec_cur.at(i).bin_ts_1_1_b,
										  sampl_vec_cur.at(i).bin_ts_2_1_a,
										  sampl_vec_cur.at(i).bin_ts_2_1_b,
										  sampl_vec_cur.at(i).bin_ts_3_1_a,
										  sampl_vec_cur.at(i).bin_ts_3_1_b,
										  sampl_vec_cur.at(i).bin_ts_4_1_a,
										  sampl_vec_cur.at(i).bin_ts_4_1_b);
			bin_ts[0] = bin_ts_tmp[0];
			bin_ts[1] = dict_bin_ts[bin_ts_tmp[1]];
			bin_ts[2] = bin_ts_tmp[2];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_1_a,
												sampl_vec_cur.at(i).bin_len_0_1_b,
												sampl_vec_cur.at(i).bin_len_1_1_a,
												sampl_vec_cur.at(i).bin_len_1_1_b,
												sampl_vec_cur.at(i).bin_len_2_1_a,
												sampl_vec_cur.at(i).bin_len_2_1_b,
												sampl_vec_cur.at(i).bin_len_3_1_a,
												sampl_vec_cur.at(i).bin_len_3_1_b,
												sampl_vec_cur.at(i).bin_len_4_1_a,
												sampl_vec_cur.at(i).bin_len_4_1_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, proto_stack_code, port_src,
								 port_dst, ts_start, ts_end, ts_agg, flag_syn, flag_ack, flag_fin, flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos, bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}

		if (sampl_vec_cur.at(i).ts_start_2 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_2;
			ts_end		= sampl_vec_cur.at(i).ts_end_2;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_2;
			ip_src		= sampl_vec_cur.at(i).ip_src_2;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_2;
			proto		= sampl_vec_cur.at(i).proto_2;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_2 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_2 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_2);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).ack_2);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_2);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).rst_2);
			cnt			= sampl_vec_cur.at(i).cnt_2;
			len			= sampl_vec_cur.at(i).len_2;
			flow_long	= sampl_vec_cur.at(i).long_2;

			if (sampl_vec_cur.at(i).proto_2 == 1) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
				proto_num = cnt;
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_ICMP);
			} else if (sampl_vec_cur.at(i).proto_2 == 17) {
				set_pkt_type_code(code, pkt_type_t::UDP);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UDP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_2 == 6) {
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_TCP);
				if (flag_syn != 0) {
					code |= 17;
				}
				if (flag_ack != 0) {
					code |= 33;
				}
				if (flag_fin != 0) {
					code |= 65;
				}
				if (flag_rst != 0) {
					code |= 129;
				}
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					proto_num = flag_syn;
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					proto_num = flag_ack;
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					proto_num = flag_fin;
				} else {
					proto_num = flag_rst;
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UNKNOWN);
				proto_num = cnt;
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_2_a,
										   sampl_vec_cur.at(i).bin_len_0_2_b,
										   sampl_vec_cur.at(i).bin_len_1_2_a,
										   sampl_vec_cur.at(i).bin_len_1_2_b,
										   sampl_vec_cur.at(i).bin_len_2_2_a,
										   sampl_vec_cur.at(i).bin_len_2_2_b,
										   sampl_vec_cur.at(i).bin_len_3_2_a,
										   sampl_vec_cur.at(i).bin_len_3_2_b,
										   sampl_vec_cur.at(i).bin_len_4_2_a,
										   sampl_vec_cur.at(i).bin_len_4_2_b);
			bin_len[0] = bin_len_tmp[0];
			bin_len[1] = dict_bin_len[bin_len_tmp[1]];
			bin_len[2] = bin_len_tmp[2];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_2_a,
										  sampl_vec_cur.at(i).bin_ts_0_2_b,
										  sampl_vec_cur.at(i).bin_ts_1_2_a,
										  sampl_vec_cur.at(i).bin_ts_1_2_b,
										  sampl_vec_cur.at(i).bin_ts_2_2_a,
										  sampl_vec_cur.at(i).bin_ts_2_2_b,
										  sampl_vec_cur.at(i).bin_ts_3_2_a,
										  sampl_vec_cur.at(i).bin_ts_3_2_b,
										  sampl_vec_cur.at(i).bin_ts_4_2_a,
										  sampl_vec_cur.at(i).bin_ts_4_2_b);
			bin_ts[0] = bin_ts_tmp[0];
			bin_ts[1] = dict_bin_ts[bin_ts_tmp[1]];
			bin_ts[2] = bin_ts_tmp[2];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_2_a,
												sampl_vec_cur.at(i).bin_len_0_2_b,
												sampl_vec_cur.at(i).bin_len_1_2_a,
												sampl_vec_cur.at(i).bin_len_1_2_b,
												sampl_vec_cur.at(i).bin_len_2_2_a,
												sampl_vec_cur.at(i).bin_len_2_2_b,
												sampl_vec_cur.at(i).bin_len_3_2_a,
												sampl_vec_cur.at(i).bin_len_3_2_b,
												sampl_vec_cur.at(i).bin_len_4_2_a,
												sampl_vec_cur.at(i).bin_len_4_2_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, proto_stack_code, port_src,
								 port_dst, ts_start, ts_end, ts_agg, flag_syn, flag_ack, flag_fin,
								 flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos,
								 bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}

		if (sampl_vec_cur.at(i).ts_start_3 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_3;
			ts_end		= sampl_vec_cur.at(i).ts_end_3;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_3;
			ip_src		= sampl_vec_cur.at(i).ip_src_3;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_3;
			proto		= sampl_vec_cur.at(i).proto_3;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_3 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_3 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_3);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).ack_3);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_3);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).rst_3);
			cnt			= sampl_vec_cur.at(i).cnt_3;
			len			= sampl_vec_cur.at(i).len_3;
			flow_long	= sampl_vec_cur.at(i).long_3;

			if (sampl_vec_cur.at(i).proto_3 == 1) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
				proto_num = cnt;
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_ICMP);
			} else if (sampl_vec_cur.at(i).proto_3 == 17) {
				set_pkt_type_code(code, pkt_type_t::UDP);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UDP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_3 == 6) {
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_TCP);
				if (flag_syn != 0) {
					code |= 17;
				}
				if (flag_ack != 0) {
					code |= 33;
				}
				if (flag_fin != 0) {
					code |= 65;
				}
				if (flag_rst != 0) {
					code |= 129;
				}
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					proto_num = flag_syn;
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					proto_num = flag_ack;
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					proto_num = flag_fin;
				} else {
					proto_num = flag_rst;
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				proto_stack_code = get_pkt_stack_code(stack_type_t::F_UNKNOWN);
				proto_num = cnt;
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_3_a,
										   sampl_vec_cur.at(i).bin_len_0_3_b,
										   sampl_vec_cur.at(i).bin_len_1_3_a,
										   sampl_vec_cur.at(i).bin_len_1_3_b,
										   sampl_vec_cur.at(i).bin_len_2_3_a,
										   sampl_vec_cur.at(i).bin_len_2_3_b,
										   sampl_vec_cur.at(i).bin_len_3_3_a,
										   sampl_vec_cur.at(i).bin_len_3_3_b,
										   sampl_vec_cur.at(i).bin_len_4_3_a,
										   sampl_vec_cur.at(i).bin_len_4_3_b);
			bin_len[0] = bin_len_tmp[0];
			bin_len[1] = dict_bin_len[bin_len_tmp[1]];
			bin_len[2] = bin_len_tmp[2];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_3_a,
										  sampl_vec_cur.at(i).bin_ts_0_3_b,
										  sampl_vec_cur.at(i).bin_ts_1_3_a,
										  sampl_vec_cur.at(i).bin_ts_1_3_b,
										  sampl_vec_cur.at(i).bin_ts_2_3_a,
										  sampl_vec_cur.at(i).bin_ts_2_3_b,
										  sampl_vec_cur.at(i).bin_ts_3_3_a,
										  sampl_vec_cur.at(i).bin_ts_3_3_b,
										  sampl_vec_cur.at(i).bin_ts_4_3_a,
										  sampl_vec_cur.at(i).bin_ts_4_3_b);
			bin_ts[0] = bin_ts_tmp[0];
			bin_ts[1] = dict_bin_ts[bin_ts_tmp[1]];
			bin_ts[2] = bin_ts_tmp[2];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_3_a,
												sampl_vec_cur.at(i).bin_len_0_3_b,
												sampl_vec_cur.at(i).bin_len_1_3_a,
												sampl_vec_cur.at(i).bin_len_1_3_b,
												sampl_vec_cur.at(i).bin_len_2_3_a,
												sampl_vec_cur.at(i).bin_len_2_3_b,
												sampl_vec_cur.at(i).bin_len_3_3_a,
												sampl_vec_cur.at(i).bin_len_3_3_b,
												sampl_vec_cur.at(i).bin_len_4_3_a,
												sampl_vec_cur.at(i).bin_len_4_3_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, proto_stack_code, port_src,
								 port_dst, ts_start, ts_end, ts_agg, flag_syn, flag_ack, flag_fin,
								 flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos,
								 bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}
	}
}

template<typename... Args>
uint32_t Hypervision::greater_than_zero(Args... args) {
	uint32_t count = 0;
	((args > 0 ? ++count : count), ...);
	return count;
}

std::vector<uint32_t> Hypervision::val_and_num(uint32_t b0, uint32_t b1, uint32_t b2,
											   uint32_t b3, uint32_t b4, uint32_t b5,
											   uint32_t b6, uint32_t b7, uint32_t b8,
											   uint32_t b9) {
	uint32_t num		= b0;
	uint32_t val		= 0;
	uint32_t sum		= 0;
	uint32_t values[]	= {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9};

	for (uint32_t i = 0; i < 10; ++i) {
		if (values[i] > num) {
			num = values[i];
			val = i;
		}
		sum += values[i] * dict_bin_len[i];
	}

	std::vector <uint32_t> v = {num, val, sum};

	return v;
}

void Hypervision::listener(Listener& p_listener) {
	while (running) {
		auto p_sampl = p_listener.receive_sample();
		if (p_sampl.valid) {
			last_ts = cur_ts;
			cur_cntr++;
			sampl_vec.push_back(p_sampl);
		}
	}
}

void Hypervision::config_via_json(const nlohmann::json& jin) {
	try {
		if (
			(jin.count("stream_dp") || jin.count("stream_cp")) &&
			jin.count("edge_construct") &&
			jin.count("graph_analyze") &&
			jin.count("result_save")) {
				jin_main = jin;
			} else {
				throw logic_error("Incomplete json configuration.");
			}
			if (jin.count("stream_dp")) {
				const auto j_stream = jin["stream_dp"];
				if (j_stream.count("max_time")) {
					max_time = static_cast<decltype(max_time)>(j_stream["max_time"]);
				}
				if (j_stream.count("epoch_cntr")) {
					epoch_cntr = static_cast<decltype(epoch_cntr)>(j_stream["epoch_cntr"]);
				}
				if (j_stream.count("flow_timeout")) {
					flow_timeout = static_cast<decltype(flow_timeout)>(j_stream["flow_timeout"]);
				}
			} else if (jin.count("stream_cp")) {
				is_stream_cp = true;
				const auto j_stream = jin["stream_cp"];
				if (j_stream.count("dp_sim")) {
					dp_sim = static_cast<decltype(dp_sim)>(j_stream["dp_sim"]);
				}
				if (j_stream.count("epoch_cntr")) {
					epoch_cntr = static_cast<decltype(epoch_cntr)>(j_stream["epoch_cntr"]);
				}
				if (j_stream.count("sampl_rate")) {
					sampl_rate = static_cast<decltype(sampl_rate)>(j_stream["sampl_rate"]);
				}
				if (j_stream.count("flow_timeout")) {
					flow_timeout = static_cast<decltype(flow_timeout)>(j_stream["flow_timeout"]);
				}
			}
			const auto j_save	= jin["result_save"];
			if (j_save.count("save_result_enable")) {
				save_result_enable =
						static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
			}
			if (j_save.count("save_result_name")) {
				save_result_name =
						static_cast<decltype(save_result_name)>(j_save["save_result_name"]);
			}
			if (j_save.count("save_result_path")) {
				save_result_path =
						static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
			}
	} catch (const exception& e) {
		FATAL_ERROR(e.what());
	}
}

void Hypervision::do_save_stream(const string& save_name, const string& save_path) {
	std::string str_stream = "dp";
	std::string str_dp_sim = "";

	if (is_stream_cp) {
		str_stream = "cp";
	}
	if (dp_sim) {
		str_dp_sim = "-dp-sim-";
	}

	auto t	= std::time(nullptr);
	auto tm = *std::localtime(&t);
	std::ostringstream oss;
	oss << std::put_time(&tm, "-%Y-%m-%d-%H-%M-%S");
	auto str_ts = oss.str();

	std::string save = save_path + "/"
					   + save_name + "-"
					   + std::to_string(cur_epoch) + "-"
					   + str_stream
					   + str_dp_sim
					   + "timeout-" + std::to_string((int)(flow_timeout))
					   + "-sampl-" + std::to_string(sampl_rate)
					   + str_ts + ".csv";

	ofstream _f(save);
	if (_f.is_open()) {
		try {
			_f << setprecision(4);
			_f << "ip_src,ip_dst,proto,port_src,port_dst,cnt,loss,label" << '\n';
			for (size_t i = 0; i < p_loss->size(); ++i) {
					_f << p_loss->at(i)[0] << ','
					<< p_loss->at(i)[1] << ','
					<< p_loss->at(i)[2] << ','
					<< p_loss->at(i)[3] << ','
					<< p_loss->at(i)[4] << ','
					<< p_loss->at(i)[5] << ','
					<< p_loss->at(i)[6] << ','
					<< p_loss->at(i)[7] << '\n';
				if (i % 1000 == 0) {
					_f << flush;
				}
			}
			_f << flush;
		} catch (const exception& e) {
			FATAL_ERROR(e.what());
		}
		_f.close();
	}
}

}
