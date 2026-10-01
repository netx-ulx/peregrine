#include "graph_define.hpp"

using namespace hypervision;

auto traffic_graph::__f_get_inout_degree(const addr_t addr) const -> pair<size_t, size_t> {
	size_t in_degree_ctr	= 0;
	size_t out_degree_ctr	= 0;

	if (short_edge_out.count(addr)) {
		out_degree_ctr += short_edge_out.at(addr).size();
	}
	if (short_edge_in.count(addr)) {
		in_degree_ctr += short_edge_in.at(addr).size();
	}
	if (short_edge_out_agg.count(addr)) {
		for (const auto index: short_edge_out_agg.at(addr)) {
			assert(is_src_agg(p_short_edge->at(index)->get_agg_code()));
			out_degree_ctr += p_short_edge->at(index)->get_agg_size();
		}
	}
	if (short_edge_in_agg.count(addr)) {
		for (const auto index: short_edge_in_agg.at(addr)) {
			assert(is_dst_agg(p_short_edge->at(index)->get_agg_code()));
			in_degree_ctr += p_short_edge->at(index)->get_agg_size();
		}
	}

	return {in_degree_ctr, out_degree_ctr};
}

auto traffic_graph::_f_exeract_feature_short(const size_t index) const -> feature_t {
	const auto p_e			= p_short_edge->at(index);
	const auto _saddr		= p_e->get_src_str();
	const auto _daddr		= p_e->get_dst_str();
	const auto _agg_code	= p_e->get_agg_code();

	const auto src_degree = __f_get_inout_degree(_saddr);
	const auto dst_degree = __f_get_inout_degree(_daddr);

	feature_t ret = {
		(double_t) is_src_agg(_agg_code),
		(double_t) is_srcp_agg(_agg_code),
		(double_t) is_dst_agg(_agg_code),
		(double_t) is_dstp_agg(_agg_code),
		(double_t) src_degree.first,
		(double_t) src_degree.second,
		(double_t) dst_degree.first,
		(double_t) dst_degree.second,
	};

	if (proto_cluster) {
		ret.push_back((double) p_e->get_pkt_seq_code());
	}

	// std::cout << "----- Short edge -----" << std::endl;
	// std::cout << "f0,f1,f2,f3,f4,f5,f6,f7,f8" << std::endl;
	// std::cout	<< (double_t) is_src_agg(_agg_code) << ","
	// 			<< (double_t) is_srcp_agg(_agg_code) << ","
	// 			<< (double_t) is_dst_agg(_agg_code) << ","
	// 			<< (double_t) is_dstp_agg(_agg_code) << ","
	// 			<< (double_t) src_degree.first << ","
	// 			<< (double_t) src_degree.second << ","
	// 			<< (double_t) dst_degree.first << ","
	// 			<< (double_t) dst_degree.second << ","
	// 			<< (double_t) p_e->get_pkt_seq_code()
	// 			<< std::endl;
	// for (const auto &p_f: * p_e->p_flow) {
	// 	std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
	// 	std::cout	<< p_f->ts_start		<< ","
	// 				<< p_f->ts_end			<< ","
	// 				<< p_f->ts_agg			<< ","
	// 				<< get_str_addr(tuple_get_src_addr(p_f->flow_id))	<< ","
	// 				<< get_str_addr(tuple_get_dst_addr(p_f->flow_id))	<< ","
	// 				<< p_f->proto			<< ","
	// 				<< tuple_get_src_port(p_f->flow_id)		<< ","
	// 				<< tuple_get_dst_port(p_f->flow_id)		<< ","
	// 				<< p_f->flag_syn		<< ","
	// 				<< p_f->flag_ack		<< ","
	// 				<< p_f->flag_fin		<< ","
	// 				<< p_f->flag_rst		<< ","
	// 				<< p_f->cnt				<< ","
	// 				<< p_f->len				<< ","
	// 				<< p_f->flow_long		<< std::endl;
	// }

	return ret;
};

auto traffic_graph::_f_exeract_feature_short2(const size_t index) const -> feature_t {
	const auto p_e			= p_short_edge->at(index);
	const auto _saddr		= p_e->get_src_str();
	const auto _daddr		= p_e->get_dst_str();
	const auto _agg_code	= p_e->get_agg_code();

	const auto src_degree = __f_get_inout_degree(_saddr);
	const auto dst_degree = __f_get_inout_degree(_daddr);

	// std::cout << "----- Short edge 2 -----" << std::endl;
	// std::cout << "f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11" << std::endl;
	// std::cout	<< (double_t) is_src_agg(_agg_code) << ","
	// 			<< (double_t) is_srcp_agg(_agg_code) << ","
	// 			<< (double_t) is_dst_agg(_agg_code) << ","
	// 			<< (double_t) is_dstp_agg(_agg_code) << ","
	// 			<< (double_t) src_degree.first << ","
	// 			<< (double_t) src_degree.second << ","
	// 			<< (double_t) dst_degree.first << ","
	// 			<< (double_t) dst_degree.second << ","
	// 			<< (double_t) p_e->get_agg_size() << ","
	// 			<< (double_t) p_e->get_pkt_seq_size() << ","
	// 			<< (double_t) p_e->get_agg_code() << ","
	// 			<< (double_t) p_e->get_avg_interval()
	// 			<< std::endl;
	// for (const auto &p_f: * p_e->p_flow) {
	// 	std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
	// 	std::cout	<< p_f->ts_start		<< ","
	// 				<< p_f->ts_end			<< ","
	// 				<< p_f->ts_agg			<< ","
	// 				<< get_str_addr(tuple_get_src_addr(p_f->flow_id))	<< ","
	// 				<< get_str_addr(tuple_get_dst_addr(p_f->flow_id))	<< ","
	// 				<< p_f->proto			<< ","
	// 				<< tuple_get_src_port(p_f->flow_id)		<< ","
	// 				<< tuple_get_dst_port(p_f->flow_id)		<< ","
	// 				<< p_f->flag_syn		<< ","
	// 				<< p_f->flag_ack		<< ","
	// 				<< p_f->flag_fin		<< ","
	// 				<< p_f->flag_rst		<< ","
	// 				<< p_f->cnt				<< ","
	// 				<< p_f->len				<< ","
	// 				<< p_f->flow_long		<< std::endl;
	// }

	return {
		(double_t) is_src_agg(_agg_code),
		(double_t) is_srcp_agg(_agg_code),
		(double_t) is_dst_agg(_agg_code),
		(double_t) is_dstp_agg(_agg_code),

		(double_t) src_degree.first,
		(double_t) src_degree.second,
		(double_t) dst_degree.first,
		(double_t) dst_degree.second,

		(double_t) p_e->get_agg_size(),
		(double_t) p_e->get_pkt_seq_size(),
		(double_t) p_e->get_agg_code(),
		(double_t) p_e->get_avg_interval(),
	};
};

auto traffic_graph::_f_exeract_feature_long(const size_t index) const -> feature_t {
	const auto & p_e	= p_long_edge->at(index);
	const auto & _saddr = p_e->get_src_str();
	const auto & _daddr = p_e->get_dst_str();

	feature_t ret = {
		long_edge_out.count(_saddr) ? (double) long_edge_out.at(_saddr).size() : 0.0,
		long_edge_in.count(_saddr) ? (double) long_edge_in.at(_saddr).size() : 0.0,
		long_edge_out.count(_daddr) ? (double) long_edge_out.at(_daddr).size() : 0.0,
		long_edge_in.count(_daddr) ? (double) long_edge_in.at(_daddr).size() : 0.0,
	};

	if (proto_cluster) {
		ret.push_back((double) p_e->get_raw_flow()->tp);
	}

	auto f0 = long_edge_out.count(_saddr) ? (double) long_edge_out.at(_saddr).size() : 0.0;
	auto f1 = long_edge_in.count(_saddr) ? (double) long_edge_in.at(_saddr).size() : 0.0;
	auto f2 = long_edge_out.count(_daddr) ? (double) long_edge_out.at(_daddr).size() : 0.0;
	auto f3 = long_edge_in.count(_daddr) ? (double) long_edge_in.at(_daddr).size() : 0.0;

	// std::cout << "----- Long edge -----" << std::endl;
	// std::cout << "f0,f1,f2,f3,f4" << std::endl;
	// std::cout	<< f0 << ","
	// 			<< f1 << ","
	// 			<< f2 << ","
	// 			<< f3 << ","
	// 			<< (double_t) p_e->get_raw_flow()->tp
	// 			<< std::endl;
	// std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
	// std::cout	<< p_e->p_flow->ts_start		<< ","
	// 			<< p_e->p_flow->ts_end			<< ","
	// 			<< p_e->p_flow->ts_agg			<< ","
	// 			<< get_str_addr(tuple_get_src_addr(p_e->p_flow->flow_id))	<< ","
	// 			<< get_str_addr(tuple_get_dst_addr(p_e->p_flow->flow_id))	<< ","
	// 			<< p_e->p_flow->proto			<< ","
	// 			<< tuple_get_src_port(p_e->p_flow->flow_id)	<< ","
	// 			<< tuple_get_dst_port(p_e->p_flow->flow_id)	<< ","
	// 			<< p_e->p_flow->flag_syn		<< ","
	// 			<< p_e->p_flow->flag_ack		<< ","
	// 			<< p_e->p_flow->flag_fin		<< ","
	// 			<< p_e->p_flow->flag_rst		<< ","
	// 			<< p_e->p_flow->cnt			<< ","
	// 			<< p_e->p_flow->len			<< ","
	// 			<< p_e->p_flow->flow_long		<< std::endl;

	return ret;
};

auto traffic_graph::_f_exeract_feature_long2(const size_t idx) const -> feature_t {
	const auto & p_e		= p_long_edge->at(idx);
	const auto & _saddr		= p_e->get_src_str();
	const auto & _daddr		= p_e->get_dst_str();
	const auto & _time_pair = p_e->get_time_range();

		auto f0 = long_edge_out.count(_saddr) ? (double) long_edge_out.at(_saddr).size() : 0.0;
		auto f1 = long_edge_in.count(_saddr) ? (double) long_edge_in.at(_saddr).size() : 0.0;
		auto f2 = long_edge_out.count(_daddr) ? (double) long_edge_out.at(_daddr).size() : 0.0;
		auto f3 = long_edge_in.count(_daddr) ? (double) long_edge_in.at(_daddr).size() : 0.0;

		// std::cout << "----- Long edge 2 -----" << std::endl;
		// std::cout << "f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11" << std::endl;
		// std::cout	<< f0 << ","
		// 			<< f1 << ","
		// 			<< f2 << ","
		// 			<< f3 << ","
		// 			<< (double_t) p_e->p_flow->tp << ","
		// 			<< (double_t) p_e->p_flow->proto_num << ","
		// 			<< (double_t) p_e->p_flow->bin_len[1] << ","
		// 			<< (double_t) p_e->p_flow->bin_len[0] << ","
		// 			<< (double_t) p_e->p_flow->cnt << ","
		// 			<< (double_t) p_e->p_flow->ts_end - (double_t) p_e->p_flow->ts_start << ","
		// 			<< (double_t) p_e->get_avg_packet_rate()
		// 			<< std::endl;
		// std::cout << "ts_start,ts_end,ts_agg,ip_src,ip_dst,ip_proto,port_src,port_dst,tcp_syn,tcp_ack,tcp_fin,tcp_rst,cnt,len,long" << std::endl;
		// std::cout	<< p_e->p_flow->ts_start		<< ","
		// 			<< p_e->p_flow->ts_end			<< ","
		// 			<< p_e->p_flow->ts_agg			<< ","
		// 			<< get_str_addr(tuple_get_src_addr(p_e->p_flow->flow_id))	<< ","
		// 			<< get_str_addr(tuple_get_dst_addr(p_e->p_flow->flow_id))	<< ","
		// 			<< p_e->p_flow->proto			<< ","
		// 			<< tuple_get_src_port(p_e->p_flow->flow_id)	<< ","
		// 			<< tuple_get_dst_port(p_e->p_flow->flow_id)	<< ","
		// 			<< p_e->p_flow->flag_syn		<< ","
		// 			<< p_e->p_flow->flag_ack		<< ","
		// 			<< p_e->p_flow->flag_fin		<< ","
		// 			<< p_e->p_flow->flag_rst		<< ","
		// 			<< p_e->p_flow->cnt			<< ","
		// 			<< p_e->p_flow->len			<< ","
		// 			<< p_e->p_flow->flow_long		<< std::endl;

	return {
		long_edge_out.count(_saddr) ? (double) long_edge_out.at(_saddr).size() : 0.0,
		long_edge_in.count(_saddr) ? (double) long_edge_in.at(_saddr).size() : 0.0,
		long_edge_out.count(_daddr) ? (double) long_edge_out.at(_daddr).size() : 0.0,
		long_edge_in.count(_daddr) ? (double) long_edge_in.at(_daddr).size() : 0.0,

		// Protocol associated with the max bin size
		(double_t) p_e->p_flow->tp,
		// Max bin size (fitting protocol distribution)
		(double_t) p_e->p_flow->proto_num,
		// Length associated with the max bin size
		(double_t) p_e->p_flow->bin_len[1],
		// Max bin size (fitting packet length distribution)
		(double_t) p_e->p_flow->bin_len[0],
		// Number of packets in the long flow
		(double_t) p_e->p_flow->cnt,
		// Flow completion time
		// (double_t) p_e->p_flow->ts_end,
		(double_t) p_e->p_flow->ts_end - (double_t) p_e->p_flow->ts_start,
		// Packet rate of the long flow
		(double_t) p_e->get_avg_packet_rate()
	};
};

auto traffic_graph::__f_trans_armadillo_mat_T(const vector<feature_t> & mx) -> arma::mat {
	size_t x_len = mx.size();
	size_t y_len = mx[0].size();
	arma::mat mxt(y_len, x_len , arma::fill::randu);

	for (size_t i = 0; i < x_len; i ++) {
		for (size_t j = 0; j < y_len; j ++) {
			mxt(j, i) = mx[i][j];
		}
	}

	return mxt;
}

void traffic_graph::_acquire_edge_index(const vector<addr_t> & addr_ls,
										unordered_set<size_t> & _long_index,
										unordered_set<size_t> & _short_index) {
	for (const addr_t& addr: addr_ls) {
		if (long_edge_out.count(addr)){
			const auto & __index_ls = long_edge_out.at(addr);
			_long_index.insert(cbegin(__index_ls), cend(__index_ls));
		}
		if (short_edge_out.count(addr)) {
			const auto & __index_ls = short_edge_out.at(addr);
			_short_index.insert(cbegin(__index_ls), cend(__index_ls));
		}
		if (short_edge_out_agg.count(addr)) {
			const auto & __index_ls = short_edge_out_agg.at(addr);
			_short_index.insert(cbegin(__index_ls), cend(__index_ls));
		}
		if (short_edge_in_agg.count(addr)) {
			const auto & __index_ls = short_edge_in_agg.at(addr);
			_short_index.insert(cbegin(__index_ls), cend(__index_ls));
		}
	}
}

auto traffic_graph::_pre_process_short(const unordered_set<size_t> & _short_index,
									   arma::mat & dataset_short,
									   arma::mat & centroids_short,
									   arma::Row<size_t> & assignments_short) -> size_t {
	vector<feature_t> short_feature;
	for (const auto index: _short_index) {
		short_feature.push_back(_f_exeract_feature_short(index));
	}

	dataset_short = __f_trans_armadillo_mat_T(short_feature);

	mlpack::data::MinMaxScaler scale_short;
	scale_short.Fit(dataset_short);
	decltype(dataset_short) short_pre_norm_feature = dataset_short;
	scale_short.Transform(short_pre_norm_feature, dataset_short);

	mlpack::dbscan::DBSCAN<> k_short(us, vs);
	k_short.Cluster<arma::mat>(dataset_short, assignments_short, centroids_short);

	#ifdef DISP_PRE_CLUSTER_SHORT
		size_t c0 = 0;
		size_t c1 = 0;
		for (const auto ve: assignments_short) {
			if (ve != SIZE_MAX) {
				c1 = c1 > ve ? c1 : ve;
			}
		}
		for (size_t j = 0; j < centroids_short.size(); j ++) {
			// printf("[----------- CLuster Number %d ---------]\n", j);
			int i = 0;
			for(const auto & index: _short_index) {
				if (assignments_short[i] == j) {
					p_short_edge->at(index)->show_edge();
					++ c0;
					++ i;
				}
			}
			// printf("[----------- %d Edges in Cluster ---------]\n\n", i);
		}
		// printf("[Number of edge in cluster: %d]\n", c0);
		// printf("[Number of aggregated cluster: %d]\n", c1);
	#endif

	size_t ret = 0;
	for (const auto ve: assignments_short) {
		if (ve != SIZE_MAX) {
			ret = ret > ve ? ret : ve;
		}
	}
	return ret;
}

auto traffic_graph::_pre_process_long(const unordered_set<size_t> & _long_index,
									  arma::mat & centroids_long,
									  arma::Row<size_t> & assignments_long) -> size_t {
	vector<feature_t> long_feature;
	for (const auto index: _long_index) {
		long_feature.push_back(_f_exeract_feature_long(index));
	}

	auto dataset_long = __f_trans_armadillo_mat_T(long_feature);

	mlpack::data::MinMaxScaler scale_long;
	scale_long.Fit(dataset_long);
	decltype(dataset_long) long_pre_norm_feature = dataset_long;
	scale_long.Transform(long_pre_norm_feature, dataset_long);

	mlpack::dbscan::DBSCAN<> k_long(ul, vl);
	k_long.Cluster<arma::mat>(dataset_long, assignments_long, centroids_long);

	#ifdef DISP_PRE_CLUSTER_LONG
		size_t ctr	= 0;
		size_t ctr1	= 0;
		for (const auto ve: assignments_long) {
			if (ve != SIZE_MAX) {
				ctr1 = ctr1 > ve ? ctr1 : ve;
			}
		}
		for (size_t j = 0; j < centroids_long.size(); j ++) {
			// printf("------------- CLuster Number %d ---------\n", j);
			int i = 0;
			for(const auto & index: _long_index) {
				if (assignments_long[i] == j) {
					p_long_edge->at(index)->show_edge();
					++ ctr;
				}
				++ i;
			}
		}
		// printf("Number of edge in cluster: %d\n", ctr);
		// printf("Number of aggregated cluster: %d\n", ctr1);
	#endif

	size_t ret = 0;
	for (const auto ve: assignments_long) {
		if (ve != SIZE_MAX) {
			ret = ret > ve ? ret : ve;
		}
	}
	return ret;
}
