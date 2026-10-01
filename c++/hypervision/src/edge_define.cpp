#include "edge_define.hpp"

using namespace hypervision;

void long_edge::show_edge(void) const {
	string saddr		= get_str_addr(tuple_get_src_addr(p_flow->flow_id));
	string daddr		= get_str_addr(tuple_get_dst_addr(p_flow->flow_id));
	pkt_port_t sp		= tuple_get_src_port(p_flow->flow_id);
	pkt_port_t dp		= tuple_get_dst_port(p_flow->flow_id);
	double_t ts_start	= p_flow->ts_start;
	double_t ts_end		= p_flow->ts_end;
	pkt_cnt_t cnt		= p_flow->cnt;
	pkt_len_t len		= p_flow->len;
}

auto long_edge::get_src_str() const -> string {
		return get_str_addr(std::get<0>(p_flow->flow_id));
}

auto long_edge::get_dst_str() const -> string {
		return get_str_addr(std::get<1>(p_flow->flow_id));
}

auto long_edge::is_huge_flow() const -> bool {
	if (p_flow->cnt > huge_flow_count_line || p_flow->len > huge_flow_byte_line) {
		return true;
	} else {
		return false;
	}
}

auto long_edge::get_avg_packet_rate() const -> double {
	return p_flow->cnt / (p_flow->ts_end - p_flow->ts_start);
}

auto long_edge::is_pulse_flow() const -> bool {
	if (get_avg_packet_rate() > pulse_flow_time_line ||
		p_flow->bin_len_num_pos < pulse_flow_ctr_line) {
		return true;
	} else {
		return false;
	}
}

auto long_edge::is_invalid_flow() const -> bool {
	if (p_flow->flag_syn > invalid_packet_line ||
		p_flow->flag_fin > invalid_packet_line ||
		p_flow->flag_rst > invalid_packet_line) {
			return true;
	}
	return false;
}

void short_edge::show_edge(size_t max_show) const {
	auto __get_agg_str = [] (const agg_code _ac) -> const string {
		ostringstream oss;
		for (size_t i = 0; i < 5; i ++)
			if ((_ac >> i) & 0x1) {
				oss << agg2name[i] << ' ';
			}
		return oss.str();
	};

	auto __get_type_str = [&] (const shared_ptr<flow> p_f) -> const string {
		u_int16_t type_code = 0;
		ostringstream oss;
		for (u_int8_t i = pkt_type_t::ICMP; i < pkt_type_t::UNKNOWN; ++i) {
			if (test_pkt_type_code(p_f->tp, (pkt_type_t) i)) {
				oss << type2name[i] << ' ';
				break;
			}
		}
		return oss.str();
	};

	string saddr				= get_str_addr(tuple_get_src_addr(p_flow->at(0)->flow_id));
	string daddr				= get_str_addr(tuple_get_dst_addr(p_flow->at(0)->flow_id));
	pkt_port_t sp				= tuple_get_src_port(p_flow->at(0)->flow_id);
	pkt_port_t dp				= tuple_get_dst_port(p_flow->at(0)->flow_id);
	const agg_code agg_idx		= get_agg_code();
	const string agg_str		= __get_agg_str(agg_idx);
	const string pkt_seq_str	= __get_type_str(p_flow->at(0));
	const size_t seq_len		= p_flow->at(0)->cnt;

	u_int32_t num_len	= 0;
	string str_saddr	= "---", str_daddr = "---", str_sp = "-", str_dp = "-";
	string str_agg		= __get_agg_str(agg_idx), str_type = __get_type_str(p_flow->at(0));

	shared_ptr<vector<string>>		p_ls_saddr, p_ls_daddr;
	shared_ptr<vector<pkt_port_t>>	p_ls_sp, p_ls_dp;
	vector<string>					ls_sp, ls_dp;

	p_ls_saddr = make_shared<vector<string> >();
	p_ls_daddr = make_shared<vector<string> >();

	if (is_no_agg(agg_idx)) {
		str_saddr = saddr;
		str_daddr = daddr;
	} else {
		if (is_src_agg(agg_idx)) {
			str_saddr = saddr;
		} else {
			p_ls_saddr = get_src_list();
		}

		if (is_dst_agg(agg_idx)) {
			str_daddr = daddr;
		} else {
			p_ls_daddr = get_dst_list();
		}
	}

	if (is_no_agg(agg_idx)) {
		str_sp = to_string(sp);
		str_dp = to_string(dp);
	} else {
		if (is_srcp_agg(agg_idx)) {
			str_sp = to_string(sp);
		} else {
			p_ls_sp = get_srcp_list();
			transform(p_ls_sp->begin(), p_ls_sp->end(), back_inserter(ls_sp),
					  [&](pkt_port_t t) -> string {return to_string(t);});
		}
		if (is_dstp_agg(agg_idx)) {
			str_dp = to_string(dp);
		} else {
			p_ls_dp = get_dstp_list();
			transform(p_ls_dp->begin(), p_ls_dp->end(), back_inserter(ls_dp),
								[&](pkt_port_t t) -> string {return to_string(t);});
		}
	}

	#ifdef DEBUG
		printf("[	%15s:%-6s -> %15s:%-6s ] => Agg Type: %s.\n",
			   str_saddr.c_str(), str_sp.c_str(), str_daddr.c_str(), str_dp.c_str(), str_agg.c_str());
	#endif

	if (!is_no_agg(agg_idx))
		for (size_t i = 0; i < get_agg_size(); i ++) {
			str_saddr	= i >= p_ls_saddr->size() ? "---" : p_ls_saddr->at(i);
			str_daddr	= i >= p_ls_daddr->size() ? "---" : p_ls_daddr->at(i);
			str_sp		= i >= ls_sp.size() ? "-" : ls_sp[i];
			str_dp		= i >= ls_dp.size() ? "-" : ls_dp[i];

			#ifdef DEBUG
				printf("[-| %15s:%-6s -> %15s:%-6s ]",
					   str_saddr.c_str(), str_sp.c_str(), str_daddr.c_str(), str_dp.c_str());
				printf(" [%s]\n", __get_type_str(p_flow->at(i)).c_str());
			#endif

			num_len ++;
			if (num_len == max_show) {
				#ifdef DEBUG
					printf("...... [%6ld lines in total]\n",
						   max(max(p_ls_saddr->size(), p_ls_daddr->size()), max(ls_sp.size(), ls_dp.size())) );
				#endif
				break;
			}
		}

	#ifdef DEBUG
		printf("[Seq. length]: %ld => [%s].\n\n", seq_len, pkt_seq_str.c_str());
	#endif
}

auto short_edge::get_src_list() const -> shared_ptr<vector<string>> {
	if (is_dst_agg(agg_indicator)) {
		const auto _ret = make_shared<vector<string>>();
		for (const auto& pf: *p_flow) {
			const auto p4 = dynamic_pointer_cast<flow>(pf);
			_ret->push_back(get_str_addr(tuple_get_src_addr(p4->flow_id)));
		}
		return _ret;
	} else {
		WARN("Get short edge src list without approperate aggregation.");
		return nullptr;
	}
}

auto short_edge::get_dst_list() const -> shared_ptr<vector<string>> {
	if (is_src_agg(agg_indicator)) {
		const auto _ret = make_shared<vector<string>>();
		for (const auto& pf: *p_flow) {
			const auto p4 = dynamic_pointer_cast<flow>(pf);
			_ret->push_back(get_str_addr(tuple_get_dst_addr(p4->flow_id)));
		}
		return _ret;
	} else {
		WARN("Get short edge dst list without approperate aggregation.");
		return nullptr;
	}
}

auto short_edge::get_dstp_list() const -> shared_ptr<vector<pkt_port_t>> {
	if (is_dstp_agg(agg_indicator)) {
		WARN("Get short edge dst port list with aggregation.");
		return nullptr;
	}

	const auto _ret = make_shared<vector<pkt_port_t>>();
	for (const auto& pf: *p_flow) {
		const auto p4 = dynamic_pointer_cast<flow>(pf);
		_ret->push_back(tuple_get_dst_port(p4->flow_id));
	}
	return _ret;
}

auto short_edge::get_srcp_list() const -> shared_ptr<vector<pkt_port_t>> {
	if (is_srcp_agg(agg_indicator)) {
		WARN("Get short edge src port list with aggregation.");
		return nullptr;
	}

	const auto _ret = make_shared<vector<pkt_port_t> >();
	for (const auto& pf: *p_flow) {
		const auto p4 = dynamic_pointer_cast<flow>(pf);
		_ret->push_back(tuple_get_src_port(p4->flow_id));
	}
	return _ret;
}

auto short_edge::get_time_range(void) const -> pair<double_t, double_t> {
	// pkt_ts_t start	= numeric_limits<pkt_ts_t>::max();
	// pkt_ts_t end	= numeric_limits<pkt_ts_t>::min();
	double start	= numeric_limits<double_t>::max();
	double end		= numeric_limits<double_t>::min();
	for (const auto& pf: *p_flow) {
		start	= min(start, pf->ts_start);
		end		= max(end, pf->ts_end);
	}
	return {start, end};
}

auto short_edge::get_src_str(void) const -> string {
	const auto p_f = p_flow->at(0);
	const auto pf4 = dynamic_pointer_cast<flow>(p_f);
	return get_str_addr(tuple_get_src_addr(pf4->flow_id));
}

auto short_edge::get_dst_str(void) const -> string {
	const auto p_f = p_flow->at(0);
	const auto pf4 = dynamic_pointer_cast<flow>(p_f);
	return get_str_addr(tuple_get_dst_addr(pf4->flow_id));
}
