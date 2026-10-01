#pragma once

#include "common.hpp"
#include "flow.hpp"
#include "pkt_info.hpp"

namespace hypervision {

class long_edge {
public:
	shared_ptr<flow> p_flow;
	long_edge(const decltype(p_flow) p_flow): p_flow(p_flow) {}
	virtual ~long_edge () {}
	long_edge(const long_edge &)			 = default;
	long_edge & operator=(const long_edge &) = default;


	inline auto get_raw_flow() const -> decltype(p_flow) {
		return p_flow;
	}

	constexpr static u_int32_t huge_flow_byte_line	= 5000 * 1024;
	constexpr static u_int32_t huge_flow_count_line = 8000;
	constexpr static double pulse_flow_time_line	= 50000;
	constexpr static double pulse_flow_ctr_line		= 2;
	constexpr static u_int32_t invalid_packet_line	= 10;

	auto get_avg_packet_rate() const	-> double;
	auto is_huge_flow() const			-> bool;
	auto is_pulse_flow() const			-> bool;
	auto is_invalid_flow() const		-> bool;

	void show_edge(void) const;

	auto get_src_str() const -> string;
	auto get_dst_str() const -> string;

	inline auto get_time_range(void) const -> pair<double_t, double_t> {
		return {p_flow->ts_start, p_flow->ts_end};
	}
};

using agg_code = u_int16_t;

enum agg_type: u_int8_t {
	SRC_AGG, DST_AGG, SRC_P_AGG, DST_P_AGG, NO_AGG
};

const vector<const char *> agg2name = {"SRC_AGG", "DST_AGG", "SRC_P_AGG", "DST_P_AGG", "NO_AGG"};

inline bool is_src_agg (const agg_code _gg) {
	return (_gg >> SRC_AGG) & 0x1;
}

inline bool is_dst_agg (const agg_code _gg) {
	return (_gg >> DST_AGG) & 0x1;
}

inline bool is_srcp_agg (const agg_code _gg) {
	return (_gg >> SRC_P_AGG) & 0x1;
}

inline bool is_dstp_agg (const agg_code _gg) {
	return (_gg >> DST_P_AGG) & 0x1;
}

inline bool is_no_agg (const agg_code _gg) {
	return (_gg >> NO_AGG) & 0x1;
}

inline void set_src_agg (agg_code & _gg) {
	_gg |= (1 << SRC_AGG);
}

inline void set_dst_agg (agg_code & _gg) {
	_gg |= (1 << DST_AGG);
}

inline void set_srcp_agg (agg_code & _gg) {
	_gg |= (1 << SRC_P_AGG);
}

inline void set_dstp_agg (agg_code & _gg) {
	_gg |= (1 << DST_P_AGG);
}

inline void set_no_agg (agg_code & _gg) {
	_gg = (1 << NO_AGG);
}

class short_edge {
private:
	agg_code agg_indicator;

public:
	shared_ptr<vector<shared_ptr<flow>>> p_flow;

	short_edge(const decltype(p_flow) p_flow, const decltype(agg_indicator) agg_indicator):
		agg_indicator(agg_indicator), p_flow(p_flow) {}

	virtual ~short_edge() {}
	short_edge(const short_edge &)				= default;
	short_edge & operator=(const short_edge &)	= default;

	static inline auto is_valid_typecode(agg_code _ac) -> bool {
		if ((_ac & (1 << NO_AGG)) && (_ac & (~(1 << NO_AGG))))
			return false;
		return true;
	}

	inline auto get_agg_code(void) const -> agg_code {
		return agg_indicator;
	}

	inline auto get_agg_size(void) const -> size_t {
		return p_flow->size();
	}

	inline auto get_time(void) const -> double_t {
		const auto p_f = p_flow->at(0);
		return p_f->ts_start;
	}

	auto get_time_range(void) const -> pair<double_t, double_t>;
	auto get_src_str(void) const	-> string;
	auto get_dst_str(void) const	-> string;

	auto get_avg_interval(void) const -> double_t {
		// std::cout << "ts_start: " << p_flow->at(0)->ts_start << std::endl;
		// std::cout << "cnt: " << p_flow->at(0)->cnt << std::endl;
		// std::cout << "agg: " << p_flow->at(0)->ts_agg << std::endl;
		// std::cout << "AVG INTERVAL: " << (p_flow->at(0)->ts_start * p_flow->at(0)->cnt + p_flow->at(0)->ts_agg) / p_flow->at(0)->cnt << std::endl;
		return (p_flow->at(0)->ts_start * (double) p_flow->at(0)->cnt + p_flow->at(0)->ts_agg) /
			(double) p_flow->at(0)->cnt;
	}

	auto get_flow_index(size_t id) const -> shared_ptr<flow> {
		return p_flow->at(id);
	}

	auto get_pkt_seq_size(void) const -> size_t {
		return p_flow->at(0)->cnt;
	}

	auto get_pkt_seq_code(void) const -> pkt_code_t {
		return p_flow->at(0)->tp;
	}

	auto get_src_list() const	-> shared_ptr<vector<string> >;
	auto get_dst_list() const	-> shared_ptr<vector<string> >;
	auto get_dstp_list() const	-> shared_ptr<vector<pkt_port_t> >;
	auto get_srcp_list() const	-> shared_ptr<vector<pkt_port_t> >;

	void show_edge(size_t max_show=5) const;
};

}
