#pragma once

#include "common.hpp"
#include "pkt_info.hpp"

namespace hypervision {

struct flow {
	// pkt_ts_t				ts_start, ts_end, ts_agg;
	double					ts_start, ts_end, ts_agg;
	pkt_code_t				tp;
	pkt_proto_t				proto;
	uint32_t				proto_num;
	uint16_t				proto_stack_code;
	pkt_flag_t				flag_syn, flag_ack, flag_fin, flag_rst;
	pkt_cnt_t				cnt;
	pkt_len_t				len;
	uint16_t				flow_long;
	std::vector<uint32_t>	bin_len;
	uint32_t				bin_len_num_pos;
	std::vector<uint32_t>	bin_ts;
	tuple5_conn4			flow_id;
	flow() = default;
	explicit flow(const pkt_addr4_t s_IP,
				  const pkt_addr4_t d_IP,
				  const pkt_proto_t proto,
				  const uint32_t proto_num,
				  const uint16_t proto_stack_code,
				  const pkt_port_t s_port,
				  const pkt_port_t d_port,
				  const decltype(ts_start) ts_start,
				  const decltype(ts_end) ts_end,
				  const decltype(ts_agg) ts_agg,
				  const decltype(flag_syn) flag_syn,
				  const decltype(flag_ack) flag_ack,
				  const decltype(flag_fin) flag_fin,
				  const decltype(flag_rst) flag_rst,
				  const decltype(tp) tp,
				  const decltype(cnt) cnt,
				  const decltype(len) len,
				  const uint16_t flow_long,
				  const std::vector<uint32_t> bin_len,
				  const uint32_t bin_len_num_pos,
				  const std::vector<uint32_t> bin_ts):
				  ts_start(ts_start),
				  ts_end(ts_end),
				  ts_agg(ts_agg),
				  tp(tp),
				  proto(proto),
				  proto_num(proto_num),
				  proto_stack_code(proto_stack_code),
				  flag_syn(flag_syn),
				  flag_ack(flag_ack),
				  flag_fin(flag_fin),
				  flag_rst(flag_rst),
				  cnt(cnt),
				  len(len),
				  flow_long(flow_long),
				  bin_len(bin_len),
				  bin_len_num_pos(bin_len_num_pos),
				  bin_ts(bin_ts),
				  flow_id(s_IP, d_IP, s_port, d_port, proto_stack_code) {}

	virtual ~flow() {}
};

}
