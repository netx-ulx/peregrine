#pragma once

#include <atomic>
#include <thread>
#include <vector>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

#include "edge_constructor.hpp"
#include "flow.hpp"
#include "graph_define.hpp"
#include "listener.hpp"
#include "pkt_info.hpp"

namespace hypervision {

class Hypervision {

private:
	nlohmann::json			jin_main;
	string file_path		= "";
	string interface		= "";
	string trace			= "";
	string dataset			= "";
	bool hv_dataset			= false;
	bool dp_sim				= false;
	bool is_stream_cp		= false;
	int epoch_cntr			= 0;
	int sampl_rate			= 0;
	double flow_timeout		= 0.0;
	int cur_cntr			= 0;
	int cur_epoch			= 0;
	int empty_epoch_cntr	= 0;
	int pkt_cnt_global		= 0;
	int trace_index			= 0;

	std::chrono::time_point<std::chrono::steady_clock> cur_ts, last_ts;

	shared_ptr<vector<shared_ptr<flow>>>		p_parse_result;
	vector<shared_ptr<flow>>					parse_result;
	vector<sample_t>							sampl_vec, sampl_vec_cur;
	shared_ptr<vector<sample_t>>				p_sampl_vec;
	shared_ptr<vector<vector<std::string>>>		p_loss;
	shared_ptr<vector<shared_ptr<short_edge>>>	p_short_edges;
	shared_ptr<vector<shared_ptr<long_edge>>>	p_long_edges;

	bool save_result_enable = false;
	string save_result_name = "";
	string save_result_path = "";

	// Max time to wait for incoming packets before terminating.
	long max_time			= 0;

public:
	void stream_dp(void);
	void stream_cp(void);
	void stream_graph(void);
	void process_received_pkts(void);

	template<typename... Args>
	uint32_t greater_than_zero(Args... args);

	std::vector<uint32_t> val_and_num(uint32_t b0, uint32_t b1, uint32_t b2, uint32_t b3,
									  uint32_t b4, uint32_t b5, uint32_t b6, uint32_t b7,
									  uint32_t b8, uint32_t b9);

	void listener(Listener& p_listener);
	void config_via_json(const nlohmann::json& jin);
	void do_save_stream(const string& save_name, const string& save_path);
};

extern std::atomic<bool> running;

}
