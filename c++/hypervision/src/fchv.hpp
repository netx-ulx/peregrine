#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <array>
#include <stdexcept>

#include <bitset>
#include <cmath>

#include "sample.h"

#define EPS 1e-9
#define GET_DOUBLE_TS(x) (double) (x.tv_sec + x.tv_nsec*(1e-9))

class FCHv {
public:
	FCHv(const std::string& file_path, bool hv_dataset, double flow_timeout,
		 int sampl_rate, bool dp_sim);

	std::unordered_map<std::string, std::string> cur_pkt;

	std::array<std::string, 56>	hv_hdr;
	std::array<std::string, 40> hv_bin_len_hdr;
	std::array<std::string, 40>	hv_bin_ts_hdr;

	size_t trace_size();
	void parse_pcap(const std::string& pcap_path);
	int fe();
	int fe_hv();
	void process();
	int process_dp();
	int process_cp();
	void reg_read_end_dp(int a, int b, int c, int d);
	void reg_read_end_cp(int a, int b, int c, int d);
	hypervision::sample_t as_sample();

	std::vector<hypervision::sample_t> cur_samples;

private:
	std::string	file_path;
	bool		hv_dataset;
	int			sampl_rate;
	int			sampl_idx = 0;
	bool		dp_sim;
	bool		timeout_toggle;
	bool		timeout_toggle_a, timeout_toggle_b, timeout_toggle_c, timeout_toggle_d;
	double		timeout;
	double		cur_ts_interval;
	int			cur_idx, read_idx;
	long		hash_dp;
	std::string hash_cp;;
	int			read_idx_test_0;
	int			read_idx_test_1;
	int			read_idx_test_2;
	int			read_idx_test_3;
	int			read_idx_test_4;
	int			read_idx_test_5;
	int			read_idx_test_6;
	int			read_idx_test_7;
	int			read_idx_test_8;
	int			read_idx_test_9;

	int			flow_global_cnt;
	double		test_ts_interval;
	double		test_ts_interval_last;

	std::vector<std::vector<std::string>> df_csv;

	std::unordered_map<long, std::array<double, 3>>			reg_ts_dp[4];
	std::unordered_map<long, double>						reg_ts_agg_dp[4];
	std::unordered_map<long, std::array<std::string, 2>>	reg_ip_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_port_dp[4];
	std::unordered_map<long, std::array<uint32_t, 4>>		reg_flags_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_data_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_len_0_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_len_1_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_len_2_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_len_3_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_len_4_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_ts_0_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_ts_1_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_ts_2_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_ts_3_dp[4];
	std::unordered_map<long, std::array<uint32_t, 2>>		reg_bin_ts_4_dp[4];

	std::unordered_map<std::string, std::array<double, 3>>			reg_ts_cp[4];
	std::unordered_map<std::string, double>							reg_ts_agg_cp[4];
	std::unordered_map<std::string, std::array<std::string, 2>>		reg_ip_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_port_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 4>>		reg_flags_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_data_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_len_0_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_len_1_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_len_2_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_len_3_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_len_4_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_ts_0_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_ts_1_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_ts_2_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_ts_3_cp[4];
	std::unordered_map<std::string, std::array<uint32_t, 2>>		reg_bin_ts_4_cp[4];

	void check_csv();
	uint16_t crc16(const std::vector<uint8_t>& data, uint16_t initial = 0);
	uint32_t crc32(const std::vector<uint8_t>& data, uint32_t initial = 0xFFFFFFFF);
	void reg_update_dp(int a, int b, int c, int d);
	void reg_update_cp(int a);
	void reg_read_cp(int a, int b, int c, int d);
	void reset_regs_dp(int idx, long read_idx);
	void reset_regs_cp(int idx, std::string read_idx);
};
