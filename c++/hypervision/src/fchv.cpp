#include <iostream>
#include <filesystem>
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
#include <cstdlib>

#include <cstdlib>
#include <chrono>
#include <thread>

#include "fchv.hpp"

FCHv::FCHv(const std::string& file_path, bool hv_dataset, double flow_timeout,
		   int sampl_rate, bool dp_sim):
			file_path(file_path), hv_dataset(hv_dataset), sampl_rate(sampl_rate), dp_sim(dp_sim),
			timeout_toggle_a(false), timeout_toggle_b(false), timeout_toggle_c(false),
			timeout_toggle_d(false), timeout(flow_timeout), cur_idx(0), read_idx(0), hash_dp(0), hash_cp(""), flow_global_cnt(0), test_ts_interval(0), test_ts_interval_last(0) {
	hv_hdr.fill("");
	hv_bin_len_hdr.fill("");
	hv_bin_ts_hdr.fill("");
	check_csv();
}

size_t FCHv::trace_size() {
	return df_csv.size();
}

void FCHv::parse_pcap(const std::string& pcap_path) {
	std::string cmd = "tshark -r " + pcap_path + " -T fields "
						"-e frame.time_epoch -e ip.len -e ip.src -e ip.dst "
						"-e ip.proto -e tcp.srcport -e tcp.dstport "
						"-e udp.srcport -e udp.dstport "
						"-e tcp.flags.syn -e tcp.flags.ack "
						"-e tcp.flags.fin -e tcp.flags.reset "
						"-E separator=, -E header=y -E occurrence=f > " +
						file_path.substr(0, file_path.find_last_of('.')) + "-hv.csv";

	std::cout << "Parsing pcap file to csv." << std::endl;
	if (system(cmd.c_str()) == -1) {
		std::cerr << "Error: the parsing attempt failed." << std::endl;
		exit(EXIT_FAILURE);
	}
}

void FCHv::check_csv() {
	std::string csv_file_path = file_path.substr(0, file_path.find_last_of('.')) + "-hv.csv";
	struct stat buffer;

	std::cout << csv_file_path << std::endl;

	if (!std::filesystem::exists(csv_file_path)) {
		if (!hv_dataset) {
			std::cout << "No csv file available." << std::endl;
			parse_pcap(file_path);
		} else {
			std::cerr << "Error: the current trace requires a csv file." << std::endl;
			std::cerr << "Current trace file: " << csv_file_path << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	std::ifstream file(csv_file_path);
	std::string line;

	while (std::getline(file, line)) {
		std::stringstream ss(line);
		std::string item;
		std::vector<std::string> row;

		while (std::getline(ss, item, ',')) {
			row.push_back(item);
		}

		df_csv.push_back(row);
	}
}

int FCHv::fe() {
	std::string ts, pkt_len, ip_src, ip_dst, ip_proto	= "";
	std::string tcp_syn, tcp_ack, tcp_fin, tcp_rst		= "";
	std::string port_src, port_dst						=  "0";

	try {
		ts			= df_csv.at(cur_idx).at(0);
		pkt_len		= df_csv.at(cur_idx).at(1);
		ip_src		= df_csv.at(cur_idx).at(2);
		ip_dst		= df_csv.at(cur_idx).at(3);
		ip_proto	= df_csv.at(cur_idx).at(4);

		if (ip_proto == "17") {
			port_src = df_csv.at(cur_idx).at(7);
			port_dst = df_csv.at(cur_idx).at(8);
		} else if (ip_proto == "6") {
			port_src	= df_csv.at(cur_idx).at(5);
			port_dst	= df_csv.at(cur_idx).at(6);
			tcp_syn		= df_csv.at(cur_idx).at(9);
			tcp_ack		= df_csv.at(cur_idx).at(10);
			tcp_fin		= df_csv.at(cur_idx).at(11);
			tcp_rst		= df_csv.at(cur_idx).at(12);
		} else if (ip_proto == "1") {
			port_src = "0";
			port_dst = "0";
		} else {
			cur_pkt.clear();
			cur_idx++;
			return 0;
		}
	} catch (const std::out_of_range&) {
		return -1;
	} catch (const std::invalid_argument&) {
		return -1;
	}

	if (ip_src == "" || ip_dst == "" || ip_proto == "") {
		cur_pkt.clear();
		cur_idx++;
		return 0;
	}

	if (port_src == "" || port_dst == "") {
		cur_pkt.clear();
		cur_idx++;
		return 0;
	}

	if (pkt_len == "") {
		pkt_len = "0";
	}


	cur_idx++;

	cur_pkt["len"]		= pkt_len;
	cur_pkt["ts"]		= ts;
	cur_pkt["ip_src"]	= ip_src;
	cur_pkt["ip_dst"]	= ip_dst;
	cur_pkt["ip_proto"] = ip_proto;
	cur_pkt["port_src"] = port_src;
	cur_pkt["port_dst"] = port_dst;
	cur_pkt["tcp_syn"]	= tcp_syn;
	cur_pkt["tcp_ack"]	= tcp_ack;
	cur_pkt["tcp_fin"]	= tcp_fin;
	cur_pkt["tcp_rst"]	= tcp_rst;

	return cur_idx;
}

int FCHv::fe_hv() {
	double ts_tmp										= 0;
	std::string ts, pkt_len, ip_src, ip_dst, ip_proto	= "";
	std::string tcp_syn, tcp_ack, tcp_fin, tcp_rst		= "";
	std::string port_src, port_dst						= "0";

	try {
		ts_tmp	= std::stod(df_csv.at(cur_idx).at(5));
		ts_tmp	= ts_tmp * (double) 0.000001;
		ts		= std::to_string(ts_tmp);

		// Skip the current pkt if IPv6.
		if (df_csv.at(cur_idx).at(0) == "6") {
			cur_pkt.clear();
			cur_idx++;
			return 0;
		}

		pkt_len		= df_csv.at(cur_idx).at(7);
		ip_src		= df_csv.at(cur_idx).at(1);
		ip_dst		= df_csv.at(cur_idx).at(2);
		port_src	= df_csv.at(cur_idx).at(3);
		port_dst	= df_csv.at(cur_idx).at(4);

		switch (std::stoi(df_csv.at(cur_idx).at(6))) {
			case 5:
				ip_proto = "1";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 17:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 33:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 49:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 65:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 81:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 97:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 113:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 129:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 145:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 161:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 177:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 193:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 209:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 241:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 257:
				ip_proto = "17";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 513:
				ip_proto = "0";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			default:
				cur_pkt.clear();
				cur_idx++;
				return 0;
		}
	} catch (const std::out_of_range&) {
		return -1;
	} catch (const std::invalid_argument&) {
		return -1;
	}

	if (ip_src == "" || ip_dst == "" || ip_proto == "") {
		cur_pkt.clear();
		cur_idx++;
		return 0;
	}

	cur_idx++;

	cur_pkt["len"]		= pkt_len;
	cur_pkt["ts"]		= ts;
	cur_pkt["ip_src"]	= ip_src;
	cur_pkt["ip_dst"]	= ip_dst;
	cur_pkt["ip_proto"] = ip_proto;
	cur_pkt["port_src"] = port_src;
	cur_pkt["port_dst"] = port_dst;
	cur_pkt["tcp_syn"]	= tcp_syn;
	cur_pkt["tcp_ack"]	= tcp_ack;
	cur_pkt["tcp_fin"]	= tcp_fin;
	cur_pkt["tcp_rst"]	= tcp_rst;

	return cur_idx;
}

void FCHv::process() {
	if (dp_sim) {
		process_dp();
	} else {
		process_cp();
	}
}

int FCHv::process_dp() {
	// If the packet is not IPv4.
	if (cur_pkt.empty()) {
		return -1;
	}

	if (sampl_idx < sampl_rate) {
		sampl_idx++;
	}

	hv_hdr.fill("");
	hv_bin_len_hdr.fill("");
	hv_bin_ts_hdr.fill("");
	timeout_toggle_a = false;
	timeout_toggle_b = false;
	timeout_toggle_c = false;
	timeout_toggle_d = false;

	// Update the current index counter value.
		if (read_idx < 16384) {
			read_idx++;
		} else {
			read_idx = 0;
		}
	// }

	// Hash calculation.

	struct in_addr ip_src_addr, ip_dst_addr;

	inet_aton(cur_pkt["ip_src"].c_str(), &ip_src_addr);
	inet_aton(cur_pkt["ip_dst"].c_str(), &ip_dst_addr);

	uint16_t proto_bytes	= htons(std::stoi(cur_pkt["ip_proto"]));
	uint16_t port_src_bytes = htons(std::stoi(cur_pkt["port_src"]));
	uint16_t port_dst_bytes = htons(std::stoi(cur_pkt["port_dst"]));

	uint16_t hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&ip_src_addr),
			reinterpret_cast<uint8_t*>(&ip_src_addr) + sizeof(ip_src_addr)));
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&ip_dst_addr),
			reinterpret_cast<uint8_t*>(&ip_dst_addr) + sizeof(ip_dst_addr)),
			hash_tmp);
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&proto_bytes),
			reinterpret_cast<uint8_t*>(&proto_bytes) + sizeof(proto_bytes)),
			hash_tmp);
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&port_src_bytes),
			reinterpret_cast<uint8_t*>(&port_src_bytes) + sizeof(port_src_bytes)),
			hash_tmp);
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&port_dst_bytes),
			reinterpret_cast<uint8_t*>(&port_dst_bytes) + sizeof(port_dst_bytes)),
			hash_tmp);

	std::string hash_bin = std::bitset<16>(hash_tmp).to_string();

	// hash_dp = std::stol(hash_bin.substr(2), nullptr, 2);
	hash_dp = std::stol(hash_bin, nullptr, 2);

	// Read/Update the various registers based on the hash value.
	if (hash_dp < 16384) {
		reg_update_dp(0, 1, 2, 3);
	} else if (hash_dp < 32768) {
		reg_update_dp(1, 0, 2, 3);
	} else if (hash_dp < 49152) {
		reg_update_dp(2, 0, 1, 3);
	} else {
		reg_update_dp(3, 0, 1, 2);
	}

	if (timeout_toggle_a == true || timeout_toggle_b == true
			|| timeout_toggle_c == true || timeout_toggle_d == true) {
		timeout_toggle_a = false;
		timeout_toggle_b = false;
		timeout_toggle_c = false;
		timeout_toggle_d = false;

		if (sampl_idx == sampl_rate) {
			cur_samples.push_back(as_sample());
			sampl_idx = 0;

			return 0;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int FCHv::process_cp() {
	// If the packet is not IPv4.
	if (cur_pkt.empty()) {
		return -1;
	}

	if (sampl_idx < sampl_rate) {
		sampl_idx++;
	}

	hv_hdr.fill("");
	hv_bin_len_hdr.fill("");
	hv_bin_ts_hdr.fill("");
	timeout_toggle = false;

	hash_cp = std::string("").append(cur_pkt["ip_src"]).append(cur_pkt["ip_dst"]).append(cur_pkt["ip_proto"]).append(cur_pkt["port_src"]).append(cur_pkt["port_dst"]);

	if (test_ts_interval_last == 0) {
		test_ts_interval_last = std::stod(cur_pkt["ts"]);
	}

	reg_update_cp(0);

	if ((std::stod(cur_pkt["ts"]) - test_ts_interval_last - 5.0) > EPS) {
		if (sampl_idx % sampl_rate == 0) {
			reg_read_cp(0, 1, 2, 3);
			test_ts_interval_last = std::stod(cur_pkt["ts"]);
		}
	}

	if (timeout_toggle == true) {
		sampl_idx = 0;
		return 0;
	} else {
		return -1;
	}
}

hypervision::sample_t FCHv::as_sample() {
	return hypervision::sample_t(hv_hdr, hv_bin_len_hdr, hv_bin_ts_hdr);
}

void FCHv::reg_update_dp(int a, int b, int c, int d) {
	long hash_mod = hash_dp % 16384;
	// long hash_mod = hash_dp;

	// Check if the hash_mod exists in reg_ts_dp[a].
	if ((reg_ts_dp[a].find(hash_mod) != reg_ts_dp[a].end())
			&& (reg_ts_dp[a][hash_mod][0] != 0 && reg_ts_dp[a][hash_mod][1] != 0)) {
		double ts_interval_a = std::stod(cur_pkt["ts"]) - reg_ts_dp[a][hash_mod][1];

		// if (((ts_interval_a - timeout) > EPS) && (sampl_idx == sampl_rate)) {
		if ((ts_interval_a - timeout) > EPS) {
			timeout_toggle_a = true;

			if (sampl_idx == sampl_rate) {

				hv_hdr[14*a]	= std::to_string(static_cast<double>(reg_ts_dp[a][hash_mod][0]));
				hv_hdr[14*a+1]	= std::to_string(static_cast<double>(reg_ts_dp[a][hash_mod][1]));
				hv_hdr[14*a+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[a][hash_mod]));
				hv_hdr[14*a+3]	= reg_ip_dp[a][hash_mod][0];
				hv_hdr[14*a+4]	= reg_ip_dp[a][hash_mod][1];
				hv_hdr[14*a+5]	= std::to_string(reg_port_dp[a][hash_mod][0]);
				hv_hdr[14*a+6]	= std::to_string(reg_port_dp[a][hash_mod][1]);
				hv_hdr[14*a+7]	= std::to_string(reg_flags_dp[a][hash_mod][0]);
				hv_hdr[14*a+8]	= std::to_string(reg_flags_dp[a][hash_mod][1]);
				hv_hdr[14*a+9]	= std::to_string(reg_flags_dp[a][hash_mod][2]);
				hv_hdr[14*a+10] = std::to_string(reg_flags_dp[a][hash_mod][3]);
				hv_hdr[14*a+11] = std::to_string(reg_data_dp[a][hash_mod][0]);
				hv_hdr[14*a+12] = std::to_string(reg_data_dp[a][hash_mod][1]);

				if (reg_data_dp[a][hash_mod][0] > 15) {
					hv_hdr[14*a+13] = "1";
				} else {
					hv_hdr[14*a+13] = "0";
				}

				hv_bin_len_hdr[2*a]			= std::to_string(reg_bin_len_0_dp[a][hash_mod][0]);
				hv_bin_len_hdr[2*a+1]		= std::to_string(reg_bin_len_0_dp[a][hash_mod][1]);
				hv_bin_len_hdr[8+2*a]		= std::to_string(reg_bin_len_1_dp[a][hash_mod][0]);
				hv_bin_len_hdr[8+2*a+1]		= std::to_string(reg_bin_len_1_dp[a][hash_mod][1]);
				hv_bin_len_hdr[16+2*a]		= std::to_string(reg_bin_len_2_dp[a][hash_mod][0]);
				hv_bin_len_hdr[16+2*a+1]	= std::to_string(reg_bin_len_2_dp[a][hash_mod][1]);
				hv_bin_len_hdr[24+2*a]		= std::to_string(reg_bin_len_3_dp[a][hash_mod][0]);
				hv_bin_len_hdr[24+2*a+1]	= std::to_string(reg_bin_len_3_dp[a][hash_mod][1]);
				hv_bin_len_hdr[32+2*a]		= std::to_string(reg_bin_len_4_dp[a][hash_mod][0]);
				hv_bin_len_hdr[32+2*a+1]	= std::to_string(reg_bin_len_4_dp[a][hash_mod][1]);

				hv_bin_ts_hdr[2*a]		= std::to_string(reg_bin_ts_0_dp[a][hash_mod][0]);
				hv_bin_ts_hdr[2*a+1]	= std::to_string(reg_bin_ts_0_dp[a][hash_mod][1]);
				hv_bin_ts_hdr[8+2*a]	= std::to_string(reg_bin_ts_1_dp[a][hash_mod][0]);
				hv_bin_ts_hdr[8+2*a+1]	= std::to_string(reg_bin_ts_1_dp[a][hash_mod][1]);
				hv_bin_ts_hdr[16+2*a]	= std::to_string(reg_bin_ts_2_dp[a][hash_mod][0]);
				hv_bin_ts_hdr[16+2*a+1]	= std::to_string(reg_bin_ts_2_dp[a][hash_mod][1]);
				hv_bin_ts_hdr[24+2*a]	= std::to_string(reg_bin_ts_3_dp[a][hash_mod][0]);
				hv_bin_ts_hdr[24+2*a+1]	= std::to_string(reg_bin_ts_3_dp[a][hash_mod][1]);
				hv_bin_ts_hdr[32+2*a]	= std::to_string(reg_bin_ts_4_dp[a][hash_mod][0]);
				hv_bin_ts_hdr[32+2*a+1]	= std::to_string(reg_bin_ts_4_dp[a][hash_mod][1]);

				reset_regs_dp(a, hash_mod);
			} else {
				hv_hdr[14*a]	= "0";
				hv_hdr[14*a+1]	= "0";
				hv_hdr[14*a+2]	= "0";
				hv_hdr[14*a+3]	= "0";
				hv_hdr[14*a+4]	= "0";
				hv_hdr[14*a+5]	= "0";
				hv_hdr[14*a+6]	= "0";
				hv_hdr[14*a+7]	= "0";
				hv_hdr[14*a+8]	= "0";
				hv_hdr[14*a+9]	= "0";
				hv_hdr[14*a+10] = "0";
				hv_hdr[14*a+11] = "0";
				hv_hdr[14*a+12] = "0";
				hv_hdr[14*a+13] = "0";

				hv_bin_len_hdr[2*a]			= "0";
				hv_bin_len_hdr[2*a+1]		= "0";
				hv_bin_len_hdr[8+2*a]		= "0";
				hv_bin_len_hdr[8+2*a+1]		= "0";
				hv_bin_len_hdr[16+2*a]		= "0";
				hv_bin_len_hdr[16+2*a+1]	= "0";
				hv_bin_len_hdr[24+2*a]		= "0";
				hv_bin_len_hdr[24+2*a+1]	= "0";
				hv_bin_len_hdr[32+2*a]		= "0";
				hv_bin_len_hdr[32+2*a+1]	= "0";

				hv_bin_ts_hdr[2*a]		= "0";
				hv_bin_ts_hdr[2*a+1]	= "0";
				hv_bin_ts_hdr[8+2*a]	= "0";
				hv_bin_ts_hdr[8+2*a+1]	= "0";
				hv_bin_ts_hdr[16+2*a]	= "0";
				hv_bin_ts_hdr[16+2*a+1]	= "0";
				hv_bin_ts_hdr[24+2*a]	= "0";
				hv_bin_ts_hdr[24+2*a+1]	= "0";
				hv_bin_ts_hdr[32+2*a]	= "0";
				hv_bin_ts_hdr[32+2*a+1]	= "0";
			}
		} else {
			// Store the time for the previous packet for this flow.
			reg_ts_dp[a][hash_mod][2]	= reg_ts_dp[a][hash_mod][1];
			// Store the current time for this packet.
			reg_ts_dp[a][hash_mod][1]	= std::stod(cur_pkt["ts"]);
		}
	} else {
		// First time this flow appears, store its start time.
		reg_ts_dp[a][hash_mod] = {std::stod(cur_pkt["ts"]),
								  std::stod(cur_pkt["ts"]),
								  std::stod(cur_pkt["ts"])};
	}

	if (!timeout_toggle_a) {
		// Elapsed time since the last received packet for this flow.
		cur_ts_interval = reg_ts_dp[a][hash_mod][1] - reg_ts_dp[a][hash_mod][2];

		// Current ts agg update calculation.
		double ts_agg_tmp = std::stod(cur_pkt["ts"]) - reg_ts_dp[a][hash_mod][0];
		if (reg_ts_agg_dp[a].find(hash_mod) != reg_ts_agg_dp[a].end()) {
			reg_ts_agg_dp[a][hash_mod] += ts_agg_tmp;
		} else {
			reg_ts_agg_dp[a][hash_mod] = ts_agg_tmp;
		}

		// IP src/dst.
		reg_ip_dp[a][hash_mod] = {cur_pkt["ip_src"], cur_pkt["ip_dst"]};

		// Pack ports.
		uint16_t port_src		= static_cast<uint16_t>(std::stoul(cur_pkt["port_src"]));
		uint16_t port_dst		= static_cast<uint16_t>(std::stoul(cur_pkt["port_dst"]));
		uint32_t ports_concat	= (static_cast<uint32_t>(port_src) << 16) | static_cast<uint32_t>(port_dst);

		// IP proto + port src/dst.
		reg_port_dp[a][hash_mod] = {static_cast<uint32_t>(std::stoul(cur_pkt["ip_proto"])),
								ports_concat};

		// TCP flags.
		if (reg_flags_dp[a].find(hash_mod) == reg_flags_dp[a].end()) {
			reg_flags_dp[a][hash_mod] = {0, 0, 0, 0};
		}
		if (cur_pkt["ip_proto"] == "6") {
			if (cur_pkt["tcp_syn"] == "1") {
				reg_flags_dp[a][hash_mod][0] += 1;
			}
			if (cur_pkt["tcp_ack"] == "1") {
				reg_flags_dp[a][hash_mod][1] += 1;
			}
			if (cur_pkt["tcp_fin"] == "1") {
				reg_flags_dp[a][hash_mod][2] += 1;
			}
			if (cur_pkt["tcp_rst"] == "1") {
				reg_flags_dp[a][hash_mod][3] += 1;
			}
		}

		// Packet count/length.
		if (reg_data_dp[a].find(hash_mod) != reg_data_dp[a].end()) {
			reg_data_dp[a][hash_mod][0] += 1;
			reg_data_dp[a][hash_mod][1] += static_cast<uint32_t>(std::stoul(cur_pkt["len"]));
		} else {
			reg_data_dp[a][hash_mod] = {1, static_cast<uint32_t>(std::stoul(cur_pkt["len"]))};
		}

		// Bin length updates.

		if (reg_bin_len_0_dp[a].find(hash_mod) == reg_bin_len_0_dp[a].end()) {
			reg_bin_len_0_dp[a][hash_mod] = {0, 0};
		}

		if (std::stoi(cur_pkt["len"]) < 256) {
			reg_bin_len_0_dp[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) < 512) {
			reg_bin_len_0_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_len_1_dp[a].find(hash_mod) == reg_bin_len_1_dp[a].end()) {
			reg_bin_len_1_dp[a][hash_mod] = {0, 0};
		}

		if (std::stoi(cur_pkt["len"]) >= 512 && std::stoi(cur_pkt["len"]) < 768) {
			reg_bin_len_1_dp[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 768 && std::stoi(cur_pkt["len"]) < 1024) {
			reg_bin_len_1_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_len_2_dp[a].find(hash_mod) == reg_bin_len_2_dp[a].end()) {
			reg_bin_len_2_dp[a][hash_mod] = {0, 0};
		}

		if (std::stoi(cur_pkt["len"]) >= 1024 && std::stoi(cur_pkt["len"]) < 1280) {
			reg_bin_len_2_dp[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 1280 && std::stoi(cur_pkt["len"]) < 1536) {
			reg_bin_len_2_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_len_3_dp[a].find(hash_mod) == reg_bin_len_3_dp[a].end()) {
			reg_bin_len_3_dp[a][hash_mod] = {0, 0};
		}

		if (std::stoi(cur_pkt["len"]) >= 1536 && std::stoi(cur_pkt["len"]) < 1792) {
			reg_bin_len_3_dp[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 1792 && std::stoi(cur_pkt["len"]) < 2048) {
			reg_bin_len_3_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_len_4_dp[a].find(hash_mod) == reg_bin_len_4_dp[a].end()) {
			reg_bin_len_4_dp[a][hash_mod] = {0, 0};
		}

		if (std::stoi(cur_pkt["len"]) >= 2048 && std::stoi(cur_pkt["len"]) < 2304) {
			reg_bin_len_4_dp[a][hash_mod][0] += 1;
		// } else if (std::stoi(cur_pkt["len"]) >= 2304 && std::stoi(cur_pkt["len"]) < 2560) {
		} else if (std::stoi(cur_pkt["len"]) >= 2304) {
			reg_bin_len_4_dp[a][hash_mod][1] += 1;
		}

		// Bin timestamp updates.

		if (reg_bin_ts_0_dp[a].find(hash_mod) == reg_bin_ts_0_dp[a].end()) {
			reg_bin_ts_0_dp[a][hash_mod] = {0, 0};
		}

		// if (cur_ts_interval < 0.016) {
		if (cur_ts_interval < 0.001) {
			reg_bin_ts_0_dp[a][hash_mod][0] += 1;
		// } else if (cur_ts_interval < 0.032) {
			reg_bin_ts_0_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_ts_1_dp[a].find(hash_mod) == reg_bin_ts_1_dp[a].end()) {
			reg_bin_ts_1_dp[a][hash_mod] = {0, 0};
		}

		// if (cur_ts_interval >= 0.032 && cur_ts_interval < 0.048) {
		if (cur_ts_interval >= 0.005 && cur_ts_interval < 0.010) {
			reg_bin_ts_1_dp[a][hash_mod][0] += 1;
		// } else if (cur_ts_interval >= 0.048 && cur_ts_interval < 0.064) {
		} else if (cur_ts_interval >= 0.010 && cur_ts_interval < 0.015) {
			reg_bin_ts_1_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_ts_2_dp[a].find(hash_mod) == reg_bin_ts_2_dp[a].end()) {
			reg_bin_ts_2_dp[a][hash_mod] = {0, 0};
		}

		// if (cur_ts_interval >= 0.064 && cur_ts_interval < 0.080) {
		if (cur_ts_interval >= 0.015 && cur_ts_interval < 0.020) {
			reg_bin_ts_2_dp[a][hash_mod][0] += 1;
		// } else if (cur_ts_interval >= 0.080 && cur_ts_interval < 0.096) {
		} else if (cur_ts_interval >= 0.020 && cur_ts_interval < 0.025) {
			reg_bin_ts_2_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_ts_3_dp[a].find(hash_mod) == reg_bin_ts_3_dp[a].end()) {
			reg_bin_ts_3_dp[a][hash_mod] = {0, 0};
		}

		// if (cur_ts_interval >= 0.096 && cur_ts_interval < 0.112) {
		if (cur_ts_interval >= 0.025 && cur_ts_interval < 0.030) {
			reg_bin_ts_3_dp[a][hash_mod][0] += 1;
		// } else if (cur_ts_interval >= 0.112 && cur_ts_interval < 0.128) {
		} else if (cur_ts_interval >= 0.030 && cur_ts_interval < 0.035) {
			reg_bin_ts_3_dp[a][hash_mod][1] += 1;
		}

		if (reg_bin_ts_4_dp[a].find(hash_mod) == reg_bin_ts_4_dp[a].end()) {
			reg_bin_ts_4_dp[a][hash_mod] = {0, 0};
		}

		// if (cur_ts_interval >= 0.128 && cur_ts_interval < 0.144) {
		if (cur_ts_interval >= 0.035 && cur_ts_interval < 0.040) {
			reg_bin_ts_4_dp[a][hash_mod][0] += 1;
		// } else if (cur_ts_interval >= 0.144 && cur_ts_interval < 0.160) {
		// } else if (cur_ts_interval >= 0.040 && cur_ts_interval < 0.045) {
		} else if (cur_ts_interval >= 0.040) {
			reg_bin_ts_4_dp[a][hash_mod][1] += 1;
		}

		hv_hdr[14*a]	= "0";
		hv_hdr[14*a+1]	= "0";
		hv_hdr[14*a+2]	= "0";
		hv_hdr[14*a+3]	= "0";
		hv_hdr[14*a+4]	= "0";
		hv_hdr[14*a+5]	= "0";
		hv_hdr[14*a+6]	= "0";
		hv_hdr[14*a+7]	= "0";
		hv_hdr[14*a+8]	= "0";
		hv_hdr[14*a+9]	= "0";
		hv_hdr[14*a+10] = "0";
		hv_hdr[14*a+11] = "0";
		hv_hdr[14*a+12] = "0";
		hv_hdr[14*a+13] = "0";

		hv_bin_len_hdr[2*a]			= "0";
		hv_bin_len_hdr[2*a+1]		= "0";
		hv_bin_len_hdr[8+2*a]		= "0";
		hv_bin_len_hdr[8+2*a+1]		= "0";
		hv_bin_len_hdr[16+2*a]		= "0";
		hv_bin_len_hdr[16+2*a+1]	= "0";
		hv_bin_len_hdr[24+2*a]		= "0";
		hv_bin_len_hdr[24+2*a+1]	= "0";
		hv_bin_len_hdr[32+2*a]		= "0";
		hv_bin_len_hdr[32+2*a+1]	= "0";

		hv_bin_ts_hdr[2*a]		= "0";
		hv_bin_ts_hdr[2*a+1]	= "0";
		hv_bin_ts_hdr[8+2*a]	= "0";
		hv_bin_ts_hdr[8+2*a+1]	= "0";
		hv_bin_ts_hdr[16+2*a]	= "0";
		hv_bin_ts_hdr[16+2*a+1]	= "0";
		hv_bin_ts_hdr[24+2*a]	= "0";
		hv_bin_ts_hdr[24+2*a+1]	= "0";
		hv_bin_ts_hdr[32+2*a]	= "0";
		hv_bin_ts_hdr[32+2*a+1]	= "0";
	}

	if (reg_ts_dp[b].find(read_idx) != reg_ts_dp[b].end()) {
		if (reg_ts_dp[b][read_idx][0] != 0 && reg_ts_dp[b][read_idx][1] != 0) {
			double ts_interval_b = std::stod(cur_pkt["ts"]) - reg_ts_dp[b][read_idx][1];

			// if (((ts_interval_b - timeout) > EPS) && (sampl_idx == sampl_rate)) {
			if ((ts_interval_b - timeout) > EPS) {
				timeout_toggle_b = true;

				if (sampl_idx == sampl_rate) {
					hv_hdr[14*b]	= std::to_string(static_cast<double>(reg_ts_dp[b][read_idx][0]));
					hv_hdr[14*b+1]	= std::to_string(static_cast<double>(reg_ts_dp[b][read_idx][1]));
					hv_hdr[14*b+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[b][read_idx]));
					hv_hdr[14*b+3]	= reg_ip_dp[b][read_idx][0];
					hv_hdr[14*b+4]	= reg_ip_dp[b][read_idx][1];
					hv_hdr[14*b+5]	= std::to_string(reg_port_dp[b][read_idx][0]);
					hv_hdr[14*b+6]	= std::to_string(reg_port_dp[b][read_idx][1]);
					hv_hdr[14*b+7]	= std::to_string(reg_flags_dp[b][read_idx][0]);
					hv_hdr[14*b+8]	= std::to_string(reg_flags_dp[b][read_idx][1]);
					hv_hdr[14*b+9]	= std::to_string(reg_flags_dp[b][read_idx][2]);
					hv_hdr[14*b+10] = std::to_string(reg_flags_dp[b][read_idx][3]);
					hv_hdr[14*b+11] = std::to_string(reg_data_dp[b][read_idx][0]);
					hv_hdr[14*b+12] = std::to_string(reg_data_dp[b][read_idx][1]);

					if (reg_data_dp[b][read_idx][0] > 15) {
						hv_hdr[14*b+13] = "1";
					} else {
						hv_hdr[14*b+13] = "0";
					}

					hv_bin_len_hdr[2*b]			= std::to_string(reg_bin_len_0_dp[b][read_idx][0]);
					hv_bin_len_hdr[2*b+1]		= std::to_string(reg_bin_len_0_dp[b][read_idx][1]);
					hv_bin_len_hdr[8+2*b]		= std::to_string(reg_bin_len_1_dp[b][read_idx][0]);
					hv_bin_len_hdr[8+2*b+1]		= std::to_string(reg_bin_len_1_dp[b][read_idx][1]);
					hv_bin_len_hdr[16+2*b]		= std::to_string(reg_bin_len_2_dp[b][read_idx][0]);
					hv_bin_len_hdr[16+2*b+1]	= std::to_string(reg_bin_len_2_dp[b][read_idx][1]);
					hv_bin_len_hdr[24+2*b]		= std::to_string(reg_bin_len_3_dp[b][read_idx][0]);
					hv_bin_len_hdr[24+2*b+1]	= std::to_string(reg_bin_len_3_dp[b][read_idx][1]);
					hv_bin_len_hdr[32+2*b]		= std::to_string(reg_bin_len_4_dp[b][read_idx][0]);
					hv_bin_len_hdr[32+2*b+1]	= std::to_string(reg_bin_len_4_dp[b][read_idx][1]);

					hv_bin_ts_hdr[2*b]		= std::to_string(reg_bin_ts_0_dp[b][read_idx][0]);
					hv_bin_ts_hdr[2*b+1]	= std::to_string(reg_bin_ts_0_dp[b][read_idx][1]);
					hv_bin_ts_hdr[8+2*b]	= std::to_string(reg_bin_ts_1_dp[b][read_idx][0]);
					hv_bin_ts_hdr[8+2*b+1]	= std::to_string(reg_bin_ts_1_dp[b][read_idx][1]);
					hv_bin_ts_hdr[16+2*b]	= std::to_string(reg_bin_ts_2_dp[b][read_idx][0]);
					hv_bin_ts_hdr[16+2*b+1]	= std::to_string(reg_bin_ts_2_dp[b][read_idx][1]);
					hv_bin_ts_hdr[24+2*b]	= std::to_string(reg_bin_ts_3_dp[b][read_idx][0]);
					hv_bin_ts_hdr[24+2*b+1]	= std::to_string(reg_bin_ts_3_dp[b][read_idx][1]);
					hv_bin_ts_hdr[32+2*b]	= std::to_string(reg_bin_ts_4_dp[b][read_idx][0]);
					hv_bin_ts_hdr[32+2*b+1]	= std::to_string(reg_bin_ts_4_dp[b][read_idx][1]);

					reset_regs_dp(b, read_idx);
				} else {
					hv_hdr[14*b]	= "0";
					hv_hdr[14*b+1]	= "0";
					hv_hdr[14*b+2]	= "0";
					hv_hdr[14*b+3]	= "0";
					hv_hdr[14*b+4]	= "0";
					hv_hdr[14*b+5]	= "0";
					hv_hdr[14*b+6]	= "0";
					hv_hdr[14*b+7]	= "0";
					hv_hdr[14*b+8]	= "0";
					hv_hdr[14*b+9]	= "0";
					hv_hdr[14*b+10] = "0";
					hv_hdr[14*b+11] = "0";
					hv_hdr[14*b+12] = "0";
					hv_hdr[14*b+13] = "0";

					hv_bin_len_hdr[2*b]			= "0";
					hv_bin_len_hdr[2*b+1]		= "0";
					hv_bin_len_hdr[8+2*b]		= "0";
					hv_bin_len_hdr[8+2*b+1]		= "0";
					hv_bin_len_hdr[16+2*b]		= "0";
					hv_bin_len_hdr[16+2*b+1]	= "0";
					hv_bin_len_hdr[24+2*b]		= "0";
					hv_bin_len_hdr[24+2*b+1]	= "0";
					hv_bin_len_hdr[32+2*b]		= "0";
					hv_bin_len_hdr[32+2*b+1]	= "0";

					hv_bin_ts_hdr[2*b]		= "0";
					hv_bin_ts_hdr[2*b+1]	= "0";
					hv_bin_ts_hdr[8+2*b]	= "0";
					hv_bin_ts_hdr[8+2*b+1]	= "0";
					hv_bin_ts_hdr[16+2*b]	= "0";
					hv_bin_ts_hdr[16+2*b+1]	= "0";
					hv_bin_ts_hdr[24+2*b]	= "0";
					hv_bin_ts_hdr[24+2*b+1]	= "0";
					hv_bin_ts_hdr[32+2*b]	= "0";
					hv_bin_ts_hdr[32+2*b+1]	= "0";
				}
			}
		}
	}

	if (!timeout_toggle_b) {
		hv_hdr[14*b]	= "0";
		hv_hdr[14*b+1]	= "0";
		hv_hdr[14*b+2]	= "0";
		hv_hdr[14*b+3]	= "0";
		hv_hdr[14*b+4]	= "0";
		hv_hdr[14*b+5]	= "0";
		hv_hdr[14*b+6]	= "0";
		hv_hdr[14*b+7]	= "0";
		hv_hdr[14*b+8]	= "0";
		hv_hdr[14*b+9]	= "0";
		hv_hdr[14*b+10] = "0";
		hv_hdr[14*b+11] = "0";
		hv_hdr[14*b+12] = "0";
		hv_hdr[14*b+13] = "0";

		hv_bin_len_hdr[2*b]			= "0";
		hv_bin_len_hdr[2*b+1]		= "0";
		hv_bin_len_hdr[8+2*b]		= "0";
		hv_bin_len_hdr[8+2*b+1]		= "0";
		hv_bin_len_hdr[16+2*b]		= "0";
		hv_bin_len_hdr[16+2*b+1]	= "0";
		hv_bin_len_hdr[24+2*b]		= "0";
		hv_bin_len_hdr[24+2*b+1]	= "0";
		hv_bin_len_hdr[32+2*b]		= "0";
		hv_bin_len_hdr[32+2*b+1]	= "0";

		hv_bin_ts_hdr[2*b]		= "0";
		hv_bin_ts_hdr[2*b+1]	= "0";
		hv_bin_ts_hdr[8+2*b]	= "0";
		hv_bin_ts_hdr[8+2*b+1]	= "0";
		hv_bin_ts_hdr[16+2*b]	= "0";
		hv_bin_ts_hdr[16+2*b+1]	= "0";
		hv_bin_ts_hdr[24+2*b]	= "0";
		hv_bin_ts_hdr[24+2*b+1]	= "0";
		hv_bin_ts_hdr[32+2*b]	= "0";
		hv_bin_ts_hdr[32+2*b+1]	= "0";
	}

	if (reg_ts_dp[c].find(read_idx) != reg_ts_dp[c].end()) {
		if (reg_ts_dp[c][read_idx][0] != 0 && reg_ts_dp[c][read_idx][1] != 0) {
			double ts_interval_c = std::stod(cur_pkt["ts"]) - reg_ts_dp[c][read_idx][1];

			// if (((ts_interval_c - timeout) > EPS) && (sampl_idx == sampl_rate)) {
			if ((ts_interval_c - timeout) > EPS) {
				timeout_toggle_c = true;

				if (sampl_idx == sampl_rate) {
					hv_hdr[14*c]	= std::to_string(static_cast<double>(reg_ts_dp[c][read_idx][0]));
					hv_hdr[14*c+1]	= std::to_string(static_cast<double>(reg_ts_dp[c][read_idx][1]));
					hv_hdr[14*c+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[c][read_idx]));
					hv_hdr[14*c+3]	= reg_ip_dp[c][read_idx][0];
					hv_hdr[14*c+4]	= reg_ip_dp[c][read_idx][1];
					hv_hdr[14*c+5]	= std::to_string(reg_port_dp[c][read_idx][0]);
					hv_hdr[14*c+6]	= std::to_string(reg_port_dp[c][read_idx][1]);
					hv_hdr[14*c+7]	= std::to_string(reg_flags_dp[c][read_idx][0]);
					hv_hdr[14*c+8]	= std::to_string(reg_flags_dp[c][read_idx][1]);
					hv_hdr[14*c+9]	= std::to_string(reg_flags_dp[c][read_idx][2]);
					hv_hdr[14*c+10] = std::to_string(reg_flags_dp[c][read_idx][3]);
					hv_hdr[14*c+11] = std::to_string(reg_data_dp[c][read_idx][0]);
					hv_hdr[14*c+12] = std::to_string(reg_data_dp[c][read_idx][1]);

					if (reg_data_dp[c][read_idx][0] > 15) {
						hv_hdr[14*c+13] = "1";
					} else {
						hv_hdr[14*c+13] = "0";
					}

					hv_bin_len_hdr[2*c]			= std::to_string(reg_bin_len_0_dp[c][read_idx][0]);
					hv_bin_len_hdr[2*c+1]		= std::to_string(reg_bin_len_0_dp[c][read_idx][1]);
					hv_bin_len_hdr[8+2*c]		= std::to_string(reg_bin_len_1_dp[c][read_idx][0]);
					hv_bin_len_hdr[8+2*c+1]		= std::to_string(reg_bin_len_1_dp[c][read_idx][1]);
					hv_bin_len_hdr[16+2*c]		= std::to_string(reg_bin_len_2_dp[c][read_idx][0]);
					hv_bin_len_hdr[16+2*c+1]	= std::to_string(reg_bin_len_2_dp[c][read_idx][1]);
					hv_bin_len_hdr[24+2*c]		= std::to_string(reg_bin_len_3_dp[c][read_idx][0]);
					hv_bin_len_hdr[24+2*c+1]	= std::to_string(reg_bin_len_3_dp[c][read_idx][1]);
					hv_bin_len_hdr[32+2*c]		= std::to_string(reg_bin_len_4_dp[c][read_idx][0]);
					hv_bin_len_hdr[32+2*c+1]	= std::to_string(reg_bin_len_4_dp[c][read_idx][1]);

					hv_bin_ts_hdr[2*c]		= std::to_string(reg_bin_ts_0_dp[c][read_idx][0]);
					hv_bin_ts_hdr[2*c+1]	= std::to_string(reg_bin_ts_0_dp[c][read_idx][1]);
					hv_bin_ts_hdr[8+2*c]	= std::to_string(reg_bin_ts_1_dp[c][read_idx][0]);
					hv_bin_ts_hdr[8+2*c+1]	= std::to_string(reg_bin_ts_1_dp[c][read_idx][1]);
					hv_bin_ts_hdr[16+2*c]	= std::to_string(reg_bin_ts_2_dp[c][read_idx][0]);
					hv_bin_ts_hdr[16+2*c+1]	= std::to_string(reg_bin_ts_2_dp[c][read_idx][1]);
					hv_bin_ts_hdr[24+2*c]	= std::to_string(reg_bin_ts_3_dp[c][read_idx][0]);
					hv_bin_ts_hdr[24+2*c+1]	= std::to_string(reg_bin_ts_3_dp[c][read_idx][1]);
					hv_bin_ts_hdr[32+2*c]	= std::to_string(reg_bin_ts_4_dp[c][read_idx][0]);
					hv_bin_ts_hdr[32+2*c+1]	= std::to_string(reg_bin_ts_4_dp[c][read_idx][1]);

					reset_regs_dp(c, read_idx);
				} else {
					hv_hdr[14*c]	= "0";
					hv_hdr[14*c+1]	= "0";
					hv_hdr[14*c+2]	= "0";
					hv_hdr[14*c+3]	= "0";
					hv_hdr[14*c+4]	= "0";
					hv_hdr[14*c+5]	= "0";
					hv_hdr[14*c+6]	= "0";
					hv_hdr[14*c+7]	= "0";
					hv_hdr[14*c+8]	= "0";
					hv_hdr[14*c+9]	= "0";
					hv_hdr[14*c+10] = "0";
					hv_hdr[14*c+11] = "0";
					hv_hdr[14*c+12] = "0";
					hv_hdr[14*c+13] = "0";

					hv_bin_len_hdr[2*c]			= "0";
					hv_bin_len_hdr[2*c+1]		= "0";
					hv_bin_len_hdr[8+2*c]		= "0";
					hv_bin_len_hdr[8+2*c+1]		= "0";
					hv_bin_len_hdr[16+2*c]		= "0";
					hv_bin_len_hdr[16+2*c+1]	= "0";
					hv_bin_len_hdr[24+2*c]		= "0";
					hv_bin_len_hdr[24+2*c+1]	= "0";
					hv_bin_len_hdr[32+2*c]		= "0";
					hv_bin_len_hdr[32+2*c+1]	= "0";

					hv_bin_ts_hdr[2*c]		= "0";
					hv_bin_ts_hdr[2*c+1]	= "0";
					hv_bin_ts_hdr[8+2*c]	= "0";
					hv_bin_ts_hdr[8+2*c+1]	= "0";
					hv_bin_ts_hdr[16+2*c]	= "0";
					hv_bin_ts_hdr[16+2*c+1]	= "0";
					hv_bin_ts_hdr[24+2*c]	= "0";
					hv_bin_ts_hdr[24+2*c+1]	= "0";
					hv_bin_ts_hdr[32+2*c]	= "0";
					hv_bin_ts_hdr[32+2*c+1]	= "0";
				}
			}
		}
	}

	if (!timeout_toggle_c) {
		hv_hdr[14*c]	= "0";
		hv_hdr[14*c+1]	= "0";
		hv_hdr[14*c+2]	= "0";
		hv_hdr[14*c+3]	= "0";
		hv_hdr[14*c+4]	= "0";
		hv_hdr[14*c+5]	= "0";
		hv_hdr[14*c+6]	= "0";
		hv_hdr[14*c+7]	= "0";
		hv_hdr[14*c+8]	= "0";
		hv_hdr[14*c+9]	= "0";
		hv_hdr[14*c+10] = "0";
		hv_hdr[14*c+11] = "0";
		hv_hdr[14*c+12] = "0";
		hv_hdr[14*c+13] = "0";

		hv_bin_len_hdr[2*c]			= "0";
		hv_bin_len_hdr[2*c+1]		= "0";
		hv_bin_len_hdr[8+2*c]		= "0";
		hv_bin_len_hdr[8+2*c+1]		= "0";
		hv_bin_len_hdr[16+2*c]		= "0";
		hv_bin_len_hdr[16+2*c+1]	= "0";
		hv_bin_len_hdr[24+2*c]		= "0";
		hv_bin_len_hdr[24+2*c+1]	= "0";
		hv_bin_len_hdr[32+2*c]		= "0";
		hv_bin_len_hdr[32+2*c+1]	= "0";

		hv_bin_ts_hdr[2*c]		= "0";
		hv_bin_ts_hdr[2*c+1]	= "0";
		hv_bin_ts_hdr[8+2*c]	= "0";
		hv_bin_ts_hdr[8+2*c+1]	= "0";
		hv_bin_ts_hdr[16+2*c]	= "0";
		hv_bin_ts_hdr[16+2*c+1]	= "0";
		hv_bin_ts_hdr[24+2*c]	= "0";
		hv_bin_ts_hdr[24+2*c+1]	= "0";
		hv_bin_ts_hdr[32+2*c]	= "0";
		hv_bin_ts_hdr[32+2*c+1]	= "0";
	}

	if (reg_ts_dp[d].find(read_idx) != reg_ts_dp[d].end()) {
		if (reg_ts_dp[d][read_idx][0] != 0 && reg_ts_dp[d][read_idx][1] != 0) {
			double ts_interval_d = std::stod(cur_pkt["ts"]) - reg_ts_dp[d][read_idx][1];

			// if (((ts_interval_d - timeout) > EPS) && (sampl_idx == sampl_rate)) {
			if ((ts_interval_d - timeout) > EPS) {
				timeout_toggle_d = true;

				if (sampl_idx == sampl_rate) {
					hv_hdr[14*d]	= std::to_string(static_cast<double>(reg_ts_dp[d][read_idx][0]));
					hv_hdr[14*d+1]	= std::to_string(static_cast<double>(reg_ts_dp[d][read_idx][1]));
					hv_hdr[14*d+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[d][read_idx]));
					hv_hdr[14*d+3]	= reg_ip_dp[d][read_idx][0];
					hv_hdr[14*d+4]	= reg_ip_dp[d][read_idx][1];
					hv_hdr[14*d+5]	= std::to_string(reg_port_dp[d][read_idx][0]);
					hv_hdr[14*d+6]	= std::to_string(reg_port_dp[d][read_idx][1]);
					hv_hdr[14*d+7]	= std::to_string(reg_flags_dp[d][read_idx][0]);
					hv_hdr[14*d+8]	= std::to_string(reg_flags_dp[d][read_idx][1]);
					hv_hdr[14*d+9]	= std::to_string(reg_flags_dp[d][read_idx][2]);
					hv_hdr[14*d+10] = std::to_string(reg_flags_dp[d][read_idx][3]);
					hv_hdr[14*d+11] = std::to_string(reg_data_dp[d][read_idx][0]);
					hv_hdr[14*d+12] = std::to_string(reg_data_dp[d][read_idx][1]);

					if (reg_data_dp[d][read_idx][0] > 15) {
						hv_hdr[14*d+13] = "1";
					} else {
						hv_hdr[14*d+13] = "0";
					}

					hv_bin_len_hdr[2*d]			= std::to_string(reg_bin_len_0_dp[d][read_idx][0]);
					hv_bin_len_hdr[2*d+1]		= std::to_string(reg_bin_len_0_dp[d][read_idx][1]);
					hv_bin_len_hdr[8+2*d]		= std::to_string(reg_bin_len_1_dp[d][read_idx][0]);
					hv_bin_len_hdr[8+2*d+1]		= std::to_string(reg_bin_len_1_dp[d][read_idx][1]);
					hv_bin_len_hdr[16+2*d]		= std::to_string(reg_bin_len_2_dp[d][read_idx][0]);
					hv_bin_len_hdr[16+2*d+1]	= std::to_string(reg_bin_len_2_dp[d][read_idx][1]);
					hv_bin_len_hdr[24+2*d]		= std::to_string(reg_bin_len_3_dp[d][read_idx][0]);
					hv_bin_len_hdr[24+2*d+1]	= std::to_string(reg_bin_len_3_dp[d][read_idx][1]);
					hv_bin_len_hdr[32+2*d]		= std::to_string(reg_bin_len_4_dp[d][read_idx][0]);
					hv_bin_len_hdr[32+2*d+1]	= std::to_string(reg_bin_len_4_dp[d][read_idx][1]);

					hv_bin_ts_hdr[2*d]		= std::to_string(reg_bin_ts_0_dp[d][read_idx][0]);
					hv_bin_ts_hdr[2*d+1]	= std::to_string(reg_bin_ts_0_dp[d][read_idx][1]);
					hv_bin_ts_hdr[8+2*d]	= std::to_string(reg_bin_ts_1_dp[d][read_idx][0]);
					hv_bin_ts_hdr[8+2*d+1]	= std::to_string(reg_bin_ts_1_dp[d][read_idx][1]);
					hv_bin_ts_hdr[16+2*d]	= std::to_string(reg_bin_ts_2_dp[d][read_idx][0]);
					hv_bin_ts_hdr[16+2*d+1]	= std::to_string(reg_bin_ts_2_dp[d][read_idx][1]);
					hv_bin_ts_hdr[24+2*d]	= std::to_string(reg_bin_ts_3_dp[d][read_idx][0]);
					hv_bin_ts_hdr[24+2*d+1]	= std::to_string(reg_bin_ts_3_dp[d][read_idx][1]);
					hv_bin_ts_hdr[32+2*d]	= std::to_string(reg_bin_ts_4_dp[d][read_idx][0]);
					hv_bin_ts_hdr[32+2*d+1]	= std::to_string(reg_bin_ts_4_dp[d][read_idx][1]);

					reset_regs_dp(d, read_idx);
				} else {
					hv_hdr[14*d]	= "0";
					hv_hdr[14*d+1]	= "0";
					hv_hdr[14*d+2]	= "0";
					hv_hdr[14*d+3]	= "0";
					hv_hdr[14*d+4]	= "0";
					hv_hdr[14*d+5]	= "0";
					hv_hdr[14*d+6]	= "0";
					hv_hdr[14*d+7]	= "0";
					hv_hdr[14*d+8]	= "0";
					hv_hdr[14*d+9]	= "0";
					hv_hdr[14*d+10] = "0";
					hv_hdr[14*d+11] = "0";
					hv_hdr[14*d+12] = "0";
					hv_hdr[14*d+13] = "0";

					hv_bin_len_hdr[2*d]			= "0";
					hv_bin_len_hdr[2*d+1]		= "0";
					hv_bin_len_hdr[8+2*d]		= "0";
					hv_bin_len_hdr[8+2*d+1]		= "0";
					hv_bin_len_hdr[16+2*d]		= "0";
					hv_bin_len_hdr[16+2*d+1]	= "0";
					hv_bin_len_hdr[24+2*d]		= "0";
					hv_bin_len_hdr[24+2*d+1]	= "0";
					hv_bin_len_hdr[32+2*d]		= "0";
					hv_bin_len_hdr[32+2*d+1]	= "0";

					hv_bin_ts_hdr[2*d]		= "0";
					hv_bin_ts_hdr[2*d+1]	= "0";
					hv_bin_ts_hdr[8+2*d]	= "0";
					hv_bin_ts_hdr[8+2*d+1]	= "0";
					hv_bin_ts_hdr[16+2*d]	= "0";
					hv_bin_ts_hdr[16+2*d+1]	= "0";
					hv_bin_ts_hdr[24+2*d]	= "0";
					hv_bin_ts_hdr[24+2*d+1]	= "0";
					hv_bin_ts_hdr[32+2*d]	= "0";
					hv_bin_ts_hdr[32+2*d+1]	= "0";
				}
			}
		}
	}

	if (!timeout_toggle_d) {
		hv_hdr[14*d]	= "0";
		hv_hdr[14*d+1]	= "0";
		hv_hdr[14*d+2]	= "0";
		hv_hdr[14*d+3]	= "0";
		hv_hdr[14*d+4]	= "0";
		hv_hdr[14*d+5]	= "0";
		hv_hdr[14*d+6]	= "0";
		hv_hdr[14*d+7]	= "0";
		hv_hdr[14*d+8]	= "0";
		hv_hdr[14*d+9]	= "0";
		hv_hdr[14*d+10] = "0";
		hv_hdr[14*d+11] = "0";
		hv_hdr[14*d+12] = "0";
		hv_hdr[14*d+13] = "0";

		hv_bin_len_hdr[2*d]			= "0";
		hv_bin_len_hdr[2*d+1]		= "0";
		hv_bin_len_hdr[8+2*d]		= "0";
		hv_bin_len_hdr[8+2*d+1]		= "0";
		hv_bin_len_hdr[16+2*d]		= "0";
		hv_bin_len_hdr[16+2*d+1]	= "0";
		hv_bin_len_hdr[24+2*d]		= "0";
		hv_bin_len_hdr[24+2*d+1]	= "0";
		hv_bin_len_hdr[32+2*d]		= "0";
		hv_bin_len_hdr[32+2*d+1]	= "0";

		hv_bin_ts_hdr[2*d]		= "0";
		hv_bin_ts_hdr[2*d+1]	= "0";
		hv_bin_ts_hdr[8+2*d]	= "0";
		hv_bin_ts_hdr[8+2*d+1]	= "0";
		hv_bin_ts_hdr[16+2*d]	= "0";
		hv_bin_ts_hdr[16+2*d+1]	= "0";
		hv_bin_ts_hdr[24+2*d]	= "0";
		hv_bin_ts_hdr[24+2*d+1]	= "0";
		hv_bin_ts_hdr[32+2*d]	= "0";
		hv_bin_ts_hdr[32+2*d+1]	= "0";
	}
}

void FCHv::reg_update_cp(int a) {
	// Check if the hash_cp exists in reg_ts[a].
	if ((reg_ts_cp[a].find(hash_cp) != reg_ts_cp[a].end())
			&& (reg_ts_cp[a][hash_cp][0] != 0 && reg_ts_cp[a][hash_cp][1] != 0)) {
		// Store the time for the previous packet for this flow.
		reg_ts_cp[a][hash_cp][2]	= reg_ts_cp[a][hash_cp][1];
		// Store the current time for this packet.
		reg_ts_cp[a][hash_cp][1]	= std::stod(cur_pkt["ts"]);
	} else {
		// First time this flow appears, store its start time.
		reg_ts_cp[a][hash_cp] = {std::stod(cur_pkt["ts"]),
								 std::stod(cur_pkt["ts"]),
								 std::stod(cur_pkt["ts"])};
	}

	// Elapsed time since the last received packet for this flow.
	cur_ts_interval = reg_ts_cp[a][hash_cp][1] - reg_ts_cp[a][hash_cp][2];

	// Current ts agg update calculation.
	double ts_agg_tmp = std::stod(cur_pkt["ts"]) - reg_ts_cp[a][hash_cp][0];
	if (reg_ts_agg_cp[a].find(hash_cp) != reg_ts_agg_cp[a].end()) {
		reg_ts_agg_cp[a][hash_cp] += ts_agg_tmp;
	} else {
		reg_ts_agg_cp[a][hash_cp] = ts_agg_tmp;
	}

	// IP src/dst.
	reg_ip_cp[a][hash_cp] = {cur_pkt["ip_src"], cur_pkt["ip_dst"]};

	// Pack ports.
	uint16_t port_src		= static_cast<uint16_t>(std::stoul(cur_pkt["port_src"]));
	uint16_t port_dst		= static_cast<uint16_t>(std::stoul(cur_pkt["port_dst"]));
	uint32_t ports_concat	= (static_cast<uint32_t>(port_src) << 16) | static_cast<uint32_t>(port_dst);

	// IP proto + port src/dst.
	reg_port_cp[a][hash_cp] = {static_cast<uint32_t>(std::stoul(cur_pkt["ip_proto"])),
							ports_concat};

	// TCP flags.
	if (reg_flags_cp[a].find(hash_cp) == reg_flags_cp[a].end()) {
		reg_flags_cp[a][hash_cp] = {0, 0, 0, 0};
	}
	if (cur_pkt["ip_proto"] == "6") {
		if (cur_pkt["tcp_syn"] == "1") {
			reg_flags_cp[a][hash_cp][0] += 1;
		}
		if (cur_pkt["tcp_ack"] == "1") {
			reg_flags_cp[a][hash_cp][1] += 1;
		}
		if (cur_pkt["tcp_fin"] == "1") {
			reg_flags_cp[a][hash_cp][2] += 1;
		}
		if (cur_pkt["tcp_rst"] == "1") {
			reg_flags_cp[a][hash_cp][3] += 1;
		}
	}

	// Packet count/length.
	if (reg_data_cp[a].find(hash_cp) != reg_data_cp[a].end()) {
		reg_data_cp[a][hash_cp][0] += 1;
		reg_data_cp[a][hash_cp][1] += static_cast<uint32_t>(std::stoul(cur_pkt["len"]));
	} else {
		reg_data_cp[a][hash_cp] = {1, static_cast<uint32_t>(std::stoul(cur_pkt["len"]))};
	}

	// Bin length updates.

	if (reg_bin_len_0_cp[a].find(hash_cp) == reg_bin_len_0_cp[a].end()) {
		reg_bin_len_0_cp[a][hash_cp] = {0, 0};
	}

	if (std::stoi(cur_pkt["len"]) < 256) {
		reg_bin_len_0_cp[a][hash_cp][0] += 1;
	} else if (std::stoi(cur_pkt["len"]) < 512) {
		reg_bin_len_0_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_len_1_cp[a].find(hash_cp) == reg_bin_len_1_cp[a].end()) {
		reg_bin_len_1_cp[a][hash_cp] = {0, 0};
	}

	if (std::stoi(cur_pkt["len"]) >= 512 && std::stoi(cur_pkt["len"]) < 768) {
		reg_bin_len_1_cp[a][hash_cp][0] += 1;
	} else if (std::stoi(cur_pkt["len"]) >= 768 && std::stoi(cur_pkt["len"]) < 1024) {
		reg_bin_len_1_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_len_2_cp[a].find(hash_cp) == reg_bin_len_2_cp[a].end()) {
		reg_bin_len_2_cp[a][hash_cp] = {0, 0};
	}

	if (std::stoi(cur_pkt["len"]) >= 1024 && std::stoi(cur_pkt["len"]) < 1280) {
		reg_bin_len_2_cp[a][hash_cp][0] += 1;
	} else if (std::stoi(cur_pkt["len"]) >= 1280 && std::stoi(cur_pkt["len"]) < 1536) {
		reg_bin_len_2_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_len_3_cp[a].find(hash_cp) == reg_bin_len_3_cp[a].end()) {
		reg_bin_len_3_cp[a][hash_cp] = {0, 0};
	}

	if (std::stoi(cur_pkt["len"]) >= 1536 && std::stoi(cur_pkt["len"]) < 1792) {
		reg_bin_len_3_cp[a][hash_cp][0] += 1;
	} else if (std::stoi(cur_pkt["len"]) >= 1792 && std::stoi(cur_pkt["len"]) < 2048) {
		reg_bin_len_3_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_len_4_cp[a].find(hash_cp) == reg_bin_len_4_cp[a].end()) {
		reg_bin_len_4_cp[a][hash_cp] = {0, 0};
	}

	if (std::stoi(cur_pkt["len"]) >= 2048 && std::stoi(cur_pkt["len"]) < 2304) {
		reg_bin_len_4_cp[a][hash_cp][0] += 1;
	// } else if (std::stoi(cur_pkt["len"]) >= 2304 && std::stoi(cur_pkt["len"]) < 2560) {
	} else if (std::stoi(cur_pkt["len"]) >= 2304) {
		reg_bin_len_4_cp[a][hash_cp][1] += 1;
	}

	// Bin timestamp updates.

	if (reg_bin_ts_0_cp[a].find(hash_cp) == reg_bin_ts_0_cp[a].end()) {
		reg_bin_ts_0_cp[a][hash_cp] = {0, 0};
	}

	// if (cur_ts_interval < 0.016) {
	if (cur_ts_interval < 0.001) {
		reg_bin_ts_0_cp[a][hash_cp][0] += 1;
	// } else if (cur_ts_interval < 0.032) {
		reg_bin_ts_0_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_ts_1_cp[a].find(hash_cp) == reg_bin_ts_1_cp[a].end()) {
		reg_bin_ts_1_cp[a][hash_cp] = {0, 0};
	}

	// if (cur_ts_interval >= 0.032 && cur_ts_interval < 0.048) {
	if (cur_ts_interval >= 0.005 && cur_ts_interval < 0.010) {
		reg_bin_ts_1_cp[a][hash_cp][0] += 1;
	// } else if (cur_ts_interval >= 0.048 && cur_ts_interval < 0.064) {
	} else if (cur_ts_interval >= 0.010 && cur_ts_interval < 0.015) {
		reg_bin_ts_1_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_ts_2_cp[a].find(hash_cp) == reg_bin_ts_2_cp[a].end()) {
		reg_bin_ts_2_cp[a][hash_cp] = {0, 0};
	}

	// if (cur_ts_interval >= 0.064 && cur_ts_interval < 0.080) {
	if (cur_ts_interval >= 0.015 && cur_ts_interval < 0.020) {
		reg_bin_ts_2_cp[a][hash_cp][0] += 1;
	// } else if (cur_ts_interval >= 0.080 && cur_ts_interval < 0.096) {
	} else if (cur_ts_interval >= 0.020 && cur_ts_interval < 0.025) {
		reg_bin_ts_2_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_ts_3_cp[a].find(hash_cp) == reg_bin_ts_3_cp[a].end()) {
		reg_bin_ts_3_cp[a][hash_cp] = {0, 0};
	}

	// if (cur_ts_interval >= 0.096 && cur_ts_interval < 0.112) {
	if (cur_ts_interval >= 0.025 && cur_ts_interval < 0.030) {
		reg_bin_ts_3_cp[a][hash_cp][0] += 1;
	// } else if (cur_ts_interval >= 0.112 && cur_ts_interval < 0.128) {
	} else if (cur_ts_interval >= 0.030 && cur_ts_interval < 0.035) {
		reg_bin_ts_3_cp[a][hash_cp][1] += 1;
	}

	if (reg_bin_ts_4_cp[a].find(hash_cp) == reg_bin_ts_4_cp[a].end()) {
		reg_bin_ts_4_cp[a][hash_cp] = {0, 0};
	}

	// if (cur_ts_interval >= 0.128 && cur_ts_interval < 0.144) {
	if (cur_ts_interval >= 0.035 && cur_ts_interval < 0.040) {
		reg_bin_ts_4_cp[a][hash_cp][0] += 1;
	// } else if (cur_ts_interval >= 0.144 && cur_ts_interval < 0.160) {
	// } else if (cur_ts_interval >= 0.040 && cur_ts_interval < 0.045) {
	} else if (cur_ts_interval >= 0.040) {
		reg_bin_ts_4_cp[a][hash_cp][1] += 1;
	}

	hv_hdr[14*a]	= "0";
	hv_hdr[14*a+1]	= "0";
	hv_hdr[14*a+2]	= "0";
	hv_hdr[14*a+3]	= "0";
	hv_hdr[14*a+4]	= "0";
	hv_hdr[14*a+5]	= "0";
	hv_hdr[14*a+6]	= "0";
	hv_hdr[14*a+7]	= "0";
	hv_hdr[14*a+8]	= "0";
	hv_hdr[14*a+9]	= "0";
	hv_hdr[14*a+10] = "0";
	hv_hdr[14*a+11] = "0";
	hv_hdr[14*a+12] = "0";
	hv_hdr[14*a+13] = "0";

	hv_bin_len_hdr[2*a]			= "0";
	hv_bin_len_hdr[2*a+1]		= "0";
	hv_bin_len_hdr[8+2*a]		= "0";
	hv_bin_len_hdr[8+2*a+1]		= "0";
	hv_bin_len_hdr[16+2*a]		= "0";
	hv_bin_len_hdr[16+2*a+1]	= "0";
	hv_bin_len_hdr[24+2*a]		= "0";
	hv_bin_len_hdr[24+2*a+1]	= "0";
	hv_bin_len_hdr[32+2*a]		= "0";
	hv_bin_len_hdr[32+2*a+1]	= "0";

	hv_bin_ts_hdr[2*a]		= "0";
	hv_bin_ts_hdr[2*a+1]	= "0";
	hv_bin_ts_hdr[8+2*a]	= "0";
	hv_bin_ts_hdr[8+2*a+1]	= "0";
	hv_bin_ts_hdr[16+2*a]	= "0";
	hv_bin_ts_hdr[16+2*a+1]	= "0";
	hv_bin_ts_hdr[24+2*a]	= "0";
	hv_bin_ts_hdr[24+2*a+1]	= "0";
	hv_bin_ts_hdr[32+2*a]	= "0";
	hv_bin_ts_hdr[32+2*a+1]	= "0";
}

void FCHv::reg_read_cp(int a, int b, int c, int d) {
	for (const auto &iter : reg_ts_cp[a]) {
		if (reg_ts_cp[a][iter.first][0] != 0 && reg_ts_cp[a][iter.first][1] != 0) {
			double ts_interval_a = std::stod(cur_pkt["ts"]) - reg_ts_cp[a][iter.first][1];

			if ((ts_interval_a - timeout) > EPS) {
				timeout_toggle = true;
				hv_hdr[14*a]	=
						std::to_string(static_cast<double>(reg_ts_cp[a][iter.first][0]));
				hv_hdr[14*a+1]	=
						std::to_string(static_cast<double>(reg_ts_cp[a][iter.first][1]));
				hv_hdr[14*a+2]	=
					std::to_string(static_cast<double>(reg_ts_agg_cp[a][iter.first]));
				hv_hdr[14*a+3]	= reg_ip_cp[a][iter.first][0];
				hv_hdr[14*a+4]	= reg_ip_cp[a][iter.first][1];
				hv_hdr[14*a+5]	= std::to_string(reg_port_cp[a][iter.first][0]);
				hv_hdr[14*a+6]	= std::to_string(reg_port_cp[a][iter.first][1]);
				hv_hdr[14*a+7]	= std::to_string(reg_flags_cp[a][iter.first][0]);
				hv_hdr[14*a+8]	= std::to_string(reg_flags_cp[a][iter.first][1]);
				hv_hdr[14*a+9]	= std::to_string(reg_flags_cp[a][iter.first][2]);
				hv_hdr[14*a+10] = std::to_string(reg_flags_cp[a][iter.first][3]);
				hv_hdr[14*a+11] = std::to_string(reg_data_cp[a][iter.first][0]);
				hv_hdr[14*a+12] = std::to_string(reg_data_cp[a][iter.first][1]);

				if (reg_data_cp[a][iter.first][0] > 15) {
					hv_hdr[14*a+13] = "1";
				} else {
					hv_hdr[14*a+13] = "0";
				}

				hv_bin_len_hdr[2*a]			= std::to_string(reg_bin_len_0_cp[a][iter.first][0]);
				hv_bin_len_hdr[2*a+1]		= std::to_string(reg_bin_len_0_cp[a][iter.first][1]);
				hv_bin_len_hdr[8+2*a]		= std::to_string(reg_bin_len_1_cp[a][iter.first][0]);
				hv_bin_len_hdr[8+2*a+1]		= std::to_string(reg_bin_len_1_cp[a][iter.first][1]);
				hv_bin_len_hdr[16+2*a]		= std::to_string(reg_bin_len_2_cp[a][iter.first][0]);
				hv_bin_len_hdr[16+2*a+1]	= std::to_string(reg_bin_len_2_cp[a][iter.first][1]);
				hv_bin_len_hdr[24+2*a]		= std::to_string(reg_bin_len_3_cp[a][iter.first][0]);
				hv_bin_len_hdr[24+2*a+1]	= std::to_string(reg_bin_len_3_cp[a][iter.first][1]);
				hv_bin_len_hdr[32+2*a]		= std::to_string(reg_bin_len_4_cp[a][iter.first][0]);
				hv_bin_len_hdr[32+2*a+1]	= std::to_string(reg_bin_len_4_cp[a][iter.first][1]);

				hv_bin_ts_hdr[2*a]		= std::to_string(reg_bin_ts_0_cp[a][iter.first][0]);
				hv_bin_ts_hdr[2*a+1]	= std::to_string(reg_bin_ts_0_cp[a][iter.first][1]);
				hv_bin_ts_hdr[8+2*a]	= std::to_string(reg_bin_ts_1_cp[a][iter.first][0]);
				hv_bin_ts_hdr[8+2*a+1]	= std::to_string(reg_bin_ts_1_cp[a][iter.first][1]);
				hv_bin_ts_hdr[16+2*a]	= std::to_string(reg_bin_ts_2_cp[a][iter.first][0]);
				hv_bin_ts_hdr[16+2*a+1]	= std::to_string(reg_bin_ts_2_cp[a][iter.first][1]);
				hv_bin_ts_hdr[24+2*a]	= std::to_string(reg_bin_ts_3_cp[a][iter.first][0]);
				hv_bin_ts_hdr[24+2*a+1]	= std::to_string(reg_bin_ts_3_cp[a][iter.first][1]);
				hv_bin_ts_hdr[32+2*a]	= std::to_string(reg_bin_ts_4_cp[a][iter.first][0]);
				hv_bin_ts_hdr[32+2*a+1]	= std::to_string(reg_bin_ts_4_cp[a][iter.first][1]);

				hv_hdr[14*b]	= "0";
				hv_hdr[14*b+1]	= "0";
				hv_hdr[14*b+2]	= "0";
				hv_hdr[14*b+3]	= "0";
				hv_hdr[14*b+4]	= "0";
				hv_hdr[14*b+5]	= "0";
				hv_hdr[14*b+6]	= "0";
				hv_hdr[14*b+7]	= "0";
				hv_hdr[14*b+8]	= "0";
				hv_hdr[14*b+9]	= "0";
				hv_hdr[14*b+10] = "0";
				hv_hdr[14*b+11] = "0";
				hv_hdr[14*b+12] = "0";
				hv_hdr[14*b+13] = "0";

				hv_bin_len_hdr[2*b]			= "0";
				hv_bin_len_hdr[2*b+1]		= "0";
				hv_bin_len_hdr[8+2*b]		= "0";
				hv_bin_len_hdr[8+2*b+1]		= "0";
				hv_bin_len_hdr[16+2*b]		= "0";
				hv_bin_len_hdr[16+2*b+1]	= "0";
				hv_bin_len_hdr[24+2*b]		= "0";
				hv_bin_len_hdr[24+2*b+1]	= "0";
				hv_bin_len_hdr[32+2*b]		= "0";
				hv_bin_len_hdr[32+2*b+1]	= "0";

				hv_bin_ts_hdr[2*b]		= "0";
				hv_bin_ts_hdr[2*b+1]	= "0";
				hv_bin_ts_hdr[8+2*b]	= "0";
				hv_bin_ts_hdr[8+2*b+1]	= "0";
				hv_bin_ts_hdr[16+2*b]	= "0";
				hv_bin_ts_hdr[16+2*b+1]	= "0";
				hv_bin_ts_hdr[24+2*b]	= "0";
				hv_bin_ts_hdr[24+2*b+1]	= "0";
				hv_bin_ts_hdr[32+2*b]	= "0";
				hv_bin_ts_hdr[32+2*b+1]	= "0";

				hv_hdr[14*c]	= "0";
				hv_hdr[14*c+1]	= "0";
				hv_hdr[14*c+2]	= "0";
				hv_hdr[14*c+3]	= "0";
				hv_hdr[14*c+4]	= "0";
				hv_hdr[14*c+5]	= "0";
				hv_hdr[14*c+6]	= "0";
				hv_hdr[14*c+7]	= "0";
				hv_hdr[14*c+8]	= "0";
				hv_hdr[14*c+9]	= "0";
				hv_hdr[14*c+10] = "0";
				hv_hdr[14*c+11] = "0";
				hv_hdr[14*c+12] = "0";
				hv_hdr[14*c+13] = "0";

				hv_bin_len_hdr[2*c]			= "0";
				hv_bin_len_hdr[2*c+1]		= "0";
				hv_bin_len_hdr[8+2*c]		= "0";
				hv_bin_len_hdr[8+2*c+1]		= "0";
				hv_bin_len_hdr[16+2*c]		= "0";
				hv_bin_len_hdr[16+2*c+1]	= "0";
				hv_bin_len_hdr[24+2*c]		= "0";
				hv_bin_len_hdr[24+2*c+1]	= "0";
				hv_bin_len_hdr[32+2*c]		= "0";
				hv_bin_len_hdr[32+2*c+1]	= "0";

				hv_bin_ts_hdr[2*c]		= "0";
				hv_bin_ts_hdr[2*c+1]	= "0";
				hv_bin_ts_hdr[8+2*c]	= "0";
				hv_bin_ts_hdr[8+2*c+1]	= "0";
				hv_bin_ts_hdr[16+2*c]	= "0";
				hv_bin_ts_hdr[16+2*c+1]	= "0";
				hv_bin_ts_hdr[24+2*c]	= "0";
				hv_bin_ts_hdr[24+2*c+1]	= "0";
				hv_bin_ts_hdr[32+2*c]	= "0";
				hv_bin_ts_hdr[32+2*c+1]	= "0";

				hv_hdr[14*d]	= "0";
				hv_hdr[14*d+1]	= "0";
				hv_hdr[14*d+2]	= "0";
				hv_hdr[14*d+3]	= "0";
				hv_hdr[14*d+4]	= "0";
				hv_hdr[14*d+5]	= "0";
				hv_hdr[14*d+6]	= "0";
				hv_hdr[14*d+7]	= "0";
				hv_hdr[14*d+8]	= "0";
				hv_hdr[14*d+9]	= "0";
				hv_hdr[14*d+10] = "0";
				hv_hdr[14*d+11] = "0";
				hv_hdr[14*d+12] = "0";
				hv_hdr[14*d+13] = "0";

				hv_bin_len_hdr[2*d]			= "0";
				hv_bin_len_hdr[2*d+1]		= "0";
				hv_bin_len_hdr[8+2*d]		= "0";
				hv_bin_len_hdr[8+2*d+1]		= "0";
				hv_bin_len_hdr[16+2*d]		= "0";
				hv_bin_len_hdr[16+2*d+1]	= "0";
				hv_bin_len_hdr[24+2*d]		= "0";
				hv_bin_len_hdr[24+2*d+1]	= "0";
				hv_bin_len_hdr[32+2*d]		= "0";
				hv_bin_len_hdr[32+2*d+1]	= "0";

				hv_bin_ts_hdr[2*d]		= "0";
				hv_bin_ts_hdr[2*d+1]	= "0";
				hv_bin_ts_hdr[8+2*d]	= "0";
				hv_bin_ts_hdr[8+2*d+1]	= "0";
				hv_bin_ts_hdr[16+2*d]	= "0";
				hv_bin_ts_hdr[16+2*d+1]	= "0";
				hv_bin_ts_hdr[24+2*d]	= "0";
				hv_bin_ts_hdr[24+2*d+1]	= "0";
				hv_bin_ts_hdr[32+2*d]	= "0";
				hv_bin_ts_hdr[32+2*d+1]	= "0";

				flow_global_cnt++;
				cur_samples.push_back(as_sample());
				reset_regs_cp(a, iter.first);
			}
		}
	}
}

void FCHv::reg_read_end_dp(int a, int b, int c, int d) {
	for (const auto &iter : reg_ts_dp[a]) {
		if (reg_ts_dp[a][iter.first][0] != 0 && reg_ts_dp[a][iter.first][1] != 0) {
			hv_hdr[14*a]	= std::to_string(static_cast<double>(reg_ts_dp[a][iter.first][0]));
			hv_hdr[14*a+1]	= std::to_string(static_cast<double>(reg_ts_dp[a][iter.first][1]));
			hv_hdr[14*a+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[a][iter.first]));
			hv_hdr[14*a+3]	= reg_ip_dp[a][iter.first][0];
			hv_hdr[14*a+4]	= reg_ip_dp[a][iter.first][1];
			hv_hdr[14*a+5]	= std::to_string(reg_port_dp[a][iter.first][0]);
			hv_hdr[14*a+6]	= std::to_string(reg_port_dp[a][iter.first][1]);
			hv_hdr[14*a+7]	= std::to_string(reg_flags_dp[a][iter.first][0]);
			hv_hdr[14*a+8]	= std::to_string(reg_flags_dp[a][iter.first][1]);
			hv_hdr[14*a+9]	= std::to_string(reg_flags_dp[a][iter.first][2]);
			hv_hdr[14*a+10] = std::to_string(reg_flags_dp[a][iter.first][3]);
			hv_hdr[14*a+11] = std::to_string(reg_data_dp[a][iter.first][0]);
			hv_hdr[14*a+12] = std::to_string(reg_data_dp[a][iter.first][1]);

			if (reg_data_dp[a][iter.first][0] > 15) {
				hv_hdr[14*a+13] = "1";
			} else {
				hv_hdr[14*a+13] = "0";
			}

			hv_bin_len_hdr[2*a]			= std::to_string(reg_bin_len_0_dp[a][iter.first][0]);
			hv_bin_len_hdr[2*a+1]		= std::to_string(reg_bin_len_0_dp[a][iter.first][1]);
			hv_bin_len_hdr[8+2*a]		= std::to_string(reg_bin_len_1_dp[a][iter.first][0]);
			hv_bin_len_hdr[8+2*a+1]		= std::to_string(reg_bin_len_1_dp[a][iter.first][1]);
			hv_bin_len_hdr[16+2*a]		= std::to_string(reg_bin_len_2_dp[a][iter.first][0]);
			hv_bin_len_hdr[16+2*a+1]	= std::to_string(reg_bin_len_2_dp[a][iter.first][1]);
			hv_bin_len_hdr[24+2*a]		= std::to_string(reg_bin_len_3_dp[a][iter.first][0]);
			hv_bin_len_hdr[24+2*a+1]	= std::to_string(reg_bin_len_3_dp[a][iter.first][1]);
			hv_bin_len_hdr[32+2*a]		= std::to_string(reg_bin_len_4_dp[a][iter.first][0]);
			hv_bin_len_hdr[32+2*a+1]	= std::to_string(reg_bin_len_4_dp[a][iter.first][1]);

			hv_bin_ts_hdr[2*a]		= std::to_string(reg_bin_ts_0_dp[a][iter.first][0]);
			hv_bin_ts_hdr[2*a+1]	= std::to_string(reg_bin_ts_0_dp[a][iter.first][1]);
			hv_bin_ts_hdr[8+2*a]	= std::to_string(reg_bin_ts_1_dp[a][iter.first][0]);
			hv_bin_ts_hdr[8+2*a+1]	= std::to_string(reg_bin_ts_1_dp[a][iter.first][1]);
			hv_bin_ts_hdr[16+2*a]	= std::to_string(reg_bin_ts_2_dp[a][iter.first][0]);
			hv_bin_ts_hdr[16+2*a+1]	= std::to_string(reg_bin_ts_2_dp[a][iter.first][1]);
			hv_bin_ts_hdr[24+2*a]	= std::to_string(reg_bin_ts_3_dp[a][iter.first][0]);
			hv_bin_ts_hdr[24+2*a+1]	= std::to_string(reg_bin_ts_3_dp[a][iter.first][1]);
			hv_bin_ts_hdr[32+2*a]	= std::to_string(reg_bin_ts_4_dp[a][iter.first][0]);
			hv_bin_ts_hdr[32+2*a+1]	= std::to_string(reg_bin_ts_4_dp[a][iter.first][1]);

			hv_hdr[14*b]	= "0";
			hv_hdr[14*b+1]	= "0";
			hv_hdr[14*b+2]	= "0";
			hv_hdr[14*b+3]	= "0";
			hv_hdr[14*b+4]	= "0";
			hv_hdr[14*b+5]	= "0";
			hv_hdr[14*b+6]	= "0";
			hv_hdr[14*b+7]	= "0";
			hv_hdr[14*b+8]	= "0";
			hv_hdr[14*b+9]	= "0";
			hv_hdr[14*b+10] = "0";
			hv_hdr[14*b+11] = "0";
			hv_hdr[14*b+12] = "0";
			hv_hdr[14*b+13] = "0";

			hv_bin_len_hdr[2*b]			= "0";
			hv_bin_len_hdr[2*b+1]		= "0";
			hv_bin_len_hdr[8+2*b]		= "0";
			hv_bin_len_hdr[8+2*b+1]		= "0";
			hv_bin_len_hdr[16+2*b]		= "0";
			hv_bin_len_hdr[16+2*b+1]	= "0";
			hv_bin_len_hdr[24+2*b]		= "0";
			hv_bin_len_hdr[24+2*b+1]	= "0";
			hv_bin_len_hdr[32+2*b]		= "0";
			hv_bin_len_hdr[32+2*b+1]	= "0";

			hv_bin_ts_hdr[2*b]		= "0";
			hv_bin_ts_hdr[2*b+1]	= "0";
			hv_bin_ts_hdr[8+2*b]	= "0";
			hv_bin_ts_hdr[8+2*b+1]	= "0";
			hv_bin_ts_hdr[16+2*b]	= "0";
			hv_bin_ts_hdr[16+2*b+1]	= "0";
			hv_bin_ts_hdr[24+2*b]	= "0";
			hv_bin_ts_hdr[24+2*b+1]	= "0";
			hv_bin_ts_hdr[32+2*b]	= "0";
			hv_bin_ts_hdr[32+2*b+1]	= "0";

			hv_hdr[14*c]	= "0";
			hv_hdr[14*c+1]	= "0";
			hv_hdr[14*c+2]	= "0";
			hv_hdr[14*c+3]	= "0";
			hv_hdr[14*c+4]	= "0";
			hv_hdr[14*c+5]	= "0";
			hv_hdr[14*c+6]	= "0";
			hv_hdr[14*c+7]	= "0";
			hv_hdr[14*c+8]	= "0";
			hv_hdr[14*c+9]	= "0";
			hv_hdr[14*c+10] = "0";
			hv_hdr[14*c+11] = "0";
			hv_hdr[14*c+12] = "0";
			hv_hdr[14*c+13] = "0";

			hv_bin_len_hdr[2*c]			= "0";
			hv_bin_len_hdr[2*c+1]		= "0";
			hv_bin_len_hdr[8+2*c]		= "0";
			hv_bin_len_hdr[8+2*c+1]		= "0";
			hv_bin_len_hdr[16+2*c]		= "0";
			hv_bin_len_hdr[16+2*c+1]	= "0";
			hv_bin_len_hdr[24+2*c]		= "0";
			hv_bin_len_hdr[24+2*c+1]	= "0";
			hv_bin_len_hdr[32+2*c]		= "0";
			hv_bin_len_hdr[32+2*c+1]	= "0";

			hv_bin_ts_hdr[2*c]		= "0";
			hv_bin_ts_hdr[2*c+1]	= "0";
			hv_bin_ts_hdr[8+2*c]	= "0";
			hv_bin_ts_hdr[8+2*c+1]	= "0";
			hv_bin_ts_hdr[16+2*c]	= "0";
			hv_bin_ts_hdr[16+2*c+1]	= "0";
			hv_bin_ts_hdr[24+2*c]	= "0";
			hv_bin_ts_hdr[24+2*c+1]	= "0";
			hv_bin_ts_hdr[32+2*c]	= "0";
			hv_bin_ts_hdr[32+2*c+1]	= "0";

			hv_hdr[14*d]	= "0";
			hv_hdr[14*d+1]	= "0";
			hv_hdr[14*d+2]	= "0";
			hv_hdr[14*d+3]	= "0";
			hv_hdr[14*d+4]	= "0";
			hv_hdr[14*d+5]	= "0";
			hv_hdr[14*d+6]	= "0";
			hv_hdr[14*d+7]	= "0";
			hv_hdr[14*d+8]	= "0";
			hv_hdr[14*d+9]	= "0";
			hv_hdr[14*d+10] = "0";
			hv_hdr[14*d+11] = "0";
			hv_hdr[14*d+12] = "0";
			hv_hdr[14*d+13] = "0";

			hv_bin_len_hdr[2*d]			= "0";
			hv_bin_len_hdr[2*d+1]		= "0";
			hv_bin_len_hdr[8+2*d]		= "0";
			hv_bin_len_hdr[8+2*d+1]		= "0";
			hv_bin_len_hdr[16+2*d]		= "0";
			hv_bin_len_hdr[16+2*d+1]	= "0";
			hv_bin_len_hdr[24+2*d]		= "0";
			hv_bin_len_hdr[24+2*d+1]	= "0";
			hv_bin_len_hdr[32+2*d]		= "0";
			hv_bin_len_hdr[32+2*d+1]	= "0";

			hv_bin_ts_hdr[2*d]		= "0";
			hv_bin_ts_hdr[2*d+1]	= "0";
			hv_bin_ts_hdr[8+2*d]	= "0";
			hv_bin_ts_hdr[8+2*d+1]	= "0";
			hv_bin_ts_hdr[16+2*d]	= "0";
			hv_bin_ts_hdr[16+2*d+1]	= "0";
			hv_bin_ts_hdr[24+2*d]	= "0";
			hv_bin_ts_hdr[24+2*d+1]	= "0";
			hv_bin_ts_hdr[32+2*d]	= "0";
			hv_bin_ts_hdr[32+2*d+1]	= "0";

			flow_global_cnt++;
			cur_samples.push_back(as_sample());
			reset_regs_dp(a, iter.first);
		}
	}

	for (const auto &iter : reg_ts_dp[b]) {
		if (reg_ts_dp[b][iter.first][0] != 0 && reg_ts_dp[b][iter.first][1] != 0) {
			hv_hdr[14*b]	= std::to_string(static_cast<double>(reg_ts_dp[b][iter.first][0]));
			hv_hdr[14*b+1]	= std::to_string(static_cast<double>(reg_ts_dp[b][iter.first][1]));
			hv_hdr[14*b+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[b][iter.first]));
			hv_hdr[14*b+3]	= reg_ip_dp[b][iter.first][0];
			std::cout << "TEST " << reg_ip_dp[b][iter.first][0] << std::endl;
			hv_hdr[14*b+4]	= reg_ip_dp[b][iter.first][1];
			hv_hdr[14*b+5]	= std::to_string(reg_port_dp[b][iter.first][0]);
			hv_hdr[14*b+6]	= std::to_string(reg_port_dp[b][iter.first][1]);
			hv_hdr[14*b+7]	= std::to_string(reg_flags_dp[b][iter.first][0]);
			hv_hdr[14*b+8]	= std::to_string(reg_flags_dp[b][iter.first][1]);
			hv_hdr[14*b+9]	= std::to_string(reg_flags_dp[b][iter.first][2]);
			hv_hdr[14*b+10] = std::to_string(reg_flags_dp[b][iter.first][3]);
			hv_hdr[14*b+11] = std::to_string(reg_data_dp[b][iter.first][0]);
			hv_hdr[14*b+12] = std::to_string(reg_data_dp[b][iter.first][1]);

			if (reg_data_dp[b][iter.first][0] > 15) {
				hv_hdr[14*b+13] = "1";
			} else {
				hv_hdr[14*b+13] = "0";
			}

			hv_bin_len_hdr[2*b]			= std::to_string(reg_bin_len_0_dp[b][iter.first][0]);
			hv_bin_len_hdr[2*b+1]		= std::to_string(reg_bin_len_0_dp[b][iter.first][1]);
			hv_bin_len_hdr[8+2*b]		= std::to_string(reg_bin_len_1_dp[b][iter.first][0]);
			hv_bin_len_hdr[8+2*b+1]		= std::to_string(reg_bin_len_1_dp[b][iter.first][1]);
			hv_bin_len_hdr[16+2*b]		= std::to_string(reg_bin_len_2_dp[b][iter.first][0]);
			hv_bin_len_hdr[16+2*b+1]	= std::to_string(reg_bin_len_2_dp[b][iter.first][1]);
			hv_bin_len_hdr[24+2*b]		= std::to_string(reg_bin_len_3_dp[b][iter.first][0]);
			hv_bin_len_hdr[24+2*b+1]	= std::to_string(reg_bin_len_3_dp[b][iter.first][1]);
			hv_bin_len_hdr[32+2*b]		= std::to_string(reg_bin_len_4_dp[b][iter.first][0]);
			hv_bin_len_hdr[32+2*b+1]	= std::to_string(reg_bin_len_4_dp[b][iter.first][1]);

			hv_bin_ts_hdr[2*b]		= std::to_string(reg_bin_ts_0_dp[b][iter.first][0]);
			hv_bin_ts_hdr[2*b+1]	= std::to_string(reg_bin_ts_0_dp[b][iter.first][1]);
			hv_bin_ts_hdr[8+2*b]	= std::to_string(reg_bin_ts_1_dp[b][iter.first][0]);
			hv_bin_ts_hdr[8+2*b+1]	= std::to_string(reg_bin_ts_1_dp[b][iter.first][1]);
			hv_bin_ts_hdr[16+2*b]	= std::to_string(reg_bin_ts_2_dp[b][iter.first][0]);
			hv_bin_ts_hdr[16+2*b+1]	= std::to_string(reg_bin_ts_2_dp[b][iter.first][1]);
			hv_bin_ts_hdr[24+2*b]	= std::to_string(reg_bin_ts_3_dp[b][iter.first][0]);
			hv_bin_ts_hdr[24+2*b+1]	= std::to_string(reg_bin_ts_3_dp[b][iter.first][1]);
			hv_bin_ts_hdr[32+2*b]	= std::to_string(reg_bin_ts_4_dp[b][iter.first][0]);
			hv_bin_ts_hdr[32+2*b+1]	= std::to_string(reg_bin_ts_4_dp[b][iter.first][1]);

			hv_hdr[14*a]	= "0";
			hv_hdr[14*a+1]	= "0";
			hv_hdr[14*a+2]	= "0";
			hv_hdr[14*a+3]	= "0";
			hv_hdr[14*a+4]	= "0";
			hv_hdr[14*a+5]	= "0";
			hv_hdr[14*a+6]	= "0";
			hv_hdr[14*a+7]	= "0";
			hv_hdr[14*a+8]	= "0";
			hv_hdr[14*a+9]	= "0";
			hv_hdr[14*a+10] = "0";
			hv_hdr[14*a+11] = "0";
			hv_hdr[14*a+12] = "0";
			hv_hdr[14*a+13] = "0";

			hv_bin_len_hdr[2*a]			= "0";
			hv_bin_len_hdr[2*a+1]		= "0";
			hv_bin_len_hdr[8+2*a]		= "0";
			hv_bin_len_hdr[8+2*a+1]		= "0";
			hv_bin_len_hdr[16+2*a]		= "0";
			hv_bin_len_hdr[16+2*a+1]	= "0";
			hv_bin_len_hdr[24+2*a]		= "0";
			hv_bin_len_hdr[24+2*a+1]	= "0";
			hv_bin_len_hdr[32+2*a]		= "0";
			hv_bin_len_hdr[32+2*a+1]	= "0";

			hv_bin_ts_hdr[2*a]		= "0";
			hv_bin_ts_hdr[2*a+1]	= "0";
			hv_bin_ts_hdr[8+2*a]	= "0";
			hv_bin_ts_hdr[8+2*a+1]	= "0";
			hv_bin_ts_hdr[16+2*a]	= "0";
			hv_bin_ts_hdr[16+2*a+1]	= "0";
			hv_bin_ts_hdr[24+2*a]	= "0";
			hv_bin_ts_hdr[24+2*a+1]	= "0";
			hv_bin_ts_hdr[32+2*a]	= "0";
			hv_bin_ts_hdr[32+2*a+1]	= "0";

			hv_hdr[14*c]	= "0";
			hv_hdr[14*c+1]	= "0";
			hv_hdr[14*c+2]	= "0";
			hv_hdr[14*c+3]	= "0";
			hv_hdr[14*c+4]	= "0";
			hv_hdr[14*c+5]	= "0";
			hv_hdr[14*c+6]	= "0";
			hv_hdr[14*c+7]	= "0";
			hv_hdr[14*c+8]	= "0";
			hv_hdr[14*c+9]	= "0";
			hv_hdr[14*c+10] = "0";
			hv_hdr[14*c+11] = "0";
			hv_hdr[14*c+12] = "0";
			hv_hdr[14*c+13] = "0";

			hv_bin_len_hdr[2*c]			= "0";
			hv_bin_len_hdr[2*c+1]		= "0";
			hv_bin_len_hdr[8+2*c]		= "0";
			hv_bin_len_hdr[8+2*c+1]		= "0";
			hv_bin_len_hdr[16+2*c]		= "0";
			hv_bin_len_hdr[16+2*c+1]	= "0";
			hv_bin_len_hdr[24+2*c]		= "0";
			hv_bin_len_hdr[24+2*c+1]	= "0";
			hv_bin_len_hdr[32+2*c]		= "0";
			hv_bin_len_hdr[32+2*c+1]	= "0";

			hv_bin_ts_hdr[2*c]		= "0";
			hv_bin_ts_hdr[2*c+1]	= "0";
			hv_bin_ts_hdr[8+2*c]	= "0";
			hv_bin_ts_hdr[8+2*c+1]	= "0";
			hv_bin_ts_hdr[16+2*c]	= "0";
			hv_bin_ts_hdr[16+2*c+1]	= "0";
			hv_bin_ts_hdr[24+2*c]	= "0";
			hv_bin_ts_hdr[24+2*c+1]	= "0";
			hv_bin_ts_hdr[32+2*c]	= "0";
			hv_bin_ts_hdr[32+2*c+1]	= "0";

			hv_hdr[14*d]	= "0";
			hv_hdr[14*d+1]	= "0";
			hv_hdr[14*d+2]	= "0";
			hv_hdr[14*d+3]	= "0";
			hv_hdr[14*d+4]	= "0";
			hv_hdr[14*d+5]	= "0";
			hv_hdr[14*d+6]	= "0";
			hv_hdr[14*d+7]	= "0";
			hv_hdr[14*d+8]	= "0";
			hv_hdr[14*d+9]	= "0";
			hv_hdr[14*d+10] = "0";
			hv_hdr[14*d+11] = "0";
			hv_hdr[14*d+12] = "0";
			hv_hdr[14*d+13] = "0";

			hv_bin_len_hdr[2*d]			= "0";
			hv_bin_len_hdr[2*d+1]		= "0";
			hv_bin_len_hdr[8+2*d]		= "0";
			hv_bin_len_hdr[8+2*d+1]		= "0";
			hv_bin_len_hdr[16+2*d]		= "0";
			hv_bin_len_hdr[16+2*d+1]	= "0";
			hv_bin_len_hdr[24+2*d]		= "0";
			hv_bin_len_hdr[24+2*d+1]	= "0";
			hv_bin_len_hdr[32+2*d]		= "0";
			hv_bin_len_hdr[32+2*d+1]	= "0";

			hv_bin_ts_hdr[2*d]		= "0";
			hv_bin_ts_hdr[2*d+1]	= "0";
			hv_bin_ts_hdr[8+2*d]	= "0";
			hv_bin_ts_hdr[8+2*d+1]	= "0";
			hv_bin_ts_hdr[16+2*d]	= "0";
			hv_bin_ts_hdr[16+2*d+1]	= "0";
			hv_bin_ts_hdr[24+2*d]	= "0";
			hv_bin_ts_hdr[24+2*d+1]	= "0";
			hv_bin_ts_hdr[32+2*d]	= "0";
			hv_bin_ts_hdr[32+2*d+1]	= "0";

			flow_global_cnt++;
			cur_samples.push_back(as_sample());
			reset_regs_dp(b, iter.first);
		}
	}

	for (const auto &iter : reg_ts_dp[c]) {
		if (reg_ts_dp[c][iter.first][0] != 0 && reg_ts_dp[c][iter.first][1] != 0) {
			hv_hdr[14*c]	= std::to_string(static_cast<double>(reg_ts_dp[c][iter.first][0]));
			hv_hdr[14*c+1]	= std::to_string(static_cast<double>(reg_ts_dp[c][iter.first][1]));
			hv_hdr[14*c+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[c][iter.first]));
			hv_hdr[14*c+3]	= reg_ip_dp[c][iter.first][0];
			hv_hdr[14*c+4]	= reg_ip_dp[c][iter.first][1];
			hv_hdr[14*c+5]	= std::to_string(reg_port_dp[c][iter.first][0]);
			hv_hdr[14*c+6]	= std::to_string(reg_port_dp[c][iter.first][1]);
			hv_hdr[14*c+7]	= std::to_string(reg_flags_dp[c][iter.first][0]);
			hv_hdr[14*c+8]	= std::to_string(reg_flags_dp[c][iter.first][1]);
			hv_hdr[14*c+9]	= std::to_string(reg_flags_dp[c][iter.first][2]);
			hv_hdr[14*c+10] = std::to_string(reg_flags_dp[c][iter.first][3]);
			hv_hdr[14*c+11] = std::to_string(reg_data_dp[c][iter.first][0]);
			hv_hdr[14*c+12] = std::to_string(reg_data_dp[c][iter.first][1]);

			if (reg_data_dp[c][iter.first][0] > 15) {
				hv_hdr[14*c+13] = "1";
			} else {
				hv_hdr[14*c+13] = "0";
			}

			hv_bin_len_hdr[2*c]			= std::to_string(reg_bin_len_0_dp[c][iter.first][0]);
			hv_bin_len_hdr[2*c+1]		= std::to_string(reg_bin_len_0_dp[c][iter.first][1]);
			hv_bin_len_hdr[8+2*c]		= std::to_string(reg_bin_len_1_dp[c][iter.first][0]);
			hv_bin_len_hdr[8+2*c+1]		= std::to_string(reg_bin_len_1_dp[c][iter.first][1]);
			hv_bin_len_hdr[16+2*c]		= std::to_string(reg_bin_len_2_dp[c][iter.first][0]);
			hv_bin_len_hdr[16+2*c+1]	= std::to_string(reg_bin_len_2_dp[c][iter.first][1]);
			hv_bin_len_hdr[24+2*c]		= std::to_string(reg_bin_len_3_dp[c][iter.first][0]);
			hv_bin_len_hdr[24+2*c+1]	= std::to_string(reg_bin_len_3_dp[c][iter.first][1]);
			hv_bin_len_hdr[32+2*c]		= std::to_string(reg_bin_len_4_dp[c][iter.first][0]);
			hv_bin_len_hdr[32+2*c+1]	= std::to_string(reg_bin_len_4_dp[c][iter.first][1]);

			hv_bin_ts_hdr[2*c]		= std::to_string(reg_bin_ts_0_dp[c][iter.first][0]);
			hv_bin_ts_hdr[2*c+1]	= std::to_string(reg_bin_ts_0_dp[c][iter.first][1]);
			hv_bin_ts_hdr[8+2*c]	= std::to_string(reg_bin_ts_1_dp[c][iter.first][0]);
			hv_bin_ts_hdr[8+2*c+1]	= std::to_string(reg_bin_ts_1_dp[c][iter.first][1]);
			hv_bin_ts_hdr[16+2*c]	= std::to_string(reg_bin_ts_2_dp[c][iter.first][0]);
			hv_bin_ts_hdr[16+2*c+1]	= std::to_string(reg_bin_ts_2_dp[c][iter.first][1]);
			hv_bin_ts_hdr[24+2*c]	= std::to_string(reg_bin_ts_3_dp[c][iter.first][0]);
			hv_bin_ts_hdr[24+2*c+1]	= std::to_string(reg_bin_ts_3_dp[c][iter.first][1]);
			hv_bin_ts_hdr[32+2*c]	= std::to_string(reg_bin_ts_4_dp[c][iter.first][0]);
			hv_bin_ts_hdr[32+2*c+1]	= std::to_string(reg_bin_ts_4_dp[c][iter.first][1]);

			hv_hdr[14*a]	= "0";
			hv_hdr[14*a+1]	= "0";
			hv_hdr[14*a+2]	= "0";
			hv_hdr[14*a+3]	= "0";
			hv_hdr[14*a+4]	= "0";
			hv_hdr[14*a+5]	= "0";
			hv_hdr[14*a+6]	= "0";
			hv_hdr[14*a+7]	= "0";
			hv_hdr[14*a+8]	= "0";
			hv_hdr[14*a+9]	= "0";
			hv_hdr[14*a+10] = "0";
			hv_hdr[14*a+11] = "0";
			hv_hdr[14*a+12] = "0";
			hv_hdr[14*a+13] = "0";

			hv_bin_len_hdr[2*a]			= "0";
			hv_bin_len_hdr[2*a+1]		= "0";
			hv_bin_len_hdr[8+2*a]		= "0";
			hv_bin_len_hdr[8+2*a+1]		= "0";
			hv_bin_len_hdr[16+2*a]		= "0";
			hv_bin_len_hdr[16+2*a+1]	= "0";
			hv_bin_len_hdr[24+2*a]		= "0";
			hv_bin_len_hdr[24+2*a+1]	= "0";
			hv_bin_len_hdr[32+2*a]		= "0";
			hv_bin_len_hdr[32+2*a+1]	= "0";

			hv_bin_ts_hdr[2*a]		= "0";
			hv_bin_ts_hdr[2*a+1]	= "0";
			hv_bin_ts_hdr[8+2*a]	= "0";
			hv_bin_ts_hdr[8+2*a+1]	= "0";
			hv_bin_ts_hdr[16+2*a]	= "0";
			hv_bin_ts_hdr[16+2*a+1]	= "0";
			hv_bin_ts_hdr[24+2*a]	= "0";
			hv_bin_ts_hdr[24+2*a+1]	= "0";
			hv_bin_ts_hdr[32+2*a]	= "0";
			hv_bin_ts_hdr[32+2*a+1]	= "0";

			hv_hdr[14*b]	= "0";
			hv_hdr[14*b+1]	= "0";
			hv_hdr[14*b+2]	= "0";
			hv_hdr[14*b+3]	= "0";
			hv_hdr[14*b+4]	= "0";
			hv_hdr[14*b+5]	= "0";
			hv_hdr[14*b+6]	= "0";
			hv_hdr[14*b+7]	= "0";
			hv_hdr[14*b+8]	= "0";
			hv_hdr[14*b+9]	= "0";
			hv_hdr[14*b+10] = "0";
			hv_hdr[14*b+11] = "0";
			hv_hdr[14*b+12] = "0";
			hv_hdr[14*b+13] = "0";

			hv_bin_len_hdr[2*b]			= "0";
			hv_bin_len_hdr[2*b+1]		= "0";
			hv_bin_len_hdr[8+2*b]		= "0";
			hv_bin_len_hdr[8+2*b+1]		= "0";
			hv_bin_len_hdr[16+2*b]		= "0";
			hv_bin_len_hdr[16+2*b+1]	= "0";
			hv_bin_len_hdr[24+2*b]		= "0";
			hv_bin_len_hdr[24+2*b+1]	= "0";
			hv_bin_len_hdr[32+2*b]		= "0";
			hv_bin_len_hdr[32+2*b+1]	= "0";

			hv_bin_ts_hdr[2*b]		= "0";
			hv_bin_ts_hdr[2*b+1]	= "0";
			hv_bin_ts_hdr[8+2*b]	= "0";
			hv_bin_ts_hdr[8+2*b+1]	= "0";
			hv_bin_ts_hdr[16+2*b]	= "0";
			hv_bin_ts_hdr[16+2*b+1]	= "0";
			hv_bin_ts_hdr[24+2*b]	= "0";
			hv_bin_ts_hdr[24+2*b+1]	= "0";
			hv_bin_ts_hdr[32+2*b]	= "0";
			hv_bin_ts_hdr[32+2*b+1]	= "0";

			hv_hdr[14*d]	= "0";
			hv_hdr[14*d+1]	= "0";
			hv_hdr[14*d+2]	= "0";
			hv_hdr[14*d+3]	= "0";
			hv_hdr[14*d+4]	= "0";
			hv_hdr[14*d+5]	= "0";
			hv_hdr[14*d+6]	= "0";
			hv_hdr[14*d+7]	= "0";
			hv_hdr[14*d+8]	= "0";
			hv_hdr[14*d+9]	= "0";
			hv_hdr[14*d+10] = "0";
			hv_hdr[14*d+11] = "0";
			hv_hdr[14*d+12] = "0";
			hv_hdr[14*d+13] = "0";

			hv_bin_len_hdr[2*d]			= "0";
			hv_bin_len_hdr[2*d+1]		= "0";
			hv_bin_len_hdr[8+2*d]		= "0";
			hv_bin_len_hdr[8+2*d+1]		= "0";
			hv_bin_len_hdr[16+2*d]		= "0";
			hv_bin_len_hdr[16+2*d+1]	= "0";
			hv_bin_len_hdr[24+2*d]		= "0";
			hv_bin_len_hdr[24+2*d+1]	= "0";
			hv_bin_len_hdr[32+2*d]		= "0";
			hv_bin_len_hdr[32+2*d+1]	= "0";

			hv_bin_ts_hdr[2*d]		= "0";
			hv_bin_ts_hdr[2*d+1]	= "0";
			hv_bin_ts_hdr[8+2*d]	= "0";
			hv_bin_ts_hdr[8+2*d+1]	= "0";
			hv_bin_ts_hdr[16+2*d]	= "0";
			hv_bin_ts_hdr[16+2*d+1]	= "0";
			hv_bin_ts_hdr[24+2*d]	= "0";
			hv_bin_ts_hdr[24+2*d+1]	= "0";
			hv_bin_ts_hdr[32+2*d]	= "0";
			hv_bin_ts_hdr[32+2*d+1]	= "0";

			flow_global_cnt++;
			cur_samples.push_back(as_sample());
			reset_regs_dp(c, iter.first);
		}
	}

	for (const auto &iter : reg_ts_dp[d]) {
		if (reg_ts_dp[d][iter.first][0] != 0 && reg_ts_dp[d][iter.first][1] != 0) {
			hv_hdr[14*d]	= std::to_string(static_cast<double>(reg_ts_dp[d][iter.first][0]));
			hv_hdr[14*d+1]	= std::to_string(static_cast<double>(reg_ts_dp[d][iter.first][1]));
			hv_hdr[14*d+2]	= std::to_string(static_cast<double>(reg_ts_agg_dp[d][iter.first]));
			hv_hdr[14*d+3]	= reg_ip_dp[d][iter.first][0];
			hv_hdr[14*d+4]	= reg_ip_dp[d][iter.first][1];
			hv_hdr[14*d+5]	= std::to_string(reg_port_dp[d][iter.first][0]);
			hv_hdr[14*d+6]	= std::to_string(reg_port_dp[d][iter.first][1]);
			hv_hdr[14*d+7]	= std::to_string(reg_flags_dp[d][iter.first][0]);
			hv_hdr[14*d+8]	= std::to_string(reg_flags_dp[d][iter.first][1]);
			hv_hdr[14*d+9]	= std::to_string(reg_flags_dp[d][iter.first][2]);
			hv_hdr[14*d+10] = std::to_string(reg_flags_dp[d][iter.first][3]);
			hv_hdr[14*d+11] = std::to_string(reg_data_dp[d][iter.first][0]);
			hv_hdr[14*d+12] = std::to_string(reg_data_dp[d][iter.first][1]);

			if (reg_data_dp[d][iter.first][0] > 15) {
				hv_hdr[14*d+13] = "1";
			} else {
				hv_hdr[14*d+13] = "0";
			}

			hv_bin_len_hdr[2*d]			= std::to_string(reg_bin_len_0_dp[d][iter.first][0]);
			hv_bin_len_hdr[2*d+1]		= std::to_string(reg_bin_len_0_dp[d][iter.first][1]);
			hv_bin_len_hdr[8+2*d]		= std::to_string(reg_bin_len_1_dp[d][iter.first][0]);
			hv_bin_len_hdr[8+2*d+1]		= std::to_string(reg_bin_len_1_dp[d][iter.first][1]);
			hv_bin_len_hdr[16+2*d]		= std::to_string(reg_bin_len_2_dp[d][iter.first][0]);
			hv_bin_len_hdr[16+2*d+1]	= std::to_string(reg_bin_len_2_dp[d][iter.first][1]);
			hv_bin_len_hdr[24+2*d]		= std::to_string(reg_bin_len_3_dp[d][iter.first][0]);
			hv_bin_len_hdr[24+2*d+1]	= std::to_string(reg_bin_len_3_dp[d][iter.first][1]);
			hv_bin_len_hdr[32+2*d]		= std::to_string(reg_bin_len_4_dp[d][iter.first][0]);
			hv_bin_len_hdr[32+2*d+1]	= std::to_string(reg_bin_len_4_dp[d][iter.first][1]);

			hv_bin_ts_hdr[2*d]		= std::to_string(reg_bin_ts_0_dp[d][iter.first][0]);
			hv_bin_ts_hdr[2*d+1]	= std::to_string(reg_bin_ts_0_dp[d][iter.first][1]);
			hv_bin_ts_hdr[8+2*d]	= std::to_string(reg_bin_ts_1_dp[d][iter.first][0]);
			hv_bin_ts_hdr[8+2*d+1]	= std::to_string(reg_bin_ts_1_dp[d][iter.first][1]);
			hv_bin_ts_hdr[16+2*d]	= std::to_string(reg_bin_ts_2_dp[d][iter.first][0]);
			hv_bin_ts_hdr[16+2*d+1]	= std::to_string(reg_bin_ts_2_dp[d][iter.first][1]);
			hv_bin_ts_hdr[24+2*d]	= std::to_string(reg_bin_ts_3_dp[d][iter.first][0]);
			hv_bin_ts_hdr[24+2*d+1]	= std::to_string(reg_bin_ts_3_dp[d][iter.first][1]);
			hv_bin_ts_hdr[32+2*d]	= std::to_string(reg_bin_ts_4_dp[d][iter.first][0]);
			hv_bin_ts_hdr[32+2*d+1]	= std::to_string(reg_bin_ts_4_dp[d][iter.first][1]);

			hv_hdr[14*a]	= "0";
			hv_hdr[14*a+1]	= "0";
			hv_hdr[14*a+2]	= "0";
			hv_hdr[14*a+3]	= "0";
			hv_hdr[14*a+4]	= "0";
			hv_hdr[14*a+5]	= "0";
			hv_hdr[14*a+6]	= "0";
			hv_hdr[14*a+7]	= "0";
			hv_hdr[14*a+8]	= "0";
			hv_hdr[14*a+9]	= "0";
			hv_hdr[14*a+10] = "0";
			hv_hdr[14*a+11] = "0";
			hv_hdr[14*a+12] = "0";
			hv_hdr[14*a+13] = "0";

			hv_bin_len_hdr[2*a]			= "0";
			hv_bin_len_hdr[2*a+1]		= "0";
			hv_bin_len_hdr[8+2*a]		= "0";
			hv_bin_len_hdr[8+2*a+1]		= "0";
			hv_bin_len_hdr[16+2*a]		= "0";
			hv_bin_len_hdr[16+2*a+1]	= "0";
			hv_bin_len_hdr[24+2*a]		= "0";
			hv_bin_len_hdr[24+2*a+1]	= "0";
			hv_bin_len_hdr[32+2*a]		= "0";
			hv_bin_len_hdr[32+2*a+1]	= "0";

			hv_bin_ts_hdr[2*a]		= "0";
			hv_bin_ts_hdr[2*a+1]	= "0";
			hv_bin_ts_hdr[8+2*a]	= "0";
			hv_bin_ts_hdr[8+2*a+1]	= "0";
			hv_bin_ts_hdr[16+2*a]	= "0";
			hv_bin_ts_hdr[16+2*a+1]	= "0";
			hv_bin_ts_hdr[24+2*a]	= "0";
			hv_bin_ts_hdr[24+2*a+1]	= "0";
			hv_bin_ts_hdr[32+2*a]	= "0";
			hv_bin_ts_hdr[32+2*a+1]	= "0";

			hv_hdr[14*b]	= "0";
			hv_hdr[14*b+1]	= "0";
			hv_hdr[14*b+2]	= "0";
			hv_hdr[14*b+3]	= "0";
			hv_hdr[14*b+4]	= "0";
			hv_hdr[14*b+5]	= "0";
			hv_hdr[14*b+6]	= "0";
			hv_hdr[14*b+7]	= "0";
			hv_hdr[14*b+8]	= "0";
			hv_hdr[14*b+9]	= "0";
			hv_hdr[14*b+10] = "0";
			hv_hdr[14*b+11] = "0";
			hv_hdr[14*b+12] = "0";
			hv_hdr[14*b+13] = "0";

			hv_bin_len_hdr[2*b]			= "0";
			hv_bin_len_hdr[2*b+1]		= "0";
			hv_bin_len_hdr[8+2*b]		= "0";
			hv_bin_len_hdr[8+2*b+1]		= "0";
			hv_bin_len_hdr[16+2*b]		= "0";
			hv_bin_len_hdr[16+2*b+1]	= "0";
			hv_bin_len_hdr[24+2*b]		= "0";
			hv_bin_len_hdr[24+2*b+1]	= "0";
			hv_bin_len_hdr[32+2*b]		= "0";
			hv_bin_len_hdr[32+2*b+1]	= "0";

			hv_bin_ts_hdr[2*b]		= "0";
			hv_bin_ts_hdr[2*b+1]	= "0";
			hv_bin_ts_hdr[8+2*b]	= "0";
			hv_bin_ts_hdr[8+2*b+1]	= "0";
			hv_bin_ts_hdr[16+2*b]	= "0";
			hv_bin_ts_hdr[16+2*b+1]	= "0";
			hv_bin_ts_hdr[24+2*b]	= "0";
			hv_bin_ts_hdr[24+2*b+1]	= "0";
			hv_bin_ts_hdr[32+2*b]	= "0";
			hv_bin_ts_hdr[32+2*b+1]	= "0";

			hv_hdr[14*c]	= "0";
			hv_hdr[14*c+1]	= "0";
			hv_hdr[14*c+2]	= "0";
			hv_hdr[14*c+3]	= "0";
			hv_hdr[14*c+4]	= "0";
			hv_hdr[14*c+5]	= "0";
			hv_hdr[14*c+6]	= "0";
			hv_hdr[14*c+7]	= "0";
			hv_hdr[14*c+8]	= "0";
			hv_hdr[14*c+9]	= "0";
			hv_hdr[14*c+10] = "0";
			hv_hdr[14*c+11] = "0";
			hv_hdr[14*c+12] = "0";
			hv_hdr[14*c+13] = "0";

			hv_bin_len_hdr[2*c]			= "0";

			hv_bin_len_hdr[2*c+1]		= "0";
			hv_bin_len_hdr[8+2*c]		= "0";
			hv_bin_len_hdr[8+2*c+1]		= "0";
			hv_bin_len_hdr[16+2*c]		= "0";
			hv_bin_len_hdr[16+2*c+1]	= "0";
			hv_bin_len_hdr[24+2*c]		= "0";
			hv_bin_len_hdr[24+2*c+1]	= "0";
			hv_bin_len_hdr[32+2*c]		= "0";
			hv_bin_len_hdr[32+2*c+1]	= "0";

			hv_bin_ts_hdr[2*c]		= "0";
			hv_bin_ts_hdr[2*c+1]	= "0";
			hv_bin_ts_hdr[8+2*c]	= "0";
			hv_bin_ts_hdr[8+2*c+1]	= "0";
			hv_bin_ts_hdr[16+2*c]	= "0";
			hv_bin_ts_hdr[16+2*c+1]	= "0";
			hv_bin_ts_hdr[24+2*c]	= "0";
			hv_bin_ts_hdr[24+2*c+1]	= "0";
			hv_bin_ts_hdr[32+2*c]	= "0";
			hv_bin_ts_hdr[32+2*c+1]	= "0";

			flow_global_cnt++;
			cur_samples.push_back(as_sample());
			reset_regs_dp(d, iter.first);
		}
	}
}

void FCHv::reg_read_end_cp(int a, int b, int c, int d) {
	for ( const auto &iter : reg_ts_cp[a]) {
		if (reg_ts_cp[a][iter.first][0] != 0 && reg_ts_cp[a][iter.first][1] != 0) {
			hv_hdr[14*a]	= std::to_string(static_cast<double>(reg_ts_cp[a][iter.first][0]));
			hv_hdr[14*a+1]	= std::to_string(static_cast<double>(reg_ts_cp[a][iter.first][1]));
			hv_hdr[14*a+2]	= std::to_string(static_cast<double>(reg_ts_agg_cp[a][iter.first]));
			hv_hdr[14*a+3]	= reg_ip_cp[a][iter.first][0];
			hv_hdr[14*a+4]	= reg_ip_cp[a][iter.first][1];
			hv_hdr[14*a+5]	= std::to_string(reg_port_cp[a][iter.first][0]);
			hv_hdr[14*a+6]	= std::to_string(reg_port_cp[a][iter.first][1]);
			hv_hdr[14*a+7]	= std::to_string(reg_flags_cp[a][iter.first][0]);
			hv_hdr[14*a+8]	= std::to_string(reg_flags_cp[a][iter.first][1]);
			hv_hdr[14*a+9]	= std::to_string(reg_flags_cp[a][iter.first][2]);
			hv_hdr[14*a+10] = std::to_string(reg_flags_cp[a][iter.first][3]);
			hv_hdr[14*a+11] = std::to_string(reg_data_cp[a][iter.first][0]);
			hv_hdr[14*a+12] = std::to_string(reg_data_cp[a][iter.first][1]);

			if (reg_data_cp[a][iter.first][0] > 15) {
				hv_hdr[14*a+13] = "1";
			} else {
				hv_hdr[14*a+13] = "0";
			}

			hv_bin_len_hdr[2*a]			= std::to_string(reg_bin_len_0_cp[a][iter.first][0]);
			hv_bin_len_hdr[2*a+1]		= std::to_string(reg_bin_len_0_cp[a][iter.first][1]);
			hv_bin_len_hdr[8+2*a]		= std::to_string(reg_bin_len_1_cp[a][iter.first][0]);
			hv_bin_len_hdr[8+2*a+1]		= std::to_string(reg_bin_len_1_cp[a][iter.first][1]);
			hv_bin_len_hdr[16+2*a]		= std::to_string(reg_bin_len_2_cp[a][iter.first][0]);
			hv_bin_len_hdr[16+2*a+1]	= std::to_string(reg_bin_len_2_cp[a][iter.first][1]);
			hv_bin_len_hdr[24+2*a]		= std::to_string(reg_bin_len_3_cp[a][iter.first][0]);
			hv_bin_len_hdr[24+2*a+1]	= std::to_string(reg_bin_len_3_cp[a][iter.first][1]);
			hv_bin_len_hdr[32+2*a]		= std::to_string(reg_bin_len_4_cp[a][iter.first][0]);
			hv_bin_len_hdr[32+2*a+1]	= std::to_string(reg_bin_len_4_cp[a][iter.first][1]);

			hv_bin_ts_hdr[2*a]		= std::to_string(reg_bin_ts_0_cp[a][iter.first][0]);
			hv_bin_ts_hdr[2*a+1]	= std::to_string(reg_bin_ts_0_cp[a][iter.first][1]);
			hv_bin_ts_hdr[8+2*a]	= std::to_string(reg_bin_ts_1_cp[a][iter.first][0]);
			hv_bin_ts_hdr[8+2*a+1]	= std::to_string(reg_bin_ts_1_cp[a][iter.first][1]);
			hv_bin_ts_hdr[16+2*a]	= std::to_string(reg_bin_ts_2_cp[a][iter.first][0]);
			hv_bin_ts_hdr[16+2*a+1]	= std::to_string(reg_bin_ts_2_cp[a][iter.first][1]);
			hv_bin_ts_hdr[24+2*a]	= std::to_string(reg_bin_ts_3_cp[a][iter.first][0]);
			hv_bin_ts_hdr[24+2*a+1]	= std::to_string(reg_bin_ts_3_cp[a][iter.first][1]);
			hv_bin_ts_hdr[32+2*a]	= std::to_string(reg_bin_ts_4_cp[a][iter.first][0]);
			hv_bin_ts_hdr[32+2*a+1]	= std::to_string(reg_bin_ts_4_cp[a][iter.first][1]);

			hv_hdr[14*b]	= "0";
			hv_hdr[14*b+1]	= "0";
			hv_hdr[14*b+2]	= "0";
			hv_hdr[14*b+3]	= "0";
			hv_hdr[14*b+4]	= "0";
			hv_hdr[14*b+5]	= "0";
			hv_hdr[14*b+6]	= "0";
			hv_hdr[14*b+7]	= "0";
			hv_hdr[14*b+8]	= "0";
			hv_hdr[14*b+9]	= "0";
			hv_hdr[14*b+10] = "0";
			hv_hdr[14*b+11] = "0";
			hv_hdr[14*b+12] = "0";
			hv_hdr[14*b+13] = "0";

			hv_bin_len_hdr[2*b]			= "0";
			hv_bin_len_hdr[2*b+1]		= "0";
			hv_bin_len_hdr[8+2*b]		= "0";
			hv_bin_len_hdr[8+2*b+1]		= "0";
			hv_bin_len_hdr[16+2*b]		= "0";
			hv_bin_len_hdr[16+2*b+1]	= "0";
			hv_bin_len_hdr[24+2*b]		= "0";
			hv_bin_len_hdr[24+2*b+1]	= "0";
			hv_bin_len_hdr[32+2*b]		= "0";
			hv_bin_len_hdr[32+2*b+1]	= "0";

			hv_bin_ts_hdr[2*b]		= "0";
			hv_bin_ts_hdr[2*b+1]	= "0";
			hv_bin_ts_hdr[8+2*b]	= "0";
			hv_bin_ts_hdr[8+2*b+1]	= "0";
			hv_bin_ts_hdr[16+2*b]	= "0";
			hv_bin_ts_hdr[16+2*b+1]	= "0";
			hv_bin_ts_hdr[24+2*b]	= "0";
			hv_bin_ts_hdr[24+2*b+1]	= "0";
			hv_bin_ts_hdr[32+2*b]	= "0";
			hv_bin_ts_hdr[32+2*b+1]	= "0";

			hv_hdr[14*c]	= "0";
			hv_hdr[14*c+1]	= "0";
			hv_hdr[14*c+2]	= "0";
			hv_hdr[14*c+3]	= "0";
			hv_hdr[14*c+4]	= "0";
			hv_hdr[14*c+5]	= "0";
			hv_hdr[14*c+6]	= "0";
			hv_hdr[14*c+7]	= "0";
			hv_hdr[14*c+8]	= "0";
			hv_hdr[14*c+9]	= "0";
			hv_hdr[14*c+10] = "0";
			hv_hdr[14*c+11] = "0";
			hv_hdr[14*c+12] = "0";
			hv_hdr[14*c+13] = "0";

			hv_bin_len_hdr[2*c]			= "0";
			hv_bin_len_hdr[2*c+1]		= "0";
			hv_bin_len_hdr[8+2*c]		= "0";
			hv_bin_len_hdr[8+2*c+1]		= "0";
			hv_bin_len_hdr[16+2*c]		= "0";
			hv_bin_len_hdr[16+2*c+1]	= "0";
			hv_bin_len_hdr[24+2*c]		= "0";
			hv_bin_len_hdr[24+2*c+1]	= "0";
			hv_bin_len_hdr[32+2*c]		= "0";
			hv_bin_len_hdr[32+2*c+1]	= "0";

			hv_bin_ts_hdr[2*c]		= "0";
			hv_bin_ts_hdr[2*c+1]	= "0";
			hv_bin_ts_hdr[8+2*c]	= "0";
			hv_bin_ts_hdr[8+2*c+1]	= "0";
			hv_bin_ts_hdr[16+2*c]	= "0";
			hv_bin_ts_hdr[16+2*c+1]	= "0";
			hv_bin_ts_hdr[24+2*c]	= "0";
			hv_bin_ts_hdr[24+2*c+1]	= "0";
			hv_bin_ts_hdr[32+2*c]	= "0";
			hv_bin_ts_hdr[32+2*c+1]	= "0";

			hv_hdr[14*d]	= "0";
			hv_hdr[14*d+1]	= "0";
			hv_hdr[14*d+2]	= "0";
			hv_hdr[14*d+3]	= "0";
			hv_hdr[14*d+4]	= "0";
			hv_hdr[14*d+5]	= "0";
			hv_hdr[14*d+6]	= "0";
			hv_hdr[14*d+7]	= "0";
			hv_hdr[14*d+8]	= "0";
			hv_hdr[14*d+9]	= "0";
			hv_hdr[14*d+10] = "0";
			hv_hdr[14*d+11] = "0";
			hv_hdr[14*d+12] = "0";
			hv_hdr[14*d+13] = "0";

			hv_bin_len_hdr[2*d]			= "0";
			hv_bin_len_hdr[2*d+1]		= "0";
			hv_bin_len_hdr[8+2*d]		= "0";
			hv_bin_len_hdr[8+2*d+1]		= "0";
			hv_bin_len_hdr[16+2*d]		= "0";
			hv_bin_len_hdr[16+2*d+1]	= "0";
			hv_bin_len_hdr[24+2*d]		= "0";
			hv_bin_len_hdr[24+2*d+1]	= "0";
			hv_bin_len_hdr[32+2*d]		= "0";
			hv_bin_len_hdr[32+2*d+1]	= "0";

			hv_bin_ts_hdr[2*d]		= "0";
			hv_bin_ts_hdr[2*d+1]	= "0";
			hv_bin_ts_hdr[8+2*d]	= "0";
			hv_bin_ts_hdr[8+2*d+1]	= "0";
			hv_bin_ts_hdr[16+2*d]	= "0";
			hv_bin_ts_hdr[16+2*d+1]	= "0";
			hv_bin_ts_hdr[24+2*d]	= "0";
			hv_bin_ts_hdr[24+2*d+1]	= "0";
			hv_bin_ts_hdr[32+2*d]	= "0";
			hv_bin_ts_hdr[32+2*d+1]	= "0";

			flow_global_cnt++;
			cur_samples.push_back(as_sample());
			reset_regs_cp(a, iter.first);
		}
	}
}

void FCHv::reset_regs_dp(int idx, long read_idx) {
	// std::cout << std::stod(cur_pkt["ts"]) << std::endl;
	// std::cout << reg_ts_dp[idx][read_idx][0] << std::endl;
	// std::cout << reg_ts_dp[idx][read_idx][1] << std::endl;
	// std::cout << reg_ts_dp[idx][read_idx][2] << std::endl;

	reg_ts_dp[idx][read_idx].fill(0);

	// std::cout << reg_ts_dp[idx][read_idx][0] << std::endl;
	// std::cout << reg_ts_dp[idx][read_idx][1] << std::endl;
	// std::cout << reg_ts_dp[idx][read_idx][2] << std::endl;
	// std::cout << "" << std::endl;

	reg_ts_agg_dp[idx][read_idx] = 0;
	reg_ip_dp[idx][read_idx].fill("");
	reg_port_dp[idx][read_idx].fill(0);
	reg_flags_dp[idx][read_idx].fill(0);
	reg_data_dp[idx][read_idx].fill(0);

	reg_bin_len_0_dp[idx][read_idx].fill(0);
	reg_bin_len_1_dp[idx][read_idx].fill(0);
	reg_bin_len_2_dp[idx][read_idx].fill(0);
	reg_bin_len_3_dp[idx][read_idx].fill(0);
	reg_bin_len_4_dp[idx][read_idx].fill(0);

	reg_bin_ts_0_dp[idx][read_idx].fill(0);
	reg_bin_ts_1_dp[idx][read_idx].fill(0);
	reg_bin_ts_2_dp[idx][read_idx].fill(0);
	reg_bin_ts_3_dp[idx][read_idx].fill(0);
	reg_bin_ts_4_dp[idx][read_idx].fill(0);
}

void FCHv::reset_regs_cp(int idx, std::string read_idx) {
	reg_ts_cp[idx][read_idx].fill(0);
	reg_ts_agg_cp[idx][read_idx] = 0;
	reg_ip_cp[idx][read_idx].fill("");
	reg_port_cp[idx][read_idx].fill(0);
	reg_flags_cp[idx][read_idx].fill(0);
	reg_data_cp[idx][read_idx].fill(0);

	reg_bin_len_0_cp[idx][read_idx].fill(0);
	reg_bin_len_1_cp[idx][read_idx].fill(0);
	reg_bin_len_2_cp[idx][read_idx].fill(0);
	reg_bin_len_3_cp[idx][read_idx].fill(0);
	reg_bin_len_4_cp[idx][read_idx].fill(0);

	reg_bin_ts_0_cp[idx][read_idx].fill(0);
	reg_bin_ts_1_cp[idx][read_idx].fill(0);
	reg_bin_ts_2_cp[idx][read_idx].fill(0);
	reg_bin_ts_3_cp[idx][read_idx].fill(0);
	reg_bin_ts_4_cp[idx][read_idx].fill(0);
}

uint16_t FCHv::crc16(const std::vector<uint8_t>& data, uint16_t initial) {
	uint16_t crc = initial;
	for (uint8_t byte : data) {
		crc ^= byte;
		for (int i = 0; i < 8; i++) {
			if (crc & 0x0001) {
				crc = (crc >> 1) ^ 0xA001;
			} else {
				crc >>= 1;
			}
		}
	}
	return crc;
}

uint32_t FCHv::crc32(const std::vector<uint8_t>& data, uint32_t initial) {
	uint32_t crc = initial;
	uint32_t crcTable[256];
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t tmp = i;
		for (int j = 0; j < 8; j++) {
			if (tmp & 1) {
				tmp = (tmp >> 1) ^ 0xEDB88320;
			} else {
				tmp >>= 1;
			}
		}
		crcTable[i] = tmp;
	}

	for (uint8_t byte : data) {
		crc = (crc >> 8) ^ crcTable[(crc ^ byte) & 0xFF];
	}

	return crc;
}
