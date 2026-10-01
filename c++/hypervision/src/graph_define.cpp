#include "graph_define.hpp"

using namespace hypervision;

auto traffic_graph::is_huge_short_edge(const addr_t addr) const -> bool {
	if ((short_edge_in.count(addr) && short_edge_in.at(addr).size() > huge_short_line) ||
		(short_edge_out.count(addr)  && short_edge_out.at(addr).size() > huge_short_line)) {
		return true;
	} else {
		return false;
	}
}

auto traffic_graph::is_huge_agg_short_edge(const addr_t & addr) const -> bool {
	if (short_edge_in_agg.count(addr)) {
		for (auto idx : short_edge_in_agg.at(addr))
			if (p_short_edge->at(idx)->get_agg_size() > huge_agg_short_line) {
				return true;
			}
	}

	if (short_edge_out_agg.count(addr)) {
		for (auto idx : short_edge_out_agg.at(addr))
			if (p_short_edge->at(idx)->get_agg_size() > huge_agg_short_line) {
				return true;
			}
	}

	return false;
}

void traffic_graph::dump_vertex_anomly(void) const {
	size_t va = 0, vga = 0;
	for(const auto & add: vertex_set_short) {
		if (is_huge_short_edge(add)) {
			++ va;
		}
		if (is_huge_agg_short_edge(add)) {
			++ vga;
		}
	}
	LOGF("Invalid vertex: %ld, Invalide aggregate: %ld.", va, vga);
}

std::string traffic_graph::get_flow_label(std::string ip_src, std::string ip_dst) const {
	if (p_attacker_src4 != nullptr) {
		for (const string & st: *p_attacker_src4) {
			if (ip_src.find(st) != string::npos) {
				return "1";
			}
		}
	}
	if (p_attacker_dst4 != nullptr) {
		for (const string & st: *p_attacker_dst4) {
			if (ip_dst.find(st) != string::npos) {
				return "1";
			}
		}
	}
	if (p_attacker_srcdst4 != nullptr) {
		for (const pair<string, string> & stp: *p_attacker_srcdst4) {
			if (ip_src.find(stp.first) != string::npos && ip_dst.find(stp.second) != string::npos) {
				return "1";
			}
		}
	}

	return "0";
}

auto traffic_graph::get_final_pkt_score() -> const decltype(p_pkt_score) {
	if (p_pkt_score != nullptr) {
		WARN("Previous result overlap.");
	}

	p_pkt_score = make_shared<score_t>();

	for (size_t i = 0; i < p_long_edge->size(); ++i) {
		const auto p_flow = p_long_edge->at(i)->get_raw_flow();

		std::string ip_src		= get_str_addr(tuple_get_src_addr(p_flow->flow_id));
		std::string ip_dst		= get_str_addr(tuple_get_dst_addr(p_flow->flow_id));
		std::string proto		= std::to_string(p_flow->proto);
		std::string port_src	= std::to_string(tuple_get_src_port(p_flow->flow_id));
		std::string port_dst	= std::to_string(tuple_get_dst_port(p_flow->flow_id));
		std::string cnt			= std::to_string(p_flow->cnt);
		std::string loss		= std::to_string(p_long_edge_score->at(i) + offset_l);
		std::string label		= get_flow_label(ip_src, ip_dst);

		// for (uint j = 0; j < p_flow->cnt; ++j) {
			p_pkt_score->push_back({ip_src, ip_dst, proto, port_src, port_dst, cnt, loss, label});
		// }
	}

	for (size_t i = 0; i < p_short_edge->size(); ++i) {
		for (size_t j = 0; j < p_short_edge->at(i)->p_flow->size(); ++j) {
			const auto p_flow = p_short_edge->at(i)->p_flow->at(j);

			std::string ip_src		= get_str_addr(tuple_get_src_addr(p_flow->flow_id));
			std::string ip_dst		= get_str_addr(tuple_get_dst_addr(p_flow->flow_id));
			std::string proto		= std::to_string(p_flow->proto);
			std::string port_src	= std::to_string(tuple_get_src_port(p_flow->flow_id));
			std::string port_dst	= std::to_string(tuple_get_dst_port(p_flow->flow_id));
			std::string cnt			= std::to_string(p_flow->cnt);
			std::string loss		= std::to_string(p_short_edge_score->at(i) + offset_s);
			std::string label		= get_flow_label(ip_src, ip_dst);

			// for (uint k = 0; k < p_flow->cnt; ++k) {
				p_pkt_score->push_back({ip_src, ip_dst, proto, port_src, port_dst, cnt, loss, label});
			// }
		}
	}

	return p_pkt_score;
}

void traffic_graph::config_via_json(const nlohmann::json & jin) {
	try {
		if (jin.count("uc")) {
			uc = static_cast<decltype(uc)>(jin["uc"]);
		}
		if (jin.count("vc")) {
			vc = static_cast<decltype(vc)>(jin["vc"]);
		}

		if (jin.count("ul")) {
			ul = static_cast<decltype(ul)>(jin["ul"]);
		}
		if (jin.count("vl")) {
			vl = static_cast<decltype(vl)>(jin["vl"]);
		}

		if (jin.count("us")) {
			us = static_cast<decltype(us)>(jin["us"]);
		}
		if (jin.count("vs")) {
			vs = static_cast<decltype(vs)>(jin["vs"]);
		}

		if (jin.count("al")) {
			al = static_cast<decltype(al)>(jin["al"]);
		}
		if (jin.count("bl")) {
			bl = static_cast<decltype(bl)>(jin["bl"]);
		}
		if (jin.count("cl")) {
			cl = static_cast<decltype(cl)>(jin["cl"]);
		}

		if (jin.count("as")) {
			as = static_cast<decltype(as)>(jin["as"]);
		}
		if (jin.count("bs")) {
			bs = static_cast<decltype(bs)>(jin["bs"]);
		}
		if (jin.count("cs")) {
			cs = static_cast<decltype(cs)>(jin["cs"]);
		}

		if (jin.count("offset_l")) {
			offset_l = static_cast<decltype(offset_l)>(jin["offset_l"]);
		}
		if (jin.count("offset_s")) {
			offset_s = static_cast<decltype(offset_s)>(jin["offset_s"]);
		}
		if (jin.count("select_ratio")) {
			select_ratio = static_cast<decltype(select_ratio)>(jin["select_ratio"]);
			if (select_ratio < EPS) {
				FATAL_ERROR("The select ratio is lower than 0.");
			}
		}
		if (jin.count("proto_cluster")) {
			proto_cluster = static_cast<decltype(proto_cluster)>(jin["proto_cluster"]);
		}
		if (jin.count("attacker_src4") && jin["attacker_src4"].size() != 0) {
			if (p_attacker_src4 != nullptr) {
				WARN("Reconfigure attacker source IPv4 list");
			}
			p_attacker_src4 = make_shared<decltype(p_attacker_src4)::element_type>();
			const auto _ls = jin["attacker_src4"];
			for (const auto & _l: _ls) {
				p_attacker_src4->push_back(static_cast<string>(_l));
			}
		}
		if (jin.count("attacker_dst4") && jin["attacker_dst4"].size() != 0) {
			if (p_attacker_dst4 != nullptr) {
				WARN("Reconfigure attacker destination IPv4 list");
			}
			p_attacker_dst4 = make_shared<decltype(p_attacker_dst4)::element_type>();
			const auto _ls = jin["attacker_dst4"];
			for (const auto & _l: _ls) {
				p_attacker_dst4->push_back(static_cast<string>(_l));
			}
		}
		if (jin.count("attacker_srcdst4") && jin["attacker_srcdst4"].size() != 0) {
			if (p_attacker_srcdst4 != nullptr) {
				WARN("Reconfigure attacker source-destination IPv4 list");
			}
			p_attacker_srcdst4 = make_shared<decltype(p_attacker_srcdst4)::element_type>();
			const auto _ls = jin["attacker_srcdst4"];
			for (const auto & _l: _ls) {
				if (_l.size() != 2) {
					LOGF("[l size: %ld]", _l.size());
					FATAL_ERROR("Wrong configuration format.");
				}
				p_attacker_srcdst4->push_back({static_cast<string>(_l[0]), static_cast<string>(_l[1])});
			}
		}
	} catch (const exception & e) {
		FATAL_ERROR(e.what());
	}
}
