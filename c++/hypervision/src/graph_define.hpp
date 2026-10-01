#pragma once

#include "common.hpp"
#include "edge_define.hpp"
#include "edge_constructor.hpp"

#include <mlpack/core.hpp>
#include <mlpack/methods/kmeans/kmeans.hpp>
#include <mlpack/methods/dbscan/dbscan.hpp>
#include <mlpack/core/data/scaler_methods/min_max_scaler.hpp>
#include <mlpack/core/metrics/lmetric.hpp>

#include <z3++.h>

namespace hypervision {

using long_edge_index	= vector<size_t>;
using short_edge_index	= vector<size_t>;
using addr_t			= string;

class traffic_graph {
private:
	using feature_t = vector<double>;
	// using score_t	= vector<double>;
	using score_t	= vector<vector<std::string>>;

	shared_ptr<vector<shared_ptr<short_edge>>>	p_short_edge;
	shared_ptr<vector<shared_ptr<long_edge>>>	p_long_edge;

	shared_ptr<vector<string>>					p_attacker_src4;
	shared_ptr<vector<string>>					p_attacker_dst4;
	shared_ptr<vector<pair<string, string>>>	p_attacker_srcdst4;

	unordered_set<addr_t>					vertex_set_long;
	unordered_set<addr_t>					vertex_set_short_reduce;
	unordered_set<addr_t>					vertex_set_short;
	unordered_map<addr_t, long_edge_index>	long_edge_out;
	unordered_map<addr_t, long_edge_index>	long_edge_in;
	unordered_map<addr_t, short_edge_index> short_edge_in;
	unordered_map<addr_t, short_edge_index> short_edge_in_agg;
	unordered_map<addr_t, short_edge_index> short_edge_out;
	unordered_map<addr_t, short_edge_index> short_edge_out_agg;

	shared_ptr<vector<double>> p_short_edge_score;
	shared_ptr<vector<double>> p_long_edge_score;
	shared_ptr<score_t> p_pkt_score;

	void parse_short_edge(void);
	void parse_long_edge(void);

	void dump_graph_statistic_long(void) const;
	void dump_graph_statistic_short(void) const;

	bool proto_cluster		= true;
	uint32_t val_K			= 10;
	double_t al				= 0.1;
	double_t bl				= 1.0;
	double_t cl				= 0.5;
	double_t as				= 0.1;
	double_t bs				= 1.0;
	double_t cs				= 0.5;
	double_t uc				= 0.01;
	double_t us				= 0.001;
	double_t ul				= 0.05;
	uint32_t vc				= 10;
	uint32_t vs				= 20;
	uint32_t vl				= 10;
	double_t select_ratio	= 0.01;
	double_t offset_l		= 0.0;
	double_t offset_s		= 0.0;

public:
	traffic_graph(const decltype(p_short_edge) p_short_edge,
				  const decltype(p_long_edge) p_long_edge):
		p_short_edge(p_short_edge), p_long_edge(p_long_edge) {}

	traffic_graph(const traffic_graph &)				= delete;
	traffic_graph & operator=(const traffic_graph &)	= delete;
	virtual ~traffic_graph () {}

	void parse_edge(void) {
		p_short_edge_score	= make_shared<std::vector<double>>(p_short_edge->size());
		p_long_edge_score	= make_shared<std::vector<double>>(p_long_edge->size());

		std::fill(p_short_edge_score->begin(), p_short_edge_score->end(), 0.0);
		std::fill(p_long_edge_score->begin(), p_long_edge_score->end(), 0.0);

		parse_short_edge();
		parse_long_edge();
	}

	void dump_graph_statistic(void) const {
		dump_graph_statistic_long();
		dump_graph_statistic_short();
	}

	constexpr static size_t huge_short_line		= 50;
	constexpr static size_t huge_agg_short_line = 100;

	auto is_huge_short_edge(const addr_t addr) const -> bool;
	auto is_huge_agg_short_edge(const addr_t & addr) const -> bool;
	void dump_vertex_anomly(void) const;
	void dump_edge_anomly(void) const;

	using component = vector<vector<addr_t> >;
	auto connected_component() const -> shared_ptr<component>;

	auto component_select(const shared_ptr<component> p_com) const -> shared_ptr<vector<size_t>>;

	std::string get_flow_label(std::string ip_src, std::string ip_dst) const;

private:
	auto __f_get_inout_degree(const addr_t addr) const -> pair<size_t, size_t>;
	auto _f_exeract_feature_short(const size_t index) const -> feature_t;
	auto _f_exeract_feature_long(const size_t index) const -> feature_t;
	auto _f_exeract_feature_short2(const size_t index) const -> feature_t;
	auto _f_exeract_feature_long2(const size_t index) const -> feature_t;
	auto __f_trans_armadillo_mat_T(const vector<feature_t> & mx) -> arma::mat;

	void _acquire_edge_index(const vector<addr_t> & addr_ls,
							 unordered_set<size_t> & _long_index,
							 unordered_set<size_t> & _short_index);
	auto _pre_process_short(const unordered_set<size_t> & _short_index,
							arma::mat & dataset_short,
							arma::mat & centroids_short,
							arma::Row<size_t> & assignments_short) -> size_t;
	auto _pre_process_long(const unordered_set<size_t> & _long_index,
						   arma::mat & centroids_long,
						   arma::Row<size_t> & assignments_long) -> size_t;
	void _process_short(const unordered_set<size_t> & _short_index,
						const arma::mat & dataset_short,
						const arma::mat & centroids_short,
						const arma::Row<size_t> & assignments_short);
	void _process_long(const unordered_set<size_t> & _long_index,
					   const arma::mat & centroids_long,
					   const arma::Row<size_t> & assignments_long);
	void _proc_each_component(const vector<addr_t> & addr_ls);

public:
	auto graph_detect() {
		proc_components(connected_component());
	}

	auto proc_components(const shared_ptr<component> p_com) -> void;

	auto get_final_pkt_score() -> const decltype(p_pkt_score);

	void config_via_json(const nlohmann::json & jin);
};

}

