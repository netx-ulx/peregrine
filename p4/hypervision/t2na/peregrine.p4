#include <core.p4>

#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/parser.p4"
#include "includes/deparser.p4"

// ---------------------------------------------------------------------------
// Pipeline - Ingress
// ---------------------------------------------------------------------------

control Ingress(inout header_t hdr,
				inout ig_meta_t ig_md,
				in ingress_intrinsic_metadata_t ig_intr_md,
				in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
				inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
				inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

	// DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) in_counter;
	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_flow;

	Register<bit<32>, _>(1)				reg_index_cntr;

	Register<flow_ts, _>(REG_SIZE)		reg_ts_0;
	Register<flow_ts, _>(REG_SIZE)		reg_ts_1;
	Register<flow_ts, _>(REG_SIZE)		reg_ts_2;
	Register<flow_ts, _>(REG_SIZE)		reg_ts_3;

	Register<bit<32>, _>(REG_SIZE)		reg_ts_agg_0;
	Register<bit<32>, _>(REG_SIZE)		reg_ts_agg_1;
	Register<bit<32>, _>(REG_SIZE)		reg_ts_agg_2;
	Register<bit<32>, _>(REG_SIZE)		reg_ts_agg_3;

	Register<flow_ip, _>(REG_SIZE)		reg_ip_0;
	Register<flow_ip, _>(REG_SIZE)		reg_ip_1;
	Register<flow_ip, _>(REG_SIZE)		reg_ip_2;
	Register<flow_ip, _>(REG_SIZE)		reg_ip_3;

	Register<flow_port, _>(REG_SIZE)	reg_port_0;
	Register<flow_port, _>(REG_SIZE)	reg_port_1;
	Register<flow_port, _>(REG_SIZE)	reg_port_2;
	Register<flow_port, _>(REG_SIZE)	reg_port_3;

	Register<flow_flags, _>(REG_SIZE)	reg_syn_ack_0;
	Register<flow_flags, _>(REG_SIZE)	reg_syn_ack_1;
	Register<flow_flags, _>(REG_SIZE)	reg_syn_ack_2;
	Register<flow_flags, _>(REG_SIZE)	reg_syn_ack_3;

	Register<flow_flags, _>(REG_SIZE)	reg_fin_rst_0;
	Register<flow_flags, _>(REG_SIZE)	reg_fin_rst_1;
	Register<flow_flags, _>(REG_SIZE)	reg_fin_rst_2;
	Register<flow_flags, _>(REG_SIZE)	reg_fin_rst_3;

	Register<flow_data, _>(REG_SIZE)	reg_data_0;
	Register<flow_data, _>(REG_SIZE)	reg_data_1;
	Register<flow_data, _>(REG_SIZE)	reg_data_2;
	Register<flow_data, _>(REG_SIZE)	reg_data_3;

	Register<bin_len, _>(REG_SIZE)		reg_bin_len_0_0;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_0_1;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_0_2;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_0_3;

	Register<bin_len, _>(REG_SIZE)		reg_bin_len_1_0;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_1_1;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_1_2;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_1_3;

	Register<bin_len, _>(REG_SIZE)		reg_bin_len_2_0;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_2_1;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_2_2;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_2_3;

	Register<bin_len, _>(REG_SIZE)		reg_bin_len_3_0;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_3_1;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_3_2;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_3_3;

	Register<bin_len, _>(REG_SIZE)		reg_bin_len_4_0;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_4_1;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_4_2;
	Register<bin_len, _>(REG_SIZE)		reg_bin_len_4_3;

	// Round-robin: Increment the current index up to 8191.
	// 8191 corresponds to the size of each register.
	RegisterAction<_, bit<1>, bit<16>>(reg_index_cntr) ract_index_cntr_update = {
		void apply(inout bit<16> val, out bit<16> res) {
			if (val < 8191) {
				val = val + 1;
			} else {
				val = 0;
			}
			res = val;
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_0) ract_ts_0_read = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> end) {
			start = 0;
			end = 0;
			if (TIME_10_S < hdr.meta.cur_ts - flow.end && flow.end != 0) {
				start = flow.start;
				end = flow.end;
				flow.start = 0;
				flow.end = 0;
			}
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_1) ract_ts_1_read = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> end) {
			start = 0;
			end = 0;
			if (TIME_10_S < hdr.meta.cur_ts - flow.end && flow.end != 0) {
				start = flow.start;
				end = flow.end;
				flow.start = 0;
				flow.end = 0;
			}
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_2) ract_ts_2_read = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> end) {
			start = 0;
			end = 0;
			if (TIME_10_S < hdr.meta.cur_ts - flow.end && flow.end != 0) {
				start = flow.start;
				end = flow.end;
				flow.start = 0;
				flow.end = 0;
			}
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_3) ract_ts_3_read = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> end) {
			start = 0;
			end = 0;
			if (TIME_10_S < hdr.meta.cur_ts - flow.end && flow.end != 0) {
				start = flow.start;
				end = flow.end;
				flow.start = 0;
				flow.end = 0;
			}
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_0) ract_ts_0_update = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> flow_end_old) {
			if (flow.start == 0) {
				flow.start = hdr.meta.cur_ts;
			}
			flow_end_old = flow.end;
			flow.end = hdr.meta.cur_ts;
			start = flow.start;
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_1) ract_ts_1_update = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> flow_end_old) {
			if (flow.start == 0) {
				flow.start = hdr.meta.cur_ts;
			}
			flow_end_old = flow.end;
			flow.end = hdr.meta.cur_ts;
			start = flow.start;
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_2) ract_ts_2_update = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> flow_end_old) {
			if (flow.start == 0) {
				flow.start = hdr.meta.cur_ts;
			}
			flow_end_old = flow.end;
			flow.end = hdr.meta.cur_ts;
			start = flow.start;
		}
	};

	RegisterAction<flow_ts, bit<16>, bit<32>>(reg_ts_3) ract_ts_3_update = {
		void apply(inout flow_ts flow, out bit<32> start, out bit<32> flow_end_old) {
			if (flow.start == 0) {
				flow.start = hdr.meta.cur_ts;
			}
			flow_end_old = flow.end;
			flow.end = hdr.meta.cur_ts;
			start = flow.start;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_0) ract_ts_agg_0_read = {
		void apply(inout bit<32> ts_agg, out bit<32> res) {
			res = ts_agg;
			ts_agg = 0;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_1) ract_ts_agg_1_read = {
		void apply(inout bit<32> ts_agg, out bit<32> res) {
			res = ts_agg;
			ts_agg = 0;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_2) ract_ts_agg_2_read = {
		void apply(inout bit<32> ts_agg, out bit<32> res) {
			res = ts_agg;
			ts_agg = 0;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_3) ract_ts_agg_3_read = {
		void apply(inout bit<32> ts_agg, out bit<32> res) {
			res = ts_agg;
			ts_agg = 0;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_0) ract_ts_agg_0_update = {
		void apply(inout bit<32> ts_agg) {
			ts_agg = ts_agg + ig_md.ts_agg_tmp;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_1) ract_ts_agg_1_update = {
		void apply(inout bit<32> ts_agg) {
			ts_agg = ts_agg + ig_md.ts_agg_tmp;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_2) ract_ts_agg_2_update = {
		void apply(inout bit<32> ts_agg) {
			ts_agg = ts_agg + ig_md.ts_agg_tmp;
		}
	};

	RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ts_agg_3) ract_ts_agg_3_update = {
		void apply(inout bit<32> ts_agg) {
			ts_agg = ts_agg + ig_md.ts_agg_tmp;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_0) ract_ip_0_read = {
		void apply(inout flow_ip flow, out bit<32> ip_src, out bit<32> ip_dst) {
			ip_src		= flow.src;
			ip_dst		= flow.dst;
			flow.src	= 0;
			flow.dst	= 0;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_1) ract_ip_1_read = {
		void apply(inout flow_ip flow, out bit<32> ip_src, out bit<32> ip_dst) {
			ip_src		= flow.src;
			ip_dst		= flow.dst;
			flow.src	= 0;
			flow.dst	= 0;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_2) ract_ip_2_read = {
		void apply(inout flow_ip flow, out bit<32> ip_src, out bit<32> ip_dst) {
			ip_src		= flow.src;
			ip_dst		= flow.dst;
			flow.src	= 0;
			flow.dst	= 0;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_3) ract_ip_3_read = {
		void apply(inout flow_ip flow, out bit<32> ip_src, out bit<32> ip_dst) {
			ip_src		= flow.src;
			ip_dst		= flow.dst;
			flow.src	= 0;
			flow.dst	= 0;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_0) ract_ip_0_update = {
		void apply(inout flow_ip flow) {
			flow.src = hdr.ipv4.src_addr;
			flow.dst = hdr.ipv4.dst_addr;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_1) ract_ip_1_update = {
		void apply(inout flow_ip flow) {
			flow.src = hdr.ipv4.src_addr;
			flow.dst = hdr.ipv4.dst_addr;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_2) ract_ip_2_update = {
		void apply(inout flow_ip flow) {
			flow.src = hdr.ipv4.src_addr;
			flow.dst = hdr.ipv4.dst_addr;
		}
	};

	RegisterAction<flow_ip, bit<16>, bit<32>>(reg_ip_3) ract_ip_3_update = {
		void apply(inout flow_ip flow) {
			flow.src = hdr.ipv4.src_addr;
			flow.dst = hdr.ipv4.dst_addr;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_0) ract_port_0_read = {
		void apply(inout flow_port flow, out bit<32> proto, out bit<32> ports) {
			proto		= flow.proto;
			ports		= flow.ports;
			flow.proto	= 0;
			flow.ports	= 0;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_1) ract_port_1_read = {
		void apply(inout flow_port flow, out bit<32> proto, out bit<32> ports) {
			proto		= flow.proto;
			ports		= flow.ports;
			flow.proto	= 0;
			flow.ports	= 0;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_2) ract_port_2_read = {
		void apply(inout flow_port flow, out bit<32> proto, out bit<32> ports) {
			proto		= flow.proto;
			ports		= flow.ports;
			flow.proto	= 0;
			flow.ports	= 0;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_3) ract_port_3_read = {
		void apply(inout flow_port flow, out bit<32> proto, out bit<32> ports) {
			proto		= flow.proto;
			ports		= flow.ports;
			flow.proto	= 0;
			flow.ports	= 0;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_0) ract_port_0_update = {
		void apply(inout flow_port flow) {
			flow.proto = (bit<32>)hdr.ipv4.protocol;
			flow.ports = ig_md.ports;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_1) ract_port_1_update = {
		void apply(inout flow_port flow) {
			flow.proto = (bit<32>)hdr.ipv4.protocol;
			flow.ports = ig_md.ports;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_2) ract_port_2_update = {
		void apply(inout flow_port flow) {
			flow.proto = (bit<32>)hdr.ipv4.protocol;
			flow.ports = ig_md.ports;
		}
	};

	RegisterAction<flow_port, bit<16>, bit<32>>(reg_port_3) ract_port_3_update = {
		void apply(inout flow_port flow) {
			flow.proto = (bit<32>)hdr.ipv4.protocol;
			flow.ports = ig_md.ports;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_0) ract_syn_ack_0_read = {
		void apply(inout flow_flags flow, out bit<32> syn, out bit<32> ack) {
			syn			= flow.flag_a;
			ack			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_1) ract_syn_ack_1_read = {
		void apply(inout flow_flags flow, out bit<32> syn, out bit<32> ack) {
			syn			= flow.flag_a;
			ack			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_2) ract_syn_ack_2_read = {
		void apply(inout flow_flags flow, out bit<32> syn, out bit<32> ack) {
			syn			= flow.flag_a;
			ack			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_3) ract_syn_ack_3_read = {
		void apply(inout flow_flags flow, out bit<32> syn, out bit<32> ack) {
			syn			= flow.flag_a;
			ack			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_0) ract_fin_rst_0_read = {
		void apply(inout flow_flags flow, out bit<32> fin, out bit<32> rst) {
			fin			= flow.flag_a;
			rst			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_1) ract_fin_rst_1_read = {
		void apply(inout flow_flags flow, out bit<32> fin, out bit<32> rst) {
			fin			= flow.flag_a;
			rst			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_2) ract_fin_rst_2_read = {
		void apply(inout flow_flags flow, out bit<32> fin, out bit<32> rst) {
			fin			= flow.flag_a;
			rst			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_3) ract_fin_rst_3_read = {
		void apply(inout flow_flags flow, out bit<32> syn, out bit<32> ack) {
			syn			= flow.flag_a;
			ack			= flow.flag_b;
			flow.flag_a	= 0;
			flow.flag_b	= 0;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_0) ract_syn_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_0) ract_ack_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_0) ract_syn_ack_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_1) ract_syn_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_1) ract_ack_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_1) ract_syn_ack_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_2) ract_syn_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_2) ract_ack_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_2) ract_syn_ack_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_3) ract_syn_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_3) ract_ack_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_syn_ack_3) ract_syn_ack_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_0) ract_fin_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_0) ract_rst_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_0) ract_fin_rst_0_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_1) ract_fin_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_1) ract_rst_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_1) ract_fin_rst_1_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_2) ract_fin_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_2) ract_rst_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_2) ract_fin_rst_2_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_3) ract_fin_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_3) ract_rst_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_flags, bit<16>, bit<32>>(reg_fin_rst_3) ract_fin_rst_3_update = {
		void apply(inout flow_flags flow) {
			flow.flag_a = flow.flag_a + 1;
			flow.flag_b = flow.flag_b + 1;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_0) ract_data_0_read = {
		void apply(inout flow_data flow, out bit<32> cnt, out bit<32> len) {
			cnt			= flow.cnt;
			len			= flow.len;
			flow.cnt	= 0;
			flow.len	= 0;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_1) ract_data_1_read = {
		void apply(inout flow_data flow, out bit<32> cnt, out bit<32> len) {
			cnt			= flow.cnt;
			len			= flow.len;
			flow.cnt	= 0;
			flow.len	= 0;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_2) ract_data_2_read = {
		void apply(inout flow_data flow, out bit<32> cnt, out bit<32> len) {
			cnt			= flow.cnt;
			len			= flow.len;
			flow.cnt	= 0;
			flow.len	= 0;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_3) ract_data_3_read = {
		void apply(inout flow_data flow, out bit<32> cnt, out bit<32> len) {
			cnt			= flow.cnt;
			len			= flow.len;
			flow.cnt	= 0;
			flow.len	= 0;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_0) ract_data_0_update = {
		void apply(inout flow_data flow) {
			flow.cnt = flow.cnt + 1;
			flow.len = flow.len + (bit<32>)hdr.ipv4.len;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_1) ract_data_1_update = {
		void apply(inout flow_data flow) {
			flow.cnt = flow.cnt + 1;
			flow.len = flow.len + (bit<32>)hdr.ipv4.len;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_2) ract_data_2_update = {
		void apply(inout flow_data flow) {
			flow.cnt = flow.cnt + 1;
			flow.len = flow.len + (bit<32>)hdr.ipv4.len;
		}
	};

	RegisterAction<flow_data, bit<16>, bit<32>>(reg_data_3) ract_data_3_update = {
		void apply(inout flow_data flow) {
			flow.cnt = flow.cnt + 1;
			flow.len = flow.len + (bit<32>)hdr.ipv4.len;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_0) ract_bin_len_0_0_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_1) ract_bin_len_0_1_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_2) ract_bin_len_0_2_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_3) ract_bin_len_0_3_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_0) ract_bin_len_0_0_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_1) ract_bin_len_0_1_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_2) ract_bin_len_0_2_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_0_3) ract_bin_len_0_3_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_0) ract_bin_len_1_0_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_1) ract_bin_len_1_1_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_2) ract_bin_len_1_2_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_3) ract_bin_len_1_3_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_0) ract_bin_len_1_0_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_1) ract_bin_len_1_1_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_2) ract_bin_len_1_2_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_1_3) ract_bin_len_1_3_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_0) ract_bin_len_2_0_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_1) ract_bin_len_2_1_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_2) ract_bin_len_2_2_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_3) ract_bin_len_2_3_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_0) ract_bin_len_2_0_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_1) ract_bin_len_2_1_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_2) ract_bin_len_2_2_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_2_3) ract_bin_len_2_3_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_0) ract_bin_len_3_0_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_1) ract_bin_len_3_1_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_2) ract_bin_len_3_2_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_3) ract_bin_len_3_3_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_0) ract_bin_len_3_0_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_1) ract_bin_len_3_1_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_2) ract_bin_len_3_2_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_3_3) ract_bin_len_3_3_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_0) ract_bin_len_4_0_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_1) ract_bin_len_4_1_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_2) ract_bin_len_4_2_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_3) ract_bin_len_4_3_read = {
		void apply(inout bin_len bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a		= bin.bin_a;
			bin_b		= bin.bin_b;
			bin.bin_a	= 0;
			bin.bin_b	= 0;
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_0) ract_bin_len_4_0_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_1) ract_bin_len_4_1_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_2) ract_bin_len_4_2_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_len, bit<16>, bit<32>>(reg_bin_len_4_3) ract_bin_len_4_3_update = {
		void apply(inout bin_len bin) {
			if (hdr.ipv4.len <= BIN_LEN_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	action hash_calc() {
		hdr.meta.hash_flow = (bit<16>)hash_flow.get({hdr.ipv4.src_addr,
													 hdr.ipv4.dst_addr,
													 ig_md.l4_src_port,
													 ig_md.l4_dst_port})[14:0];
	}

	action set_out_port(PortId_t port) {
		hdr.hv_bin_len.setValid();
		ig_tm_md.ucast_egress_port = port;
		// in_counter.count();
	}

	// Timestamp bit-slicing from 48 to 32 bits.
	// Necessary to alow usage in reg. actions, which only support max 32 bits.
	action ts_conversion() {
		hdr.meta.cur_ts = ig_intr_md.ingress_mac_tstamp[47:16];
	}

	action index_cntr_update() {
		hdr.meta.index_cntr = ract_index_cntr_update.execute(0);
	}

	action set_hv_hdrs() {
		ig_md.custom_hdr_toggle = 1;
	}

	action reg_ts_0_read() {
		ract_ts_0_read.execute(hdr.meta.index_cntr,
							   hdr.hv_0.ts_start,
							   hdr.hv_0.ts_end);
	}

	action reg_ts_1_read() {
		ract_ts_1_read.execute(hdr.meta.index_cntr,
							   hdr.hv_1.ts_start,
							   hdr.hv_1.ts_end);
	}

	action reg_ts_2_read() {
		ract_ts_2_read.execute(hdr.meta.index_cntr,
							   hdr.hv_2.ts_start,
							   hdr.hv_2.ts_end);
	}

	action reg_ts_3_read() {
		ract_ts_3_read.execute(hdr.meta.index_cntr,
							   hdr.hv_3.ts_start,
							   hdr.hv_3.ts_end);
	}

	action reg_ts_0_update() {
		ract_ts_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0],
								 ig_md.ts_agg_tmp,
								 hdr.meta.flow_end_old);
	}

	action reg_ts_1_update() {
		ract_ts_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0],
								 ig_md.ts_agg_tmp,
								 hdr.meta.flow_end_old);
	}

	action reg_ts_2_update() {
		ract_ts_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0],
								 ig_md.ts_agg_tmp,
								 hdr.meta.flow_end_old);
	}

	action reg_ts_3_update() {
		ract_ts_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0],
								 ig_md.ts_agg_tmp,
								 hdr.meta.flow_end_old);
	}

	action reg_ts_agg_0_read() {
		hdr.hv_0.ts_agg = ract_ts_agg_0_read.execute(hdr.meta.index_cntr);
	}

	action reg_ts_agg_1_read() {
		hdr.hv_1.ts_agg = ract_ts_agg_1_read.execute(hdr.meta.index_cntr);
	}

	action reg_ts_agg_2_read() {
		hdr.hv_2.ts_agg = ract_ts_agg_2_read.execute(hdr.meta.index_cntr);
	}

	action reg_ts_agg_3_read() {
		hdr.hv_3.ts_agg = ract_ts_agg_3_read.execute(hdr.meta.index_cntr);
	}

	action reg_ts_agg_0_update() {
		ract_ts_agg_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ts_agg_1_update() {
		ract_ts_agg_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ts_agg_2_update() {
		ract_ts_agg_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ts_agg_3_update() {
		ract_ts_agg_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ip_0_read() {
		ract_ip_0_read.execute(hdr.meta.index_cntr,
							   hdr.hv_0.ip_src,
							   hdr.hv_0.ip_dst);
	}

	action reg_ip_1_read() {
		ract_ip_1_read.execute(hdr.meta.index_cntr,
							   hdr.hv_1.ip_src,
							   hdr.hv_1.ip_dst);
	}

	action reg_ip_2_read() {
		ract_ip_2_read.execute(hdr.meta.index_cntr,
							   hdr.hv_2.ip_src,
							   hdr.hv_2.ip_dst);
	}

	action reg_ip_3_read() {
		ract_ip_3_read.execute(hdr.meta.index_cntr,
							   hdr.hv_3.ip_src,
							   hdr.hv_3.ip_dst);
	}

	action reg_ip_0_update() {
		ract_ip_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ip_1_update() {
		ract_ip_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ip_2_update() {
		ract_ip_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ip_3_update() {
		ract_ip_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_port_0_read() {
		ract_port_0_read.execute(hdr.meta.index_cntr,
								 hdr.hv_0.proto,
								 hdr.hv_0.ports);
	}

	action reg_port_1_read() {
		ract_port_1_read.execute(hdr.meta.index_cntr,
								 hdr.hv_1.proto,
								 hdr.hv_1.ports);
	}

	action reg_port_2_read() {
		ract_port_2_read.execute(hdr.meta.index_cntr,
								 hdr.hv_2.proto,
								 hdr.hv_2.ports);
	}

	action reg_port_3_read() {
		ract_port_3_read.execute(hdr.meta.index_cntr,
								 hdr.hv_3.proto,
								 hdr.hv_3.ports);
	}

	action reg_port_0_update() {
		ract_port_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_port_1_update() {
		ract_port_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_port_2_update() {
		ract_port_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_port_3_update() {
		ract_port_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_ack_0_read() {
		ract_syn_ack_0_read.execute(hdr.meta.index_cntr,
									hdr.hv_0.syn,
									hdr.hv_0.ack);
	}

	action reg_syn_ack_1_read() {
		ract_syn_ack_1_read.execute(hdr.meta.index_cntr,
									hdr.hv_1.syn,
									hdr.hv_1.ack);
	}

	action reg_syn_ack_2_read() {
		ract_syn_ack_2_read.execute(hdr.meta.index_cntr,
									hdr.hv_2.syn,
									hdr.hv_2.ack);
	}

	action reg_syn_ack_3_read() {
		ract_syn_ack_3_read.execute(hdr.meta.index_cntr,
									hdr.hv_3.syn,
									hdr.hv_3.ack);
	}

	action reg_fin_rst_0_read() {
		ract_fin_rst_0_read.execute(hdr.meta.index_cntr,
									hdr.hv_0.fin,
									hdr.hv_0.rst);
	}

	action reg_fin_rst_1_read() {
		ract_fin_rst_1_read.execute(hdr.meta.index_cntr,
									hdr.hv_1.fin,
									hdr.hv_1.rst);
	}

	action reg_fin_rst_2_read() {
		ract_fin_rst_2_read.execute(hdr.meta.index_cntr,
									hdr.hv_2.fin,
									hdr.hv_2.rst);
	}

	action reg_fin_rst_3_read() {
		ract_fin_rst_3_read.execute(hdr.meta.index_cntr,
									hdr.hv_3.fin,
									hdr.hv_3.rst);
	}

	action reg_syn_0_update() {
		ract_syn_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ack_0_update() {
		ract_ack_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_ack_0_update() {
		ract_syn_ack_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_1_update() {
		ract_syn_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ack_1_update() {
		ract_ack_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_ack_1_update() {
		ract_syn_ack_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_2_update() {
		ract_syn_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ack_2_update() {
		ract_ack_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_ack_2_update() {
		ract_syn_ack_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_3_update() {
		ract_syn_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_ack_3_update() {
		ract_ack_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_syn_ack_3_update() {
		ract_syn_ack_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_0_update() {
		ract_fin_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_rst_0_update() {
		ract_rst_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_rst_0_update() {
		ract_fin_rst_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_1_update() {
		ract_fin_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_rst_1_update() {
		ract_rst_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_rst_1_update() {
		ract_fin_rst_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_2_update() {
		ract_fin_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_rst_2_update() {
		ract_rst_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_rst_2_update() {
		ract_fin_rst_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_3_update() {
		ract_fin_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_rst_3_update() {
		ract_rst_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_fin_rst_3_update() {
		ract_fin_rst_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_data_0_read() {
		ract_data_0_read.execute(hdr.meta.index_cntr,
								 hdr.hv_0.cnt,
								 hdr.hv_0.len);
	}

	action reg_data_1_read() {
		ract_data_1_read.execute(hdr.meta.index_cntr,
								 hdr.hv_1.cnt,
								 hdr.hv_1.len);
	}

	action reg_data_2_read() {
		ract_data_2_read.execute(hdr.meta.index_cntr,
								 hdr.hv_2.cnt,
								 hdr.hv_2.len);
	}

	action reg_data_3_read() {
		ract_data_3_read.execute(hdr.meta.index_cntr,
								 hdr.hv_3.cnt,
								 hdr.hv_3.len);
	}

	action reg_data_0_update() {
		ract_data_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_data_1_update() {
		ract_data_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_data_2_update() {
		ract_data_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_data_3_update() {
		ract_data_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_0_0_read() {
		ract_bin_len_0_0_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_0_0,
									  hdr.hv_bin_len.b_0_0);
	}

	action reg_bin_len_0_1_read() {
		ract_bin_len_0_1_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_0_1,
									  hdr.hv_bin_len.b_0_1);
	}

	action reg_bin_len_0_2_read() {
		ract_bin_len_0_2_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_0_2,
									  hdr.hv_bin_len.b_0_2);
	}

	action reg_bin_len_0_3_read() {
		ract_bin_len_0_3_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_0_3,
									  hdr.hv_bin_len.b_0_3);
	}

	action reg_bin_len_0_0_update() {
		ract_bin_len_0_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_0_1_update() {
		ract_bin_len_0_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_0_2_update() {
		ract_bin_len_0_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_0_3_update() {
		ract_bin_len_0_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_1_0_read() {
		ract_bin_len_1_0_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_1_0,
									  hdr.hv_bin_len.b_1_0);
	}

	action reg_bin_len_1_1_read() {
		ract_bin_len_1_1_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_1_1,
									  hdr.hv_bin_len.b_1_1);
	}

	action reg_bin_len_1_2_read() {
		ract_bin_len_1_2_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_1_2,
									  hdr.hv_bin_len.b_1_2);
	}

	action reg_bin_len_1_3_read() {
		ract_bin_len_1_3_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_1_3,
									  hdr.hv_bin_len.b_1_3);
	}

	action reg_bin_len_1_0_update() {
		ract_bin_len_1_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_1_1_update() {
		ract_bin_len_1_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_1_2_update() {
		ract_bin_len_1_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_1_3_update() {
		ract_bin_len_1_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_2_0_read() {
		ract_bin_len_2_0_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_2_0,
									  hdr.hv_bin_len.b_2_0);
	}

	action reg_bin_len_2_1_read() {
		ract_bin_len_2_1_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_2_1,
									  hdr.hv_bin_len.b_2_1);
	}

	action reg_bin_len_2_2_read() {
		ract_bin_len_2_2_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_2_2,
									  hdr.hv_bin_len.b_2_2);
	}

	action reg_bin_len_2_3_read() {
		ract_bin_len_2_3_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_2_3,
									  hdr.hv_bin_len.b_2_3);
	}

	action reg_bin_len_2_0_update() {
		ract_bin_len_2_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_2_1_update() {
		ract_bin_len_2_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_2_2_update() {
		ract_bin_len_2_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_2_3_update() {
		ract_bin_len_2_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_3_0_read() {
		ract_bin_len_3_0_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_3_0,
									  hdr.hv_bin_len.b_3_0);
	}

	action reg_bin_len_3_1_read() {
		ract_bin_len_3_1_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_3_1,
									  hdr.hv_bin_len.b_3_1);
	}

	action reg_bin_len_3_2_read() {
		ract_bin_len_3_2_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_3_2,
									  hdr.hv_bin_len.b_3_2);
	}

	action reg_bin_len_3_3_read() {
		ract_bin_len_3_3_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_3_3,
									  hdr.hv_bin_len.b_3_3);
	}

	action reg_bin_len_3_0_update() {
		ract_bin_len_3_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_3_1_update() {
		ract_bin_len_3_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_3_2_update() {
		ract_bin_len_3_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_3_3_update() {
		ract_bin_len_3_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_4_0_read() {
		ract_bin_len_4_0_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_4_0,
									  hdr.hv_bin_len.b_4_0);
	}

	action reg_bin_len_4_1_read() {
		ract_bin_len_4_1_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_4_1,
									  hdr.hv_bin_len.b_4_1);
	}

	action reg_bin_len_4_2_read() {
		ract_bin_len_4_2_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_4_2,
									  hdr.hv_bin_len.b_4_2);
	}

	action reg_bin_len_4_3_read() {
		ract_bin_len_4_3_read.execute(hdr.meta.index_cntr,
									  hdr.hv_bin_len.a_4_3,
									  hdr.hv_bin_len.b_4_3);
	}

	action reg_bin_len_4_0_update() {
		ract_bin_len_4_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_4_1_update() {
		ract_bin_len_4_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_4_2_update() {
		ract_bin_len_4_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_len_4_3_update() {
		ract_bin_len_4_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action set_flow_long_0() {
		hdr.hv_0.long = 1;
	}

	action set_flow_long_1() {
		hdr.hv_1.long = 1;
	}

	action set_flow_long_2() {
		hdr.hv_2.long = 1;
	}

	action set_flow_long_3() {
		hdr.hv_3.long = 1;
	}

	action miss() {
		// in_counter.count();
	}

	table fwd {
		key = {
			ig_intr_md.ingress_port : exact;
			ig_md.custom_hdr_toggle : exact;
		}
		actions = {
			set_out_port;
			miss;
		}
		const default_action = miss;
		// counters = in_counter;
		size = 4;
		// const entries = {
		//	   (8, 1) : set_out_port(OUT_PORT);
		// }
	}

	table hv_0_hdr_valid {
		key = {
			hdr.hv_0.ts_start : ternary;
		}
		actions = {
			set_hv_hdrs;
			NoAction;
		}
		size = 1;
		 const entries = {
			(0x0 &&& 0x1) : NoAction;
			(0x0 &&& 0x0) : set_hv_hdrs;
		 }
	}

	table hv_1_hdr_valid {
		key = {
			hdr.hv_1.ts_start : ternary;
		}
		actions = {
			set_hv_hdrs;
			NoAction;
		}
		size = 1;
		 const entries = {
			(0x0 &&& 0x1) : NoAction;
			(0x0 &&& 0x0) : set_hv_hdrs;
		 }
	}

	table hv_2_hdr_valid {
		key = {
			hdr.hv_2.ts_start : ternary;
		}
		actions = {
			set_hv_hdrs;
			NoAction;
		}
		size = 1;
		 const entries = {
			(0x0 &&& 0x1) : NoAction;
			(0x0 &&& 0x0) : set_hv_hdrs;
		 }
	}

	table hv_3_hdr_valid {
		key = {
			hdr.hv_3.ts_start : ternary;
		}
		actions = {
			set_hv_hdrs;
			NoAction;
		}
		size = 1;
		 const entries = {
			(0x0 &&& 0x1) : NoAction;
			(0x0 &&& 0x0) : set_hv_hdrs;
		 }
	}

	table ts_0_read {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_0_read;
		}
		size = 1;
		const entries = {
			(8192..32767) : reg_ts_0_read;
		}
	}

	table ts_1_read {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_1_read;
		}
		size = 2;
		const entries = {
			(0..8191)		: reg_ts_1_read;
			(16384..32767)	: reg_ts_1_read;
		}
	}

	table ts_2_read {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_2_read;
		}
		size = 2;
		const entries = {
			(0..16383)		: reg_ts_2_read;
			(24576..32767)	: reg_ts_2_read;
		}
	}

	table ts_3_read {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_3_read;
		}
		size = 1;
		const entries = {
			(0..24575) : reg_ts_3_read;
		}
	}

	table ts_0_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_0_update;
		}
		size = 1;
		const entries = {
			(0..8191) : reg_ts_0_update;
		}
	}

	table ts_1_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383) : reg_ts_1_update;
		}
	}

	table ts_2_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_2_update;
		}
		size = 1;
		const entries = {
			(16384..24575) : reg_ts_2_update;
		}
	}

	table ts_3_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_3_update;
		}
		size = 1;
		const entries = {
			(24576..32767) : reg_ts_3_update;
		}
	}

	table ts_agg_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ts_agg_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_ts_agg_0_read;
		}
	}

	table ts_agg_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ts_agg_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_ts_agg_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_ts_agg_1_read;
		}
	}

	table ts_agg_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ts_agg_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_ts_agg_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_ts_agg_2_read;
		}
	}

	table ts_agg_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ts_agg_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)	: NoAction;
			(0x0 &&& 0x0, 0..24575)	: reg_ts_agg_3_read;
		}
	}

	table ts_agg_0_update {
		key = {
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ts_agg_0_update;
		}
		size = 1;
		const entries = {
			(0..8191) : reg_ts_agg_0_update;
		}
	}

	table ts_agg_1_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_agg_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383) : reg_ts_agg_1_update;
		}
	}

	table ts_agg_2_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_agg_2_update;
		}
		size = 1;
		const entries = {
			(16384..24575) : reg_ts_agg_2_update;
		}
	}

	table ts_agg_3_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ts_agg_3_update;
		}
		size = 1;
		const entries = {
			(24576..32767) : reg_ts_agg_3_update;
		}
	}

	table ip_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ip_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_ip_0_read;
		}
	}

	table ip_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ip_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_ip_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_ip_1_read;
		}
	}

	table ip_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ip_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_ip_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_ip_2_read;
		}
	}

	table ip_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_ip_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..24575)		: reg_ip_3_read;
		}
	}

	table ip_0_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ip_0_update;
		}
		size = 1;
		const entries = {
			(0..8191) : reg_ip_0_update;
		}
	}

	table ip_1_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ip_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383) : reg_ip_1_update;
		}
	}

	table ip_2_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ip_2_update;
		}
		size = 1;
		const entries = {
			(16384..24575) : reg_ip_2_update;
		}
	}

	table ip_3_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_ip_3_update;
		}
		size = 1;
		const entries = {
			(24576..32767) : reg_ip_3_update;
		}
	}

	table port_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_port_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_port_0_read;
		}
	}

	table port_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_port_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_port_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_port_1_read;
		}
	}

	table port_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_port_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_port_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_port_2_read;
		}
	}

	table port_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_port_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..24575)		: reg_port_3_read;
		}
	}

	table port_0_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_port_0_update;
		}
		size = 1;
		const entries = {
			(0..8191) : reg_port_0_update;
		}
	}

	table port_1_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_port_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383) : reg_port_1_update;
		}
	}

	table port_2_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_port_2_update;
		}
		size = 1;
		const entries = {
			(16384..24575) : reg_port_2_update;
		}
	}

	table port_3_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_port_3_update;
		}
		size = 1;
		const entries = {
			(24576..32767) : reg_port_3_update;
		}
	}

	table syn_ack_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_syn_ack_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_syn_ack_0_read;
		}
	}

	table syn_ack_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_syn_ack_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_syn_ack_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_syn_ack_1_read;
		}
	}

	table syn_ack_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_syn_ack_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_syn_ack_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_syn_ack_2_read;
		}
	}

	table syn_ack_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_syn_ack_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..24575)		: reg_syn_ack_3_read;
		}
	}

	table fin_rst_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_fin_rst_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_fin_rst_0_read;
		}
	}

	table fin_rst_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_fin_rst_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_fin_rst_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_fin_rst_1_read;
		}
	}

	table fin_rst_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_fin_rst_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_fin_rst_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_fin_rst_2_read;
		}
	}

	table fin_rst_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_fin_rst_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..24575)		: reg_fin_rst_3_read;
		}
	}

	table syn_ack_0_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.syn			: exact;
			hdr.tcp.ack			: exact;
		}
		actions = {
			reg_syn_0_update;
			reg_ack_0_update;
			reg_syn_ack_0_update;
		}
		size = 3;
		 const entries = {
			   (0..8191, 1, 0) : reg_syn_0_update;
			   (0..8191, 0, 1) : reg_ack_0_update;
			   (0..8191, 1, 1) : reg_syn_ack_0_update;
		 }
	}

	table syn_ack_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.syn			: exact;
			hdr.tcp.ack			: exact;
		}
		actions = {
			reg_syn_1_update;
			reg_ack_1_update;
			reg_syn_ack_1_update;
		}
		size = 3;
		 const entries = {
			   (8192..16383, 1, 0) : reg_syn_1_update;
			   (8192..16383, 0, 1) : reg_ack_1_update;
			   (8192..16383, 1, 1) : reg_syn_ack_1_update;
		 }
	}

	table syn_ack_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.syn			: exact;
			hdr.tcp.ack			: exact;
		}
		actions = {
			reg_syn_2_update;
			reg_ack_2_update;
			reg_syn_ack_2_update;
		}
		size = 3;
		 const entries = {
			   (16384..24575, 1, 0) : reg_syn_2_update;
			   (16384..24575, 0, 1) : reg_ack_2_update;
			   (16384..24575, 1, 1) : reg_syn_ack_2_update;
		 }
	}

	table syn_ack_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.syn			: exact;
			hdr.tcp.ack			: exact;
		}
		actions = {
			reg_syn_3_update;
			reg_ack_3_update;
			reg_syn_ack_3_update;
		}
		size = 3;
		 const entries = {
			   (24576..32767, 1, 0) : reg_syn_3_update;
			   (24576..32767, 0, 1) : reg_ack_3_update;
			   (24576..32767, 1, 1) : reg_syn_ack_3_update;
		 }
	}

	table fin_rst_0_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.fin			: exact;
			hdr.tcp.rst			: exact;
		}
		actions = {
			reg_fin_0_update;
			reg_rst_0_update;
			reg_fin_rst_0_update;
		}
		size = 3;
		 const entries = {
			   (0..8191, 1, 0) : reg_fin_0_update;
			   (0..8191, 0, 1) : reg_rst_0_update;
			   (0..8191, 1, 1) : reg_fin_rst_0_update;
		 }
	}

	table fin_rst_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.fin			: exact;
			hdr.tcp.rst			: exact;
		}
		actions = {
			reg_fin_1_update;
			reg_rst_1_update;
			reg_fin_rst_1_update;
		}
		size = 3;
		 const entries = {
			   (8192..16383, 1, 0) : reg_fin_1_update;
			   (8192..16383, 0, 1) : reg_rst_1_update;
			   (8192..16383, 1, 1) : reg_fin_rst_1_update;
		 }
	}

	table fin_rst_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.fin			: exact;
			hdr.tcp.rst			: exact;
		}
		actions = {
			reg_fin_2_update;
			reg_rst_2_update;
			reg_fin_rst_2_update;
		}
		size = 3;
		 const entries = {
			   (16384..24575, 1, 0) : reg_fin_2_update;
			   (16384..24575, 0, 1) : reg_rst_2_update;
			   (16384..24575, 1, 1) : reg_fin_rst_2_update;
		 }
	}

	table fin_rst_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.tcp.fin			: exact;
			hdr.tcp.rst			: exact;
		}
		actions = {
			reg_fin_3_update;
			reg_rst_3_update;
			reg_fin_rst_3_update;
		}
		size = 3;
		 const entries = {
			   (24576..32767, 1, 0) : reg_fin_3_update;
			   (24576..32767, 0, 1) : reg_rst_3_update;
			   (24576..32767, 1, 1) : reg_fin_rst_3_update;
		 }
	}

	table data_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_data_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 8192..32767)	: reg_data_0_read;
		}
	}

	table data_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_data_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..8191)		: reg_data_1_read;
			(0x0 &&& 0x0, 16384..32767)	: reg_data_1_read;
		}
	}

	table data_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_data_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..16383)		: reg_data_2_read;
			(0x0 &&& 0x0, 24576..32767)	: reg_data_2_read;
		}
	}

	table data_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
		}
		actions = {
			reg_data_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767)		: NoAction;
			(0x0 &&& 0x0, 0..24575)		: reg_data_3_read;
		}
	}

	table data_0_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_data_0_update;
		}
		size = 1;
		const entries = {
			(0..8191) : reg_data_0_update;
		}
	}

	table data_1_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_data_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383) : reg_data_1_update;
		}
	}

	table data_2_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_data_2_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(16384..24575) : reg_data_2_update;
		}
	}

	table data_3_update {
		key = {
			hdr.meta.hash_flow : range;
		}
		actions = {
			reg_data_3_update;
		}
		size = 1;
		const entries = {
			(24576..32767) : reg_data_3_update;
		}
	}

	table bin_len_0_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfe00)	: reg_bin_len_0_0_read;
		}
	}

	table bin_len_0_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfe00)		: reg_bin_len_0_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfe00)	: reg_bin_len_0_1_read;
		}
	}

	table bin_len_0_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfe00)		: reg_bin_len_0_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfe00)	: reg_bin_len_0_2_read;
		}
	}

	table bin_len_0_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfe00)	: reg_bin_len_0_3_read;
		}
	}

	table bin_len_0_0_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_0_update;
		}
		size = 1;
		const entries = {
			(0..8191, 0x0 &&& 0xfe00) : reg_bin_len_0_0_update;
		}
	}

	table bin_len_0_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_1_update;
		}
		size = 1;
		const entries = {
			(8192..16383, 0x0 &&& 0xfe00) : reg_bin_len_0_1_update;
		}
	}

	table bin_len_0_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_2_update;
		}
		size = 1;
		const entries = {
			(16384..24575, 0x0 &&& 0xfe00) : reg_bin_len_0_2_update;
		}
	}

	table bin_len_0_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_0_3_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(24576..32767, 0x0 &&& 0xfe00) : reg_bin_len_0_3_update;
		}
	}

	table bin_len_1_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfe00)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfc00)	: reg_bin_len_1_0_read;
		}
	}

	table bin_len_1_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfe00)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfc00)		: reg_bin_len_1_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfe00)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfc00)	: reg_bin_len_1_1_read;
		}
	}

	table bin_len_1_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfe00)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfc00)		: reg_bin_len_1_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfe00)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfc00)	: reg_bin_len_1_2_read;
		}
	}

	table bin_len_1_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfe00)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfc00)	: reg_bin_len_1_3_read;
		}
	}

	table bin_len_1_0_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xfe00) : NoAction;
			(0..8191, 0x0 &&& 0xfc00) : reg_bin_len_1_0_update;
		}
	}

	table bin_len_1_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xfe00) : NoAction;
			(8192..16383, 0x0 &&& 0xfc00) : reg_bin_len_1_1_update;
		}
	}

	table bin_len_1_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xfe00) : NoAction;
			(16384..24575, 0x0 &&& 0xfc00) : reg_bin_len_1_2_update;
		}
	}

	table bin_len_1_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_1_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xfe00) : NoAction;
			(24576..32767, 0x0 &&& 0xfc00) : reg_bin_len_1_3_update;
		}
	}

	table bin_len_2_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfc00)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfa00)	: reg_bin_len_2_0_read;
		}
	}

	table bin_len_2_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfc00)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfa00)		: reg_bin_len_2_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfc00)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfa00)	: reg_bin_len_2_1_read;
		}
	}

	table bin_len_2_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfc00)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfa00)		: reg_bin_len_2_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfc00)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfa00)	: reg_bin_len_2_2_read;
		}
	}

	table bin_len_2_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfc00)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfa00)	: reg_bin_len_2_3_read;
		}
	}

	table bin_len_2_0_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xfc00) : NoAction;
			(0..8191, 0x0 &&& 0xfa00) : reg_bin_len_2_0_update;
		}
	}

	table bin_len_2_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xfc00) : NoAction;
			(8192..16383, 0x0 &&& 0xfa00) : reg_bin_len_2_1_update;
		}
	}

	table bin_len_2_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xfc00) : NoAction;
			(16384..24575, 0x0 &&& 0xfa00) : reg_bin_len_2_2_update;
		}
	}

	table bin_len_2_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_2_3_update;
			NoAction;
		}
		size = 3;
		const entries = {
			(24576..32767, 0x0 &&& 0xfc00) : NoAction;
			(24576..32767, 0x0 &&& 0xfa00) : reg_bin_len_2_3_update;
		}
	}

	table bin_len_3_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xfa00)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xf800)	: reg_bin_len_3_0_read;
		}
	}

	table bin_len_3_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xfa00)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xf800)		: reg_bin_len_3_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xfa00)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xf800)	: reg_bin_len_3_1_read;
		}
	}

	table bin_len_3_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xfa00)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xf800)		: reg_bin_len_3_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xfa00)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xf800)	: reg_bin_len_3_2_read;
		}
	}

	table bin_len_3_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xfa00)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xf800)	: reg_bin_len_3_3_read;
		}
	}

	table bin_len_3_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			hdr.ipv4.len			: ternary;
		}
		actions = {
			reg_bin_len_3_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xfa00) : NoAction;
			(0..8191, 0x0 &&& 0xf800) : reg_bin_len_3_0_update;
		}
	}

	table bin_len_3_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xfa00) : NoAction;
			(8192..16383, 0x0 &&& 0xf800) : reg_bin_len_3_1_update;
		}
	}

	table bin_len_3_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xfa00) : NoAction;
			(16384..24575, 0x0 &&& 0xf800) : reg_bin_len_3_2_update;
		}
	}

	table bin_len_3_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_3_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xfa00) : NoAction;
			(24576..32767, 0x0 &&& 0xf800) : reg_bin_len_3_3_update;
		}
	}

	table bin_len_4_0_read {
		key = {
			hdr.hv_0.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xf800)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xf600)	: reg_bin_len_4_0_read;
		}
	}

	table bin_len_4_1_read {
		key = {
			hdr.hv_1.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xf800)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xf600)		: reg_bin_len_4_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xf800)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xf600)	: reg_bin_len_4_1_read;
		}
	}

	table bin_len_4_2_read {
		key = {
			hdr.hv_2.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xf800)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xf600)		: reg_bin_len_4_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xf800)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xf600)	: reg_bin_len_4_2_read;
		}
	}

	table bin_len_4_3_read {
		key = {
			hdr.hv_3.ts_start	: ternary;
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xf800)	: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xf600)	: reg_bin_len_4_3_read;
		}
	}

	table bin_len_4_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			hdr.ipv4.len			: ternary;
		}
		actions = {
			reg_bin_len_4_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xf800) : NoAction;
			(0..8191, 0x0 &&& 0xf600) : reg_bin_len_4_0_update;
		}
	}

	table bin_len_4_1_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xf800) : NoAction;
			(8192..16383, 0x0 &&& 0xf600) : reg_bin_len_4_1_update;
		}
	}

	table bin_len_4_2_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xf800) : NoAction;
			(16384..24575, 0x0 &&& 0xf600) : reg_bin_len_4_2_update;
		}
	}

	table bin_len_4_3_update {
		key = {
			hdr.meta.hash_flow	: range;
			hdr.ipv4.len		: ternary;
		}
		actions = {
			reg_bin_len_4_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xf800) : NoAction;
			(24576..32767, 0x0 &&& 0xf600) : reg_bin_len_4_3_update;
		}
	}

	table flow_size_0 {
		key = {
			hdr.hv_0.cnt : ternary;
		}
		actions = {
			set_flow_long_0;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0xfffffff0)	: NoAction;
			(0x0 &&& 0x0)			: set_flow_long_0;
		}
	}

	table flow_size_1 {
		key = {
			hdr.hv_1.cnt : ternary;
		}
		actions = {
			set_flow_long_1;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0xfffffff0)	: NoAction;
			(0x0 &&& 0x0)			: set_flow_long_1;
		}
	}

	table flow_size_2 {
		key = {
			hdr.hv_2.cnt : ternary;
		}
		actions = {
			set_flow_long_2;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0xfffffff0)	: NoAction;
			(0x0 &&& 0x0)			: set_flow_long_2;
		}
	}

	table flow_size_3 {
		key = {
			hdr.hv_3.cnt : ternary;
		}
		actions = {
			set_flow_long_3;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0xfffffff0)	: NoAction;
			(0x0 &&& 0x0)			: set_flow_long_3;
		}
	}

	apply {
		if (hdr.ipv4.isValid()) {
			if (!hdr.hv_0.isValid() && !hdr.hv_1.isValid() &&
				!hdr.hv_2.isValid() && !hdr.hv_3.isValid()) {

				// Timestamp bit-slicing.
				ts_conversion();

				// Round-robin: increment the current index for read actions.
				hash_calc();
				index_cntr_update();

				// Check the interval to which the calculated hash belongs:
				// [0-8191], [8192-16383], [16384-24575], [24576-32767]
				// Each interval corresponds to a register: 0, 1, 2 and 3, respectively.
				// The matching register is updated in the index corresponding to the hash,
				// all the others are checked for the flow timeout according to a round-robin.
				// (only if the timeout occurs in the ts regs do we retrieve the flow id/stats).
				ts_0_read.apply();
				ts_1_read.apply();
				ts_2_read.apply();
				ts_3_read.apply();
				ts_0_update.apply();
				ts_1_update.apply();
				ts_2_update.apply();
				ts_3_update.apply();
				hv_0_hdr_valid.apply();
				hv_1_hdr_valid.apply();
				hv_2_hdr_valid.apply();
				hv_3_hdr_valid.apply();
				ig_md.ts_agg_tmp = hdr.meta.cur_ts - ig_md.ts_agg_tmp;
				ts_agg_0_read.apply();
				ts_agg_1_read.apply();
				ts_agg_2_read.apply();
				ts_agg_3_read.apply();
				ts_agg_0_update.apply();
				ts_agg_1_update.apply();
				ts_agg_2_update.apply();
				ts_agg_3_update.apply();
				ip_0_read.apply();
				ip_1_read.apply();
				ip_2_read.apply();
				ip_3_read.apply();
				ip_0_update.apply();
				ip_1_update.apply();
				ip_2_update.apply();
				ip_3_update.apply();
				port_0_read.apply();
				port_1_read.apply();
				port_2_read.apply();
				port_3_read.apply();
				port_0_update.apply();
				port_1_update.apply();
				port_2_update.apply();
				port_3_update.apply();
				syn_ack_0_read.apply();
				syn_ack_1_read.apply();
				syn_ack_2_read.apply();
				syn_ack_3_read.apply();
				fin_rst_0_read.apply();
				fin_rst_1_read.apply();
				fin_rst_2_read.apply();
				fin_rst_3_read.apply();
				syn_ack_0_update.apply();
				syn_ack_1_update.apply();
				syn_ack_2_update.apply();
				syn_ack_3_update.apply();
				fin_rst_0_update.apply();
				fin_rst_1_update.apply();
				fin_rst_2_update.apply();
				fin_rst_3_update.apply();
				data_0_read.apply();
				data_1_read.apply();
				data_2_read.apply();
				data_3_read.apply();
				data_0_update.apply();
				data_1_update.apply();
				data_2_update.apply();
				data_3_update.apply();

				bin_len_0_0_read.apply();
				bin_len_0_1_read.apply();
				bin_len_0_2_read.apply();
				bin_len_0_3_read.apply();
				bin_len_0_0_update.apply();
				bin_len_0_1_update.apply();
				bin_len_0_2_update.apply();
				bin_len_0_3_update.apply();
				bin_len_1_0_read.apply();
				bin_len_1_1_read.apply();
				bin_len_1_2_read.apply();
				bin_len_1_3_read.apply();
				bin_len_1_0_update.apply();
				bin_len_1_1_update.apply();
				bin_len_1_2_update.apply();
				bin_len_1_3_update.apply();
				bin_len_2_0_read.apply();
				bin_len_2_1_read.apply();
				bin_len_2_2_read.apply();
				bin_len_2_3_read.apply();
				bin_len_2_0_update.apply();
				bin_len_2_1_update.apply();
				bin_len_2_2_update.apply();
				bin_len_2_3_update.apply();
				bin_len_3_0_read.apply();
				bin_len_3_1_read.apply();
				bin_len_3_2_read.apply();
				bin_len_3_3_read.apply();
				bin_len_3_0_update.apply();
				bin_len_3_1_update.apply();
				bin_len_3_2_update.apply();
				bin_len_3_3_update.apply();
				bin_len_4_0_read.apply();
				bin_len_4_1_read.apply();
				bin_len_4_2_read.apply();
				bin_len_4_3_read.apply();
				bin_len_4_0_update.apply();
				bin_len_4_1_update.apply();
				bin_len_4_2_update.apply();
				bin_len_4_3_update.apply();

				flow_size_0.apply();
				flow_size_1.apply();
				flow_size_2.apply();
				flow_size_3.apply();
			}

			// Only forward packets if a flow timeout has ocurred
			// (i.e., when the custom header is set to valid)
			fwd.apply();
		}
	}
}

// ---------------------------------------------------------------------------
// Pipeline - Egress
// ---------------------------------------------------------------------------

control Egress(inout header_t hdr,
			   inout eg_meta_t eg_md,
			   in egress_intrinsic_metadata_t eg_intr_md,
			   in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
			   inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
			   inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_0_0;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_0_1;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_0_2;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_0_3;

	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_1_0;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_1_1;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_1_2;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_1_3;

	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_2_0;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_2_1;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_2_2;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_2_3;

	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_3_0;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_3_1;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_3_2;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_3_3;

	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_4_0;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_4_1;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_4_2;
	Register<bin_ts, bit<16>>(REG_SIZE)	reg_bin_ts_4_3;

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_0) ract_bin_ts_0_0_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_1) ract_bin_ts_0_1_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_2) ract_bin_ts_0_2_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_3) ract_bin_ts_0_3_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_0) ract_bin_ts_0_0_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_1) ract_bin_ts_0_1_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_2) ract_bin_ts_0_2_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_0_3) ract_bin_ts_0_3_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_0_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_0) ract_bin_ts_1_0_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_1) ract_bin_ts_1_1_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_2) ract_bin_ts_1_2_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_3) ract_bin_ts_1_3_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_0) ract_bin_ts_1_0_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_1) ract_bin_ts_1_1_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_2) ract_bin_ts_1_2_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_1_3) ract_bin_ts_1_3_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_1_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_0) ract_bin_ts_2_0_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_1) ract_bin_ts_2_1_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_2) ract_bin_ts_2_2_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_3) ract_bin_ts_2_3_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_0) ract_bin_ts_2_0_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_1) ract_bin_ts_2_1_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_2) ract_bin_ts_2_2_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_2_3) ract_bin_ts_2_3_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_2_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_0) ract_bin_ts_3_0_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_1) ract_bin_ts_3_1_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_2) ract_bin_ts_3_2_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_3) ract_bin_ts_3_3_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_0) ract_bin_ts_3_0_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_1) ract_bin_ts_3_1_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_2) ract_bin_ts_3_2_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_3_3) ract_bin_ts_3_3_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_3_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_0) ract_bin_ts_4_0_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_1) ract_bin_ts_4_1_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_2) ract_bin_ts_4_2_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_3) ract_bin_ts_4_3_read = {
		void apply(inout bin_ts bin, out bit<32> bin_a, out bit<32> bin_b) {
			bin_a = bin.bin_a;
			bin_b = bin.bin_b;
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_0) ract_bin_ts_4_0_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_1) ract_bin_ts_4_1_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_2) ract_bin_ts_4_2_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	RegisterAction<bin_ts, bit<16>, bit<32>>(reg_bin_ts_4_3) ract_bin_ts_4_3_update = {
		void apply(inout bin_ts bin) {
			if (eg_md.cur_ts_interval <= BIN_TS_4_SPLIT) {
				bin.bin_a = bin.bin_a + 1;
			} else {
				bin.bin_b = bin.bin_b + 1;
			}
		}
	};

	// Calculate the ts interval between the current and last packet for the current flow.
	action ts_interval_calc() {
		eg_md.cur_ts_interval = hdr.meta.cur_ts - hdr.meta.flow_end_old;
	}

	action reg_bin_ts_0_0_read() {
		ract_bin_ts_0_0_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_0_0,
									 hdr.hv_bin_ts.b_0_0);
	}

	action reg_bin_ts_0_1_read() {
		ract_bin_ts_0_1_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_0_1,
									 hdr.hv_bin_ts.b_0_1);
	}

	action reg_bin_ts_0_2_read() {
		ract_bin_ts_0_2_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_0_2,
									 hdr.hv_bin_ts.b_0_2);
	}

	action reg_bin_ts_0_3_read() {
		ract_bin_ts_0_3_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_0_3,
									 hdr.hv_bin_ts.b_0_3);
	}

	action reg_bin_ts_0_0_update() {
		ract_bin_ts_0_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_0_1_update() {
		ract_bin_ts_0_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_0_2_update() {
		ract_bin_ts_0_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_0_3_update() {
		ract_bin_ts_0_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_1_0_read() {
		ract_bin_ts_1_0_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_1_0,
									 hdr.hv_bin_ts.b_1_0);
	}

	action reg_bin_ts_1_1_read() {
		ract_bin_ts_1_1_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_1_1,
									 hdr.hv_bin_ts.b_1_1);
	}

	action reg_bin_ts_1_2_read() {
		ract_bin_ts_1_2_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_1_2,
									 hdr.hv_bin_ts.b_1_2);
	}

	action reg_bin_ts_1_3_read() {
		ract_bin_ts_1_3_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_1_3,
									 hdr.hv_bin_ts.b_1_3);
	}

	action reg_bin_ts_1_0_update() {
		ract_bin_ts_1_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_1_1_update() {
		ract_bin_ts_1_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_1_2_update() {
		ract_bin_ts_1_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_1_3_update() {
		ract_bin_ts_1_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_2_0_read() {
		ract_bin_ts_2_0_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_2_0,
									 hdr.hv_bin_ts.b_2_0);
	}

	action reg_bin_ts_2_1_read() {
		ract_bin_ts_2_1_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_2_1,
									 hdr.hv_bin_ts.b_2_1);
	}

	action reg_bin_ts_2_2_read() {
		ract_bin_ts_2_2_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_2_2,
									 hdr.hv_bin_ts.b_2_2);
	}

	action reg_bin_ts_2_3_read() {
		ract_bin_ts_2_3_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_2_3,
									 hdr.hv_bin_ts.b_2_3);
	}

	action reg_bin_ts_2_0_update() {
		ract_bin_ts_2_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_2_1_update() {
		ract_bin_ts_2_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_2_2_update() {
		ract_bin_ts_2_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_2_3_update() {
		ract_bin_ts_2_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_3_0_read() {
		ract_bin_ts_3_0_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_3_0,
									 hdr.hv_bin_ts.b_3_0);
	}

	action reg_bin_ts_3_1_read() {
		ract_bin_ts_3_1_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_3_1,
									 hdr.hv_bin_ts.b_3_1);
	}

	action reg_bin_ts_3_2_read() {
		ract_bin_ts_3_2_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_3_2,
									 hdr.hv_bin_ts.b_3_2);
	}

	action reg_bin_ts_3_3_read() {
		ract_bin_ts_3_3_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_3_3,
									 hdr.hv_bin_ts.b_3_3);
	}

	action reg_bin_ts_3_0_update() {
		ract_bin_ts_3_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_3_1_update() {
		ract_bin_ts_3_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_3_2_update() {
		ract_bin_ts_3_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_3_3_update() {
		ract_bin_ts_3_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_4_0_read() {
		ract_bin_ts_4_0_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_4_0,
									 hdr.hv_bin_ts.b_4_0);
	}

	action reg_bin_ts_4_1_read() {
		ract_bin_ts_4_1_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_4_1,
									 hdr.hv_bin_ts.b_4_1);
	}

	action reg_bin_ts_4_2_read() {
		ract_bin_ts_4_2_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_4_2,
									 hdr.hv_bin_ts.b_4_2);
	}

	action reg_bin_ts_4_3_read() {
		ract_bin_ts_4_3_read.execute(hdr.meta.index_cntr,
									 hdr.hv_bin_ts.a_4_3,
									 hdr.hv_bin_ts.b_4_3);
	}

	action reg_bin_ts_4_0_update() {
		ract_bin_ts_4_0_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_4_1_update() {
		ract_bin_ts_4_1_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_4_2_update() {
		ract_bin_ts_4_2_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	action reg_bin_ts_4_3_update() {
		ract_bin_ts_4_3_update.execute((bit<16>)hdr.meta.hash_flow[12:0]);
	}

	table bin_ts_0_0_read {
		key = {
			hdr.hv_0.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_0_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffe0)	: reg_bin_ts_0_0_read;
		}
	}

	table bin_ts_0_1_read {
		key = {
			hdr.hv_1.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_1_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffe0)		: reg_bin_ts_0_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffe0)	: reg_bin_ts_0_1_read;
		}
	}

	table bin_ts_0_2_read {
		key = {
			hdr.hv_2.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_2_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffe0)		: reg_bin_ts_0_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffe0)	: reg_bin_ts_0_2_read;
		}
	}

	table bin_ts_0_3_read {
		key = {
			hdr.hv_3.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_3_read;
			NoAction;
		}
		size = 2;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)		: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffe0)	: reg_bin_ts_0_3_read;
		}
	}

	table bin_ts_0_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_0_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(0..8191, 0x0 &&& 0xffffffe0) : reg_bin_ts_0_0_update;
		}
	}

	table bin_ts_0_1_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_1_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(8192..16383, 0x0 &&& 0xffffffe0) : reg_bin_ts_0_1_update;
		}
	}

	table bin_ts_0_2_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_2_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(16384..24575, 0x0 &&& 0xffffffe0) : reg_bin_ts_0_2_update;
		}
	}

	table bin_ts_0_3_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_0_3_update;
			NoAction;
		}
		size = 1;
		const entries = {
			(24576..32767, 0x0 &&& 0xffffffe0) : reg_bin_ts_0_3_update;
		}
	}

	table bin_ts_1_0_read {
		key = {
			hdr.hv_0.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffe0)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffc0)	: reg_bin_ts_1_0_read;
		}
	}

	table bin_ts_1_1_read {
		key = {
			hdr.hv_1.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffe0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffc0)		: reg_bin_ts_1_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffe0)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffc0)	: reg_bin_ts_1_1_read;
		}
	}

	table bin_ts_1_2_read {
		key = {
			hdr.hv_2.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffe0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffc0)		: reg_bin_ts_1_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffe0)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffc0)	: reg_bin_ts_1_2_read;
		}
	}

	table bin_ts_1_3_read {
		key = {
			hdr.hv_3.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffe0)		: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffc0)		: reg_bin_ts_1_3_read;
		}
	}

	table bin_ts_1_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xffffffe0) : NoAction;
			(0..8191, 0x0 &&& 0xffffffc0) : reg_bin_ts_1_0_update;
		}
	}

	table bin_ts_1_1_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xffffffe0) : NoAction;
			(8192..16383, 0x0 &&& 0xffffffc0) : reg_bin_ts_1_1_update;
		}
	}

	table bin_ts_1_2_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xffffffe0) : NoAction;
			(16384..24575, 0x0 &&& 0xffffffc0) : reg_bin_ts_1_2_update;
		}
	}

	table bin_ts_1_3_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_1_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xffffffe0) : NoAction;
			(24576..32767, 0x0 &&& 0xffffffc0) : reg_bin_ts_1_3_update;
		}
	}

	table bin_ts_2_0_read {
		key = {
			hdr.hv_0.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffc0)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffa0)	: reg_bin_ts_2_0_read;
		}
	}

	table bin_ts_2_1_read {
		key = {
			hdr.hv_1.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffc0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffa0)		: reg_bin_ts_2_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffc0)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffa0)	: reg_bin_ts_2_1_read;
		}
	}

	table bin_ts_2_2_read {
		key = {
			hdr.hv_2.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffc0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffa0)		: reg_bin_ts_2_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffc0)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffa0)	: reg_bin_ts_2_2_read;
		}
	}

	table bin_ts_2_3_read {
		key = {
			hdr.hv_3.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffc0)		: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffa0)		: reg_bin_ts_2_3_read;
		}
	}

	table bin_ts_2_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xffffffc0) : NoAction;
			(0..8191, 0x0 &&& 0xffffffa0) : reg_bin_ts_2_0_update;
		}
	}

	table bin_ts_2_1_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xffffffc0) : NoAction;
			(8192..16383, 0x0 &&& 0xffffffa0) : reg_bin_ts_2_1_update;
		}
	}

	table bin_ts_2_2_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xffffffc0) : NoAction;
			(16384..24575, 0x0 &&& 0xffffffa0) : reg_bin_ts_2_2_update;
		}
	}

	table bin_ts_2_3_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_2_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xffffffc0) : NoAction;
			(24576..32767, 0x0 &&& 0xffffffa0) : reg_bin_ts_2_3_update;
		}
	}

	table bin_ts_3_0_read {
		key = {
			hdr.hv_0.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffffa0)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffff80)	: reg_bin_ts_3_0_read;
		}
	}

	table bin_ts_3_1_read {
		key = {
			hdr.hv_1.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffffa0)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffff80)		: reg_bin_ts_3_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffffa0)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffff80)	: reg_bin_ts_3_1_read;
		}
	}

	table bin_ts_3_2_read {
		key = {
			hdr.hv_2.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffffa0)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffff80)		: reg_bin_ts_3_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffffa0)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffff80)	: reg_bin_ts_3_2_read;
		}
	}

	table bin_ts_3_3_read {
		key = {
			hdr.hv_3.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffffa0)		: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffff80)		: reg_bin_ts_3_3_read;
		}
	}

	table bin_ts_3_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xffffffa0) : NoAction;
			(0..8191, 0x0 &&& 0xffffff80) : reg_bin_ts_3_0_update;
		}
	}

	table bin_ts_3_1_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xffffffa0) : NoAction;
			(8192..16383, 0x0 &&& 0xffffff80) : reg_bin_ts_3_1_update;
		}
	}

	table bin_ts_3_2_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xffffffa0) : NoAction;
			(16384..24575, 0x0 &&& 0xffffff80) : reg_bin_ts_3_2_update;
		}
	}

	table bin_ts_3_3_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_3_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xffffffa0) : NoAction;
			(24576..32767, 0x0 &&& 0xffffff80) : reg_bin_ts_3_3_update;
		}
	}

	table bin_ts_4_0_read {
		key = {
			hdr.hv_0.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_0_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffff80)	: NoAction;
			(0x0 &&& 0x0, 8192..32767, 0x0 &&& 0xffffff60)	: reg_bin_ts_4_0_read;
		}
	}

	table bin_ts_4_1_read {
		key = {
			hdr.hv_1.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_1_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffff80)		: NoAction;
			(0x0 &&& 0x0, 0..8191, 0x0 &&& 0xffffff60)		: reg_bin_ts_4_1_read;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffff80)	: NoAction;
			(0x0 &&& 0x0, 16384..32767, 0x0 &&& 0xffffff60)	: reg_bin_ts_4_1_read;
		}
	}

	table bin_ts_4_2_read {
		key = {
			hdr.hv_2.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_2_read;
			NoAction;
		}
		size = 5;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffff80)		: NoAction;
			(0x0 &&& 0x0, 0..16383, 0x0 &&& 0xffffff60)		: reg_bin_ts_4_2_read;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffff80)	: NoAction;
			(0x0 &&& 0x0, 24576..32767, 0x0 &&& 0xffffff60)	: reg_bin_ts_4_2_read;
		}
	}

	table bin_ts_4_3_read {
		key = {
			hdr.hv_3.ts_start		: ternary;
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_3_read;
			NoAction;
		}
		size = 3;
		const entries = {
			(0x0 &&& 0x1, 0..32767, 0x0 &&& 0x0)			: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffff80)		: NoAction;
			(0x0 &&& 0x0, 0..24575, 0x0 &&& 0xffffff60)		: reg_bin_ts_4_3_read;
		}
	}

	table bin_ts_4_0_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_0_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(0..8191, 0x0 &&& 0xffffff80) : NoAction;
			(0..8191, 0x0 &&& 0xffffff60) : reg_bin_ts_4_0_update;
		}
	}

	table bin_ts_4_1_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_1_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(8192..16383, 0x0 &&& 0xffffff80) : NoAction;
			(8192..16383, 0x0 &&& 0xffffff60) : reg_bin_ts_4_1_update;
		}
	}

	table bin_ts_4_2_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_2_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(16384..24575, 0x0 &&& 0xffffff80) : NoAction;
			(16384..24575, 0x0 &&& 0xffffff60) : reg_bin_ts_4_2_update;
		}
	}

	table bin_ts_4_3_update {
		key = {
			hdr.meta.hash_flow		: range;
			eg_md.cur_ts_interval	: ternary;
		}
		actions = {
			reg_bin_ts_4_3_update;
			NoAction;
		}
		size = 2;
		const entries = {
			(24576..32767, 0x0 &&& 0xffffff80) : NoAction;
			(24576..32767, 0x0 &&& 0xffffff60) : reg_bin_ts_4_3_update;
		}
	}

	apply {
		if (hdr.hv_0.isValid() && hdr.hv_1.isValid() &&
			hdr.hv_2.isValid() && hdr.hv_3.isValid()) {

			ts_interval_calc();

			bin_ts_0_0_read.apply();
			bin_ts_0_1_read.apply();
			bin_ts_0_2_read.apply();
			bin_ts_0_3_read.apply();
			bin_ts_0_0_update.apply();
			bin_ts_0_1_update.apply();
			bin_ts_0_2_update.apply();
			bin_ts_0_3_update.apply();
			bin_ts_1_0_read.apply();
			bin_ts_1_1_read.apply();
			bin_ts_1_2_read.apply();
			bin_ts_1_3_read.apply();
			bin_ts_1_0_update.apply();
			bin_ts_1_1_update.apply();
			bin_ts_1_2_update.apply();
			bin_ts_1_3_update.apply();
			bin_ts_2_0_read.apply();
			bin_ts_2_1_read.apply();
			bin_ts_2_2_read.apply();
			bin_ts_2_3_read.apply();
			bin_ts_2_0_update.apply();
			bin_ts_2_1_update.apply();
			bin_ts_2_2_update.apply();
			bin_ts_2_3_update.apply();
			bin_ts_3_0_read.apply();
			bin_ts_3_1_read.apply();
			bin_ts_3_2_read.apply();
			bin_ts_3_3_read.apply();
			bin_ts_3_0_update.apply();
			bin_ts_3_1_update.apply();
			bin_ts_3_2_update.apply();
			bin_ts_3_3_update.apply();
			bin_ts_4_0_read.apply();
			bin_ts_4_1_read.apply();
			bin_ts_4_2_read.apply();
			bin_ts_4_3_read.apply();
			bin_ts_4_0_update.apply();
			bin_ts_4_1_update.apply();
			bin_ts_4_2_update.apply();
			bin_ts_4_3_update.apply();
			hdr.hv_bin_ts.setValid();
		}
	}
}

// ---------------------------------------------------------------------------
// Instantiation
// ---------------------------------------------------------------------------

Pipeline(IngressParser(),
		 Ingress(),
		 IngressDeparser(),
		 EgressParser(),
		 Egress(),
		 EgressDeparser()) pipe;

Switch(pipe) main;
