#ifndef _STATS_FIVE_T_
#define _STATS_FIVE_T_

#include "../math/sqr.p4"
#include "../math/sqrt.p4"

control c_stats_five_t(inout header_t hdr, inout egress_metadata_t eg_md) {

    c_sqr()		mean_sqr_0;
    c_sqr()		mean_sqr_1;
    c_sqr()		variance_sqr_0;
    c_sqr()		variance_sqr_1;
    c_sqrt()    magnitude;
    c_sqrt()    std_dev_0;
    c_sqrt()    std_dev_1;
    c_sqrt()    radius;

	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_five_t_0;		// Hash for flow id (a->b)
	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_five_t_1;		// Hash for flow id (b->a)

	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_ts;
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_pkt_cnt_0; 	// Packet count for flow id (a->b)
	Register<cntr_cur, bit<16>>(REG_SIZE) reg_five_t_pkt_cnt;		// Packet count values (struct)
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_pkt_len;   	// Packet length for flow id (a->b)
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_ss_0;    		// Squared sum of the packet length
	Register<cntr_cur, bit<16>>(REG_SIZE) reg_five_t_ss;    		// Squared sum (struct)
	Register<cntr_cur, bit<16>>(REG_SIZE) reg_five_t_mean;		// Mean (struct)
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_flow_dir;		// Flow direction
	Register<cntr_cur, bit<16>>(REG_SIZE) reg_five_t_res;			// Residue values

	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_sum_res_prod_lo;			// Sum of residual products
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_sum_res_prod_lo_carry;	// Sum of residual products
	Register<bit<32>, bit<16>>(REG_SIZE) reg_five_t_sum_res_prod_hi;			// Sum of residual products

	// Register<bit<32>, bit<1>>(1) reg_five_t_mean_sqr_0;		// Squared mean for flow id (a->b)
	// Register<bit<32>, bit<1>>(1) reg_five_t_mean_sqr_1;		// Squared mean for flow id (b->a)
	// Register<bit<32>, bit<1>>(1) reg_five_t_variance_sqr_0;	// Squared variance for flow id (a->b)
	// Register<bit<32>, bit<1>>(1) reg_five_t_variance_sqr_1;	// Squared variance for flow id (b->a)
	// Register<bit<32>, bit<1>>(1) reg_five_t_std_dev_0;		// Std. deviation for flow id (a->b)
	// Register<bit<32>, bit<1>>(1) reg_five_t_std_dev_1;		// Std. deviation for flow id (b->a)
	// Register<bit<32>, bit<1>>(1) reg_five_t_magnitude; 		// Magnitude
	// Register<bit<32>, bit<1>>(1) reg_five_t_radius;			// Radius

	/* // Temporary variables for stats calculation. */
	bit<32> res_prod_lo_inv;
	bit<32> sum_res_prod_hi_carry;

	// Check if more than 100 ms have elapsed since the last update for the current flow.
	// If so, increase the stored value by 100 ms and set a flag.
	// 1525 corresponds to the bit-sliced value for 100 ms (in ns).
    RegisterAction<_, bit<16>, bit<32>>(reg_five_t_ts) ract_decay_check_100_ms = {
        void apply(inout bit<32> val, out bit<32> res) {
            res = 0;
            if (DECAY_100_MS < hdr.meta.curr_ts - val && val != 0) {
                val = val + DECAY_100_MS;
                res = 1;
            } else {
                val = hdr.meta.curr_ts;
            }
        }
    };

	// Check if more than 1 sec has elapsed since the last update for the current flow.
	// If so, increase the stored value by 1 sec and set a flag.
	// 15258 corresponds to the bit-sliced value for 1 sec (in ns).
    RegisterAction<_, bit<16>, bit<32>>(reg_five_t_ts) ract_decay_check_1_s = {
        void apply(inout bit<32> val, out bit<32> res) {
            res = 0;
            if (DECAY_1_S < hdr.meta.curr_ts - val && val != 0) {
                val = val + DECAY_1_S;
                res = 1;
            } else {
                val = hdr.meta.curr_ts;
            }
        }
    };

	// Check if more than 10 secs have elapsed since the last update for the current flow.
	// If so, increase the stored value by 10 secs and set a flag.
	// 152587 corresponds to the bit-sliced value for 10 secs (in ns).
    RegisterAction<_, bit<16>, bit<32>>(reg_five_t_ts) ract_decay_check_10_s = {
        void apply(inout bit<32> val, out bit<32> res) {
            res = 0;
            if (DECAY_10_S < hdr.meta.curr_ts - val && val != 0) {
                val = val + DECAY_10_S;
                res = 1;
            } else {
                val = hdr.meta.curr_ts;
            }
        }
    };

	// Check if more than 60 secs have elapsed since the last update for the current flow.
	// If so, increase the stored value by 60 secs and set a flag.
	// 915527 corresponds to the bit-sliced value for 60 secs (in ns).
    RegisterAction<_, bit<16>, bit<32>>(reg_five_t_ts) ract_decay_check_60_s = {
        void apply(inout bit<32> val, out bit<32> res) {
            res = 0;
            if (DECAY_60_S < hdr.meta.curr_ts - val && val != 0) {
                val = val + DECAY_60_S;
                res = 1;
            } else {
                val = hdr.meta.curr_ts;
            }
        }
    };

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_cnt;
	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_pkt_cnt_0) ract_pkt_cnt_0_incr = {
		void apply(inout bit<32> val, out bit<32> res) {
			if(eg_md.stats_five_t.decay_check == 0) {
				val = val + 1;
			} else {
				val = div_pkt_cnt.execute(val) + 1;
			}
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_len;
	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_pkt_len) ract_pkt_len_incr = {
		void apply(inout bit<32> val, out bit<32> res) {
			if (eg_md.stats_five_t.decay_check == 0) {
				val = val + (bit<32>)hdr.ipv4.len;
			} else {
				val = div_pkt_len.execute(val);
			}
			res = val;
		}
	};

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_ss;
    RegisterAction<_, bit<16>, bit<32>>(reg_five_t_ss_0) ract_ss_0_incr = {
        void apply(inout bit<32> val, out bit<32> res) {
            if (eg_md.stats_five_t.decay_check == 0) {
                val = val + hdr.meta.pkt_len_sqr;
            } else {
                val = div_ss.execute(val);
            }
            res = val;
        }
    };

	// Check if the current flow hash corresponds to the stored flow direction.
	// If not, then the stored value is from the reverse flow and must be updated.
	RegisterAction<_, bit<16>, bit<8>>(reg_five_t_flow_dir) ract_flow_dir = {
		void apply(inout bit<16> val, out bit<8> res) {
			res = 0;
			if (val != eg_md.stats_five_t.hash_0) {
				val = eg_md.stats_five_t.hash_0;
				res = 1;
			}
		}
	};

	// The stored values correspond to the current flow direction.
	// Update the current value and return the value for the other direction.
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_pkt_cnt) ract_pkt_cnt_1_read = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_1;
			cntr.cntr_0_old = hdr.peregrine.five_t_pkt_cnt;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old value as the reverse (cntr_1) and update the current (cntr_0).
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_pkt_cnt) ract_pkt_cnt_1_update = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_0_old;
			cntr.cntr_1 = cntr.cntr_0_old;
			cntr.cntr_0_old = hdr.peregrine.five_t_pkt_cnt;
		}
	};


	// The stored values correspond to the current flow direction.
	// Update the current value and return the value for the other direction.
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_ss) ract_ss_1_read = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_1;
			cntr.cntr_0_old = eg_md.stats_five_t.ss_0;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old value as the reverse (cntr_1) and update the current (cntr_0).
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_ss) ract_ss_1_update = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_0_old;
			cntr.cntr_1 = cntr.cntr_0_old;
			cntr.cntr_0_old = eg_md.stats_five_t.ss_0;
		}
	};

	// The stored values correspond to the current flow direction.
	// Update the current value and return the value for the other direction.
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_mean) ract_mean_1_read = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_1;
			cntr.cntr_0_old = hdr.peregrine.five_t_mean;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old value as the reverse (cntr_1) and update the current (cntr_0).
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_mean) ract_mean_1_update = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_0_old;
			cntr.cntr_1 = cntr.cntr_0_old;
			cntr.cntr_0_old = hdr.peregrine.five_t_mean;
		}
	};

	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_lo) ract_sum_res_prod_lo = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = val + eg_md.stats_five_t.res_prod[31:0];
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_lo;
	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_lo) ract_sum_res_prod_lo_decay = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = div_sum_res_prod_lo.execute(val);
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_lo_carry;
	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_lo_carry) ract_sum_res_prod_lo_carry_decay = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = div_sum_res_prod_lo_carry.execute(val);
			res = val;
		}
	};

	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_lo_carry) ract_sum_res_prod_lo_carry = {
		void apply(inout bit<32> val, out bit<32> res) {
			if (res_prod_lo_inv < val) {
				res = 1;
			} else {
				res = 0;
			}
			val = val + eg_md.stats_five_t.res_prod[31:0];
		}
	};

	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_hi) ract_sum_res_prod_hi = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = val + sum_res_prod_hi_carry;
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_hi;
	RegisterAction<_, bit<16>, bit<32>>(reg_five_t_sum_res_prod_hi) ract_sum_res_prod_hi_decay = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = div_sum_res_prod_hi.execute(val);
			res = val;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old value as the reverse (cntr_1) and update the current (cntr_0).
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_res) ract_res_1_read = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_1;
			cntr.cntr_0_old = eg_md.stats_five_t.res_0;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old value as the reverse (cntr_1) and update the current (cntr_0).
	RegisterAction<cntr_cur, bit<16>, bit<32>>(reg_five_t_res) ract_res_1_update = {
		void apply(inout cntr_cur cntr, out bit<32> res) {
			res = cntr.cntr_0_old;
			cntr.cntr_1 = cntr.cntr_0_old;
			cntr.cntr_0_old = eg_md.stats_five_t.res_0;
		}
	};

	/*
	MathUnit<bit<32>>(MathOp_t.SQR, 1) mean_sqr_0;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_mean_sqr_0) ract_mean_sqr_0_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = mean_sqr_0.execute(hdr.peregrine.five_t_mean);
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQR, 1) mean_sqr_1;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_mean_sqr_1) ract_mean_sqr_1_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = mean_sqr_1.execute(eg_md.stats_five_t.mean_1);
			res = val;
		}
	};
	*/

	/*
	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_std_dev_0;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_std_dev_0) ract_std_dev_0_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = sqrt_std_dev_0.execute(eg_md.stats_five_t.variance_0);
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_std_dev_1;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_std_dev_1) ract_std_dev_1_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = sqrt_std_dev_1.execute(eg_md.stats_five_t.variance_1);
			res = val;
		}
	};
	*/

	/*
	MathUnit<bit<32>>(MathOp_t.SQR, 1) variance_sqr_0;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_variance_sqr_0) ract_variance_sqr_0_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = variance_sqr_0.execute(eg_md.stats_five_t.variance_0);
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQR, 1) variance_sqr_1;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_variance_sqr_1) ract_variance_sqr_1_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = variance_sqr_1.execute(eg_md.stats_five_t.variance_1);
			res = val;
		}
	};
	*/

	/*
	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_magnitude;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_magnitude) ract_magnitude_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = sqrt_magnitude.execute(eg_md.stats_five_t.mean_sqr_0);
			res = val;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_radius;
	RegisterAction<_, bit<1>, bit<32>>(reg_five_t_radius) ract_radius_calc = {
		void apply(inout bit<32> val, out bit<32> res) {
			val = sqrt_radius.execute(eg_md.stats_five_t.variance_sqr_0);
			res = val;
		}
	};
	*/

	action hash_calc_five_t_0() {
		eg_md.stats_five_t.hash_0 = (bit<16>)hash_five_t_0.get({hdr.ipv4.src_addr,
														  hdr.ipv4.dst_addr,
														  hdr.ipv4.protocol,
														  hdr.meta.l4_src_port,
														  hdr.meta.l4_dst_port})[12:0];
	}

	action hash_calc_five_t_1() {
		eg_md.stats_five_t.hash_1 = (bit<16>)hash_five_t_1.get({hdr.ipv4.dst_addr,
														  hdr.ipv4.src_addr,
														  hdr.ipv4.protocol,
														  hdr.meta.l4_dst_port,
														  hdr.meta.l4_src_port})[12:0];
	}

	action hash_calc_five_t_xor() {
		eg_md.stats_five_t.hash_xor = (eg_md.stats_five_t.hash_0 ^ eg_md.stats_five_t.hash_1);
	}

	action hash_calc_five_t_decay() {
		eg_md.stats_five_t.hash_0 = eg_md.stats_five_t.hash_0 + hdr.meta.decay_cntr;
		eg_md.stats_five_t.hash_1 = eg_md.stats_five_t.hash_1 + hdr.meta.decay_cntr;
		eg_md.stats_five_t.hash_xor = eg_md.stats_five_t.hash_xor + hdr.meta.decay_cntr;
	}

    action decay_check_100_ms() {
        eg_md.stats_five_t.decay_check = ract_decay_check_100_ms.execute(eg_md.stats_five_t.hash_0);
    }

    action decay_check_1_s() {
        eg_md.stats_five_t.decay_check = ract_decay_check_1_s.execute(eg_md.stats_five_t.hash_0);
    }

    action decay_check_10_s() {
        eg_md.stats_five_t.decay_check = ract_decay_check_10_s.execute(eg_md.stats_five_t.hash_0);
    }

    action decay_check_60_s() {
        eg_md.stats_five_t.decay_check = ract_decay_check_60_s.execute(eg_md.stats_five_t.hash_0);
    }

	action flow_dir() {
		eg_md.stats_five_t.flow_dir = ract_flow_dir.execute(eg_md.stats_five_t.hash_xor);
	}

	action pkt_cnt_0_incr() {
		hdr.peregrine.five_t_pkt_cnt = ract_pkt_cnt_0_incr.execute(eg_md.stats_five_t.hash_0);
	}

	action pkt_cnt_1_read() {
		eg_md.stats_five_t.pkt_cnt_1 = ract_pkt_cnt_1_read.execute(eg_md.stats_five_t.hash_xor);
	}

	action pkt_cnt_1_update() {
		eg_md.stats_five_t.pkt_cnt_1 = ract_pkt_cnt_1_update.execute(eg_md.stats_five_t.hash_xor);
	}

	action pkt_len_incr() {
		eg_md.stats_five_t.pkt_len = ract_pkt_len_incr.execute(eg_md.stats_five_t.hash_0);
	}

	action ss_0_incr() {
		eg_md.stats_five_t.ss_0 = ract_ss_0_incr.execute(eg_md.stats_five_t.hash_0);
	}

	action ss_1_read() {
		eg_md.stats_five_t.ss_1 = ract_ss_1_read.execute(eg_md.stats_five_t.hash_xor);
	}

	action ss_1_update() {
		eg_md.stats_five_t.ss_1 = ract_ss_1_update.execute(eg_md.stats_five_t.hash_xor);
	}

	action mean_1_read() {
		eg_md.stats_five_t.mean_1 = ract_mean_1_read.execute(eg_md.stats_five_t.hash_xor);
	}

	action mean_1_update() {
		eg_md.stats_five_t.mean_1 = ract_mean_1_update.execute(eg_md.stats_five_t.hash_xor);
	}

	action res_0_calc() {
		eg_md.stats_five_t.res_0 = eg_md.stats_five_t.pkt_len - hdr.peregrine.five_t_mean;
	}

	action res_1_read() {
		eg_md.stats_five_t.res_1 = ract_res_1_read.execute(eg_md.stats_five_t.hash_xor);
	}

	action res_1_update() {
		eg_md.stats_five_t.res_1 = ract_res_1_update.execute(eg_md.stats_five_t.hash_xor);
	}

	action sum_res_prod_lo_decay_0() {
		eg_md.stats_five_t.sum_res_prod[31:0] = ract_sum_res_prod_lo.execute(eg_md.stats_five_t.hash_xor);
	}

	action sum_res_prod_lo_decay_1() {
		eg_md.stats_five_t.sum_res_prod[31:0] = ract_sum_res_prod_lo_decay.execute(eg_md.stats_five_t.hash_xor);
	}

	action res_prod_lo_inv_calc() {
		res_prod_lo_inv = ~eg_md.stats_five_t.res_prod[31:0];
	}

	action sum_res_prod_get_carry_decay_0() {
		sum_res_prod_hi_carry = eg_md.stats_five_t.res_prod[63:32] + ract_sum_res_prod_lo_carry.execute(eg_md.stats_five_t.hash_xor);
	}

	action sum_res_prod_get_carry_decay_1() {
		sum_res_prod_hi_carry = eg_md.stats_five_t.res_prod[63:32] + ract_sum_res_prod_lo_carry_decay.execute(eg_md.stats_five_t.hash_xor);
	}

	action sum_res_prod_hi_decay_0() {
		eg_md.stats_five_t.sum_res_prod[63:32] = ract_sum_res_prod_hi.execute(eg_md.stats_five_t.hash_xor);
	}

	action sum_res_prod_hi_decay_1() {
		eg_md.stats_five_t.sum_res_prod[63:32] = ract_sum_res_prod_hi_decay.execute(eg_md.stats_five_t.hash_xor);
	}

	action rshift_mean_0() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len;
	}

	action rshift_mean_1() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 1;
	}

	action rshift_mean_2() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 2;
	}

	action rshift_mean_3() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 3;
	}

	action rshift_mean_4() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 4;
	}

	action rshift_mean_5() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 5;
	}

	action rshift_mean_6() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 6;
	}

	action rshift_mean_7() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 7;
	}

	action rshift_mean_8() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 8;
	}

	action rshift_mean_9() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 9;
	}

	action rshift_mean_10() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 10;
	}

	action rshift_mean_11() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 11;
	}

	action rshift_mean_12() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 12;
	}

	action rshift_mean_13() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 13;
	}

	action rshift_mean_14() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 14;
	}

	action rshift_mean_15() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 15;
	}

	action rshift_mean_16() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 16;
	}

	action rshift_mean_17() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 17;
	}

	action rshift_mean_18() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 18;
	}

	action rshift_mean_19() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 19;
	}

	action rshift_mean_20() {
		hdr.peregrine.five_t_mean = eg_md.stats_five_t.pkt_len >> 20;
	}

	action lshift_res_prod_0() {
		eg_md.stats_five_t.res_prod = (bit<64>)eg_md.stats_five_t.res_0;
	}

	action lshift_res_prod_1() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 1);
	}

	action lshift_res_prod_2() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 2);
	}

	action lshift_res_prod_3() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 3);
	}

	action lshift_res_prod_4() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 4);
	}

	action lshift_res_prod_5() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 5);
	}

	action lshift_res_prod_6() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 6);
	}

	action lshift_res_prod_7() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 7);
	}

	action lshift_res_prod_8() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 8);
	}

	action lshift_res_prod_9() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 9);
	}

	action lshift_res_prod_10() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 10);
	}

	action lshift_res_prod_11() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 11);
	}

	action lshift_res_prod_12() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 12);
	}

	action lshift_res_prod_13() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 13);
	}

	action lshift_res_prod_14() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 14);
	}

	action lshift_res_prod_15() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 15);
	}

	action lshift_res_prod_16() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 16);
	}

	action lshift_res_prod_17() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 17);
	}

	action lshift_res_prod_18() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 18);
	}

	action lshift_res_prod_19() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 19);
	}

	action lshift_res_prod_20() {
		eg_md.stats_five_t.res_prod = (bit<64>)(eg_md.stats_five_t.res_0 << 20);
	}

	/*
	action mean_sqr_0_calc() {
		eg_md.stats_five_t.mean_sqr_0 = ract_mean_sqr_0_calc.execute(0);
	}

	action mean_sqr_1_calc() {
		eg_md.stats_five_t.mean_sqr_1 = ract_mean_sqr_1_calc.execute(0);
	}
	*/

	action mean_sqr_sum() {
		eg_md.stats_five_t.mean_sqr_sum = eg_md.stats_five_t.mean_sqr_0 + eg_md.stats_five_t.mean_sqr_1;
	}

	action variance_0_calc() {
		eg_md.stats_five_t.variance_0 = eg_md.stats_five_t.mean_sqr_0 - eg_md.stats_five_t.mean_ss_0;
		eg_md.stats_five_t.variance_0_neg = eg_md.stats_five_t.mean_ss_0 - eg_md.stats_five_t.mean_sqr_0;
	}

	action variance_1_calc() {
		eg_md.stats_five_t.variance_1 = eg_md.stats_five_t.mean_sqr_1 - eg_md.stats_five_t.mean_ss_1;
		eg_md.stats_five_t.variance_1_neg = eg_md.stats_five_t.mean_ss_1 - eg_md.stats_five_t.mean_sqr_1;
	}

	action variance_abs() {
        eg_md.stats_five_t.variance_0 = min(eg_md.stats_five_t.variance_0, eg_md.stats_five_t.variance_0_neg);
        eg_md.stats_five_t.variance_1 = min(eg_md.stats_five_t.variance_1, eg_md.stats_five_t.variance_1_neg);
	}

	action rshift_mean_ss_0_0() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0;
	}

	action rshift_mean_ss_0_1() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 1;
	}

	action rshift_mean_ss_0_2() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 2;
	}

	action rshift_mean_ss_0_3() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 3;
	}

	action rshift_mean_ss_0_4() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 4;
	}

	action rshift_mean_ss_0_5() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 5;
	}

	action rshift_mean_ss_0_6() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 6;
	}

	action rshift_mean_ss_0_7() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 7;
	}

	action rshift_mean_ss_0_8() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 8;
	}

	action rshift_mean_ss_0_9() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 9;
	}

	action rshift_mean_ss_0_10() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 10;
	}

	action rshift_mean_ss_0_11() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 11;
	}

	action rshift_mean_ss_0_12() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 12;
	}

	action rshift_mean_ss_0_13() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 13;
	}

	action rshift_mean_ss_0_14() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 14;
	}

	action rshift_mean_ss_0_15() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 15;
	}

	action rshift_mean_ss_0_16() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 16;
	}

	action rshift_mean_ss_0_17() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 17;
	}

	action rshift_mean_ss_0_18() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 18;
	}

	action rshift_mean_ss_0_19() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 19;
	}

	action rshift_mean_ss_0_20() {
		eg_md.stats_five_t.mean_ss_0 = eg_md.stats_five_t.ss_0 >> 20;
	}

	action rshift_mean_ss_1_0() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1;
	}

	action rshift_mean_ss_1_1() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 1;
	}

	action rshift_mean_ss_1_2() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 2;
	}

	action rshift_mean_ss_1_3() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 3;
	}

	action rshift_mean_ss_1_4() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 4;
	}

	action rshift_mean_ss_1_5() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 5;
	}

	action rshift_mean_ss_1_6() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 6;
	}

	action rshift_mean_ss_1_7() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 7;
	}

	action rshift_mean_ss_1_8() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 8;
	}

	action rshift_mean_ss_1_9() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 9;
	}

	action rshift_mean_ss_1_10() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 10;
	}

	action rshift_mean_ss_1_11() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 11;
	}

	action rshift_mean_ss_1_12() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 12;
	}

	action rshift_mean_ss_1_13() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 13;
	}

	action rshift_mean_ss_1_14() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 14;
	}

	action rshift_mean_ss_1_15() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 15;
	}

	action rshift_mean_ss_1_16() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 16;
	}

	action rshift_mean_ss_1_17() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 17;
	}

	action rshift_mean_ss_1_18() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 18;
	}

	action rshift_mean_ss_1_19() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 19;
	}

	action rshift_mean_ss_1_20() {
		eg_md.stats_five_t.mean_ss_1 = eg_md.stats_five_t.ss_1 >> 20;
	}

	/*
	action std_dev_0_calc() {
		hdr.peregrine.five_t_std_dev = ract_std_dev_0_calc.execute(0);
	}

	action std_dev_1_calc() {
		eg_md.stats_five_t.std_dev_1 = ract_std_dev_1_calc.execute(0);
	}
	*/

	/*
	action magnitude_calc() {
		hdr.peregrine.five_t_magnitude = ract_magnitude_calc.execute(0);
	}
	*/

	/*
	action variance_sqr_0_calc() {
		eg_md.stats_five_t.variance_sqr_0 = ract_variance_sqr_0_calc.execute(0);
	}

	action variance_sqr_1_calc() {
		eg_md.stats_five_t.variance_sqr_1 = ract_variance_sqr_1_calc.execute(0);
	}
	*/

	action variance_sqr_sum() {
		eg_md.stats_five_t.variance_sqr_0 = eg_md.stats_five_t.variance_sqr_0 + eg_md.stats_five_t.variance_sqr_1;
	}

	/*
	action radius_calc() {
		hdr.peregrine.five_t_radius = ract_radius_calc.execute(0);
	}
	*/

	action pkt_cnt_sum() {
		eg_md.stats_five_t.pkt_cnt_1 = eg_md.stats_five_t.pkt_cnt_1 + hdr.peregrine.five_t_pkt_cnt;
	}

	action rshift_cov_0() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod;
	}

	action rshift_cov_1() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 1;
	}

	action rshift_cov_2() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 2;
	}

	action rshift_cov_3() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 3;
	}

	action rshift_cov_4() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 4;
	}

	action rshift_cov_5() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 5;
	}

	action rshift_cov_6() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 6;
	}

	action rshift_cov_7() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 7;
	}

	action rshift_cov_8() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 8;
	}

	action rshift_cov_9() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 9;
	}

	action rshift_cov_10() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 10;
	}

	action rshift_cov_11() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 11;
	}

	action rshift_cov_12() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 12;
	}

	action rshift_cov_13() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 13;
	}

	action rshift_cov_14() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 14;
	}

	action rshift_cov_15() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 15;
	}

	action rshift_cov_16() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 16;
	}

	action rshift_cov_17() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 17;
	}

	action rshift_cov_18() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 18;
	}

	action rshift_cov_19() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 19;
	}

	action rshift_cov_20() {
		hdr.peregrine.five_t_cov = eg_md.stats_five_t.sum_res_prod >> 20;
	}

	action lshift_std_dev_prod_0() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev;
	}

	action lshift_std_dev_prod_1() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 1;
	}

	action lshift_std_dev_prod_2() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 2;
	}

	action lshift_std_dev_prod_3() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 3;
	}

	action lshift_std_dev_prod_4() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 4;
	}

	action lshift_std_dev_prod_5() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 5;
	}

	action lshift_std_dev_prod_6() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 6;
	}

	action lshift_std_dev_prod_7() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 7;
	}

	action lshift_std_dev_prod_8() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 8;
	}

	action lshift_std_dev_prod_9() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 9;
	}

	action lshift_std_dev_prod_10() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 10;
	}

	action lshift_std_dev_prod_11() {
		eg_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev << 11;
	}

	action rshift_pcc_0() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov;
	}

	action rshift_pcc_1() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 1;
	}

	action rshift_pcc_2() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 2;
	}

	action rshift_pcc_3() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 3;
	}

	action rshift_pcc_4() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 4;
	}

	action rshift_pcc_5() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 5;
	}

	action rshift_pcc_6() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 6;
	}

	action rshift_pcc_7() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 7;
	}

	action rshift_pcc_8() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 8;
	}

	action rshift_pcc_9() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 9;
	}

	action rshift_pcc_10() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 10;
	}

	action rshift_pcc_11() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 11;
	}

	action rshift_pcc_12() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 12;
	}

	action rshift_pcc_13() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 13;
	}

	action rshift_pcc_14() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 14;
	}

	action rshift_pcc_15() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 15;
	}

	action rshift_pcc_16() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 16;
	}

	action rshift_pcc_17() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 17;
	}

	action rshift_pcc_18() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 18;
	}

	action rshift_pcc_19() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 19;
	}

	action rshift_pcc_20() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 20;
	}

	action rshift_pcc_21() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 21;
	}

	action rshift_pcc_22() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 22;
	}

	action rshift_pcc_23() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 23;
	}

	action rshift_pcc_24() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 24;
	}

	action rshift_pcc_25() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 25;
	}

	action rshift_pcc_26() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 26;
	}

	action rshift_pcc_27() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 27;
	}

	action rshift_pcc_28() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 28;
	}

	action rshift_pcc_29() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 29;
	}

	action rshift_pcc_30() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 30;
	}

	action rshift_pcc_31() {
		hdr.peregrine.five_t_pcc = hdr.peregrine.five_t_cov >> 31;
	}

	action miss() {}

    table decay_check {
        key = {
            hdr.meta.decay_cntr : exact;
        }
        actions = {
            decay_check_100_ms;
            decay_check_1_s;
            decay_check_10_s;
            decay_check_60_s;
            miss;
        }
        const default_action = miss;
        size = 4;
        const entries = {
            (0)     : decay_check_100_ms;
            (8192)  : decay_check_1_s;
            (16384) : decay_check_10_s;
            (24576) : decay_check_60_s;
        }
    }

	table mean_0 {
		key = {
			hdr.peregrine.five_t_pkt_cnt : ternary;
		}
		actions = {
			rshift_mean_0;
			rshift_mean_1;
			rshift_mean_2;
			rshift_mean_3;
			rshift_mean_4;
			rshift_mean_5;
			rshift_mean_6;
			rshift_mean_7;
			rshift_mean_8;
			rshift_mean_9;
			rshift_mean_10;
			rshift_mean_11;
			rshift_mean_12;
			rshift_mean_13;
			rshift_mean_14;
			rshift_mean_15;
			rshift_mean_16;
			rshift_mean_17;
			rshift_mean_18;
			rshift_mean_19;
			rshift_mean_20;
			miss;
		}
		const default_action = miss;
		size = 21;
        const entries = {
            (1048576 &&& 0xfff00000)    : rshift_mean_20;
            (524288 &&& 0xfff80000)     : rshift_mean_19;
            (262144 &&& 0xfffc0000)     : rshift_mean_18;
            (131072 &&& 0xfffe0000)     : rshift_mean_17;
            (65536 &&& 0xffff0000)      : rshift_mean_16;
            (32768 &&& 0xffff8000)      : rshift_mean_15;
            (16384 &&& 0xffffc000)      : rshift_mean_14;
            (8192 &&& 0xffffe000)       : rshift_mean_13;
            (4096 &&& 0xfffff000)       : rshift_mean_12;
            (2048 &&& 0xfffff800)       : rshift_mean_11;
            (1024 &&& 0xfffffc00)       : rshift_mean_10;
            (512 &&& 0xfffffe00)        : rshift_mean_9;
            (256 &&& 0xffffff00)        : rshift_mean_8;
            (128 &&& 0xffffff80)        : rshift_mean_7;
            (64 &&& 0xffffffc0)         : rshift_mean_6;
            (32 &&& 0xffffffe0)         : rshift_mean_5;
            (16 &&& 0xfffffff0)         : rshift_mean_4;
            (8 &&& 0xfffffff8)          : rshift_mean_3;
            (4 &&& 0xfffffffc)          : rshift_mean_2;
            (2 &&& 0xfffffffe)          : rshift_mean_1;
            (1 &&& 0xffffffff)          : rshift_mean_0;
        }
	}

	table pkt_cnt_update {
		key = {
			eg_md.stats_five_t.flow_dir : exact;
		}
		actions = {
			pkt_cnt_1_read;
			pkt_cnt_1_update;
		}
		size = 2;
        const entries = {
            (0) : pkt_cnt_1_read;
            (1)	: pkt_cnt_1_update;
        }
	}

	table ss_update {
		key = {
			eg_md.stats_five_t.flow_dir: exact;
		}
		actions = {
			ss_1_read;
			ss_1_update;
		}
		size = 2;
        const entries = {
            (0) : ss_1_read;
            (1)	: ss_1_update;
        }
	}

	table mean_update {
		key = {
			eg_md.stats_five_t.flow_dir: exact;
		}
		actions = {
			mean_1_read;
			mean_1_update;
		}
		size = 2;
        const entries = {
            (0) : mean_1_read;
            (1)	: mean_1_update;
        }
	}

	table res_update {
		key = {
			eg_md.stats_five_t.flow_dir : exact;
		}
		actions = {
			res_1_read;
			res_1_update;
		}
		size = 2;
        const entries = {
            (0) : res_1_read;
            (1)	: res_1_update;
        }
	}

	table res_prod {
		key = {
			eg_md.stats_five_t.res_1 : ternary;
		}
		actions = {
			lshift_res_prod_0;
			lshift_res_prod_1;
			lshift_res_prod_2;
			lshift_res_prod_3;
			lshift_res_prod_4;
			lshift_res_prod_5;
			lshift_res_prod_6;
			lshift_res_prod_7;
			lshift_res_prod_8;
			lshift_res_prod_9;
			lshift_res_prod_10;
			lshift_res_prod_11;
			lshift_res_prod_12;
			lshift_res_prod_13;
			lshift_res_prod_14;
			lshift_res_prod_15;
			lshift_res_prod_16;
			lshift_res_prod_17;
			lshift_res_prod_18;
			lshift_res_prod_19;
			lshift_res_prod_20;
			miss;
		}
		const default_action = miss;
		size = 21;
        const entries = {
            (1048576 &&& 0xfff00000)    : lshift_res_prod_20;
            (524288 &&& 0xfff80000)     : lshift_res_prod_19;
            (262144 &&& 0xfffc0000)     : lshift_res_prod_18;
            (131072 &&& 0xfffe0000)     : lshift_res_prod_17;
            (65536 &&& 0xffff0000)      : lshift_res_prod_16;
            (32768 &&& 0xffff8000)      : lshift_res_prod_15;
            (16384 &&& 0xffffc000)      : lshift_res_prod_14;
            (8192 &&& 0xffffe000)       : lshift_res_prod_13;
            (4096 &&& 0xfffff000)       : lshift_res_prod_12;
            (2048 &&& 0xfffff800)       : lshift_res_prod_11;
            (1024 &&& 0xfffffc00)       : lshift_res_prod_10;
            (512 &&& 0xfffffe00)        : lshift_res_prod_9;
            (256 &&& 0xffffff00)        : lshift_res_prod_8;
            (128 &&& 0xffffff80)        : lshift_res_prod_7;
            (64 &&& 0xffffffc0)         : lshift_res_prod_6;
            (32 &&& 0xffffffe0)         : lshift_res_prod_5;
            (16 &&& 0xfffffff0)         : lshift_res_prod_4;
            (8 &&& 0xfffffff8)          : lshift_res_prod_3;
            (4 &&& 0xfffffffc)          : lshift_res_prod_2;
            (2 &&& 0xfffffffe)          : lshift_res_prod_1;
            (1 &&& 0xffffffff)          : lshift_res_prod_0;
        }
	}

	table sum_res_prod_lo {
		key = {
			eg_md.stats_five_t.decay_check : exact;
		}
		actions = {
			sum_res_prod_lo_decay_0;
			sum_res_prod_lo_decay_1;
		}
		size = 2;
        const entries = {
            (0) : sum_res_prod_lo_decay_0;
            (1)	: sum_res_prod_lo_decay_1;
        }
	}

	table sum_res_prod_get_carry {
		key = {
			eg_md.stats_five_t.decay_check : exact;
		}
		actions = {
			sum_res_prod_get_carry_decay_0;
			sum_res_prod_get_carry_decay_1;
		}
		size = 2;
        const entries = {
            (0) : sum_res_prod_get_carry_decay_0;
            (1)	: sum_res_prod_get_carry_decay_1;
        }
	}

	table sum_res_prod_hi {
		key = {
			eg_md.stats_five_t.decay_check : exact;
		}
		actions = {
			sum_res_prod_hi_decay_0;
			sum_res_prod_hi_decay_1;
		}
		size = 2;
        const entries = {
            (0) : sum_res_prod_hi_decay_0;
            (1)	: sum_res_prod_hi_decay_1;
        }
	}

	table mean_ss_0 {
		key = {
			hdr.peregrine.five_t_pkt_cnt: ternary;
		}
		actions = {
			rshift_mean_ss_0_0;
			rshift_mean_ss_0_1;
			rshift_mean_ss_0_2;
			rshift_mean_ss_0_3;
			rshift_mean_ss_0_4;
			rshift_mean_ss_0_5;
			rshift_mean_ss_0_6;
			rshift_mean_ss_0_7;
			rshift_mean_ss_0_8;
			rshift_mean_ss_0_9;
			rshift_mean_ss_0_10;
			rshift_mean_ss_0_11;
			rshift_mean_ss_0_12;
			rshift_mean_ss_0_13;
			rshift_mean_ss_0_14;
			rshift_mean_ss_0_15;
			rshift_mean_ss_0_16;
			rshift_mean_ss_0_17;
			rshift_mean_ss_0_18;
			rshift_mean_ss_0_19;
			rshift_mean_ss_0_20;
			miss;
		}
		const default_action = miss;
		size = 21;
        const entries = {
            (1048576 &&& 0xfff00000)    : rshift_mean_ss_0_20;
            (524288 &&& 0xfff80000)     : rshift_mean_ss_0_19;
            (262144 &&& 0xfffc0000)     : rshift_mean_ss_0_18;
            (131072 &&& 0xfffe0000)     : rshift_mean_ss_0_17;
            (65536 &&& 0xffff0000)      : rshift_mean_ss_0_16;
            (32768 &&& 0xffff8000)      : rshift_mean_ss_0_15;
            (16384 &&& 0xffffc000)      : rshift_mean_ss_0_14;
            (8192 &&& 0xffffe000)       : rshift_mean_ss_0_13;
            (4096 &&& 0xfffff000)       : rshift_mean_ss_0_12;
            (2048 &&& 0xfffff800)       : rshift_mean_ss_0_11;
            (1024 &&& 0xfffffc00)       : rshift_mean_ss_0_10;
            (512 &&& 0xfffffe00)        : rshift_mean_ss_0_9;
            (256 &&& 0xffffff00)        : rshift_mean_ss_0_8;
            (128 &&& 0xffffff80)        : rshift_mean_ss_0_7;
            (64 &&& 0xffffffc0)         : rshift_mean_ss_0_6;
            (32 &&& 0xffffffe0)         : rshift_mean_ss_0_5;
            (16 &&& 0xfffffff0)         : rshift_mean_ss_0_4;
            (8 &&& 0xfffffff8)          : rshift_mean_ss_0_3;
            (4 &&& 0xfffffffc)          : rshift_mean_ss_0_2;
            (2 &&& 0xfffffffe)          : rshift_mean_ss_0_1;
            (1 &&& 0xffffffff)          : rshift_mean_ss_0_0;
        }
	}

	table mean_ss_1 {
		key = {
			eg_md.stats_five_t.pkt_cnt_1: ternary;
		}
		actions = {
			rshift_mean_ss_1_0;
			rshift_mean_ss_1_1;
			rshift_mean_ss_1_2;
			rshift_mean_ss_1_3;
			rshift_mean_ss_1_4;
			rshift_mean_ss_1_5;
			rshift_mean_ss_1_6;
			rshift_mean_ss_1_7;
			rshift_mean_ss_1_8;
			rshift_mean_ss_1_9;
			rshift_mean_ss_1_10;
			rshift_mean_ss_1_11;
			rshift_mean_ss_1_12;
			rshift_mean_ss_1_13;
			rshift_mean_ss_1_14;
			rshift_mean_ss_1_15;
			rshift_mean_ss_1_16;
			rshift_mean_ss_1_17;
			rshift_mean_ss_1_18;
			rshift_mean_ss_1_19;
			rshift_mean_ss_1_20;
			miss;
		}
		const default_action = miss;
		size = 21;
        const entries = {
            (1048576 &&& 0xfff00000)    : rshift_mean_ss_1_20;
            (524288 &&& 0xfff80000)     : rshift_mean_ss_1_19;
            (262144 &&& 0xfffc0000)     : rshift_mean_ss_1_18;
            (131072 &&& 0xfffe0000)     : rshift_mean_ss_1_17;
            (65536 &&& 0xffff0000)      : rshift_mean_ss_1_16;
            (32768 &&& 0xffff8000)      : rshift_mean_ss_1_15;
            (16384 &&& 0xffffc000)      : rshift_mean_ss_1_14;
            (8192 &&& 0xffffe000)       : rshift_mean_ss_1_13;
            (4096 &&& 0xfffff000)       : rshift_mean_ss_1_12;
            (2048 &&& 0xfffff800)       : rshift_mean_ss_1_11;
            (1024 &&& 0xfffffc00)       : rshift_mean_ss_1_10;
            (512 &&& 0xfffffe00)        : rshift_mean_ss_1_9;
            (256 &&& 0xffffff00)        : rshift_mean_ss_1_8;
            (128 &&& 0xffffff80)        : rshift_mean_ss_1_7;
            (64 &&& 0xffffffc0)         : rshift_mean_ss_1_6;
            (32 &&& 0xffffffe0)         : rshift_mean_ss_1_5;
            (16 &&& 0xfffffff0)         : rshift_mean_ss_1_4;
            (8 &&& 0xfffffff8)          : rshift_mean_ss_1_3;
            (4 &&& 0xfffffffc)          : rshift_mean_ss_1_2;
            (2 &&& 0xfffffffe)          : rshift_mean_ss_1_1;
            (1 &&& 0xffffffff)          : rshift_mean_ss_1_0;
        }
	}

	table cov {
		key = {
			eg_md.stats_five_t.pkt_cnt_1 : ternary;
		}
		actions = {
			rshift_cov_0;
			rshift_cov_1;
			rshift_cov_2;
			rshift_cov_3;
			rshift_cov_4;
			rshift_cov_5;
			rshift_cov_6;
			rshift_cov_7;
			rshift_cov_8;
			rshift_cov_9;
			rshift_cov_10;
			rshift_cov_11;
			rshift_cov_12;
			rshift_cov_13;
			rshift_cov_14;
			rshift_cov_15;
			rshift_cov_16;
			rshift_cov_17;
			rshift_cov_18;
			rshift_cov_19;
			rshift_cov_20;
			miss;
		}
		const default_action = miss;
		size = 21;
        const entries = {
            (1048576 &&& 0xfff00000)    : rshift_cov_20;
            (524288 &&& 0xfff80000)     : rshift_cov_19;
            (262144 &&& 0xfffc0000)     : rshift_cov_18;
            (131072 &&& 0xfffe0000)     : rshift_cov_17;
            (65536 &&& 0xffff0000)      : rshift_cov_16;
            (32768 &&& 0xffff8000)      : rshift_cov_15;
            (16384 &&& 0xffffc000)      : rshift_cov_14;
            (8192 &&& 0xffffe000)       : rshift_cov_13;
            (4096 &&& 0xfffff000)       : rshift_cov_12;
            (2048 &&& 0xfffff800)       : rshift_cov_11;
            (1024 &&& 0xfffffc00)       : rshift_cov_10;
            (512 &&& 0xfffffe00)        : rshift_cov_9;
            (256 &&& 0xffffff00)        : rshift_cov_8;
            (128 &&& 0xffffff80)        : rshift_cov_7;
            (64 &&& 0xffffffc0)         : rshift_cov_6;
            (32 &&& 0xffffffe0)         : rshift_cov_5;
            (16 &&& 0xfffffff0)         : rshift_cov_4;
            (8 &&& 0xfffffff8)          : rshift_cov_3;
            (4 &&& 0xfffffffc)          : rshift_cov_2;
            (2 &&& 0xfffffffe)          : rshift_cov_1;
            (1 &&& 0xffffffff)          : rshift_cov_0;
        }
	}

	table std_dev_prod {
		key = {
			eg_md.stats_five_t.std_dev_1 : ternary;
		}
		actions = {
			lshift_std_dev_prod_0;
			lshift_std_dev_prod_1;
			lshift_std_dev_prod_2;
			lshift_std_dev_prod_3;
			lshift_std_dev_prod_4;
			lshift_std_dev_prod_5;
			lshift_std_dev_prod_6;
			lshift_std_dev_prod_7;
			lshift_std_dev_prod_8;
			lshift_std_dev_prod_9;
			lshift_std_dev_prod_10;
			lshift_std_dev_prod_11;
			miss;
		}
		const default_action = miss;
		size = 12;
        const entries = {
            (2048 &&& 0xfffff800)       : lshift_std_dev_prod_11;
            (1024 &&& 0xfffffc00)       : lshift_std_dev_prod_10;
            (512 &&& 0xfffffe00)        : lshift_std_dev_prod_9;
            (256 &&& 0xffffff00)        : lshift_std_dev_prod_8;
            (128 &&& 0xffffff80)        : lshift_std_dev_prod_7;
            (64 &&& 0xffffffc0)         : lshift_std_dev_prod_6;
            (32 &&& 0xffffffe0)         : lshift_std_dev_prod_5;
            (16 &&& 0xfffffff0)         : lshift_std_dev_prod_4;
            (8 &&& 0xfffffff8)          : lshift_std_dev_prod_3;
            (4 &&& 0xfffffffc)          : lshift_std_dev_prod_2;
            (2 &&& 0xfffffffe)          : lshift_std_dev_prod_1;
            (1 &&& 0xffffffff)          : lshift_std_dev_prod_0;
        }
	}

	table pcc {
		key = {
			eg_md.stats_five_t.std_dev_prod : ternary;
		}
		actions = {
			rshift_pcc_0;
			rshift_pcc_1;
			rshift_pcc_2;
			rshift_pcc_3;
			rshift_pcc_4;
			rshift_pcc_5;
			rshift_pcc_6;
			rshift_pcc_7;
			rshift_pcc_8;
			rshift_pcc_9;
			rshift_pcc_10;
			rshift_pcc_11;
			rshift_pcc_12;
			rshift_pcc_13;
			rshift_pcc_14;
			rshift_pcc_15;
			rshift_pcc_16;
			rshift_pcc_17;
			rshift_pcc_18;
			rshift_pcc_19;
			rshift_pcc_20;
			rshift_pcc_21;
			rshift_pcc_22;
			rshift_pcc_23;
			rshift_pcc_24;
			rshift_pcc_25;
			rshift_pcc_26;
			rshift_pcc_27;
			rshift_pcc_28;
			rshift_pcc_29;
			rshift_pcc_30;
			rshift_pcc_31;
			miss;
		}
		const default_action = miss;
		size = 32;
        const entries = {
            (2147483648 &&& 0x80000000)    : rshift_pcc_31;
            (1073741824 &&& 0xc0000000)    : rshift_pcc_30;
            (536870912 &&& 0xe0000000)    : rshift_pcc_29;
            (268435456 &&& 0xf0000000)    : rshift_pcc_28;
            (134217728 &&& 0xf8000000)    : rshift_pcc_27;
            (67108864 &&& 0xfc000000)    : rshift_pcc_26;
            (33554432 &&& 0xfe000000)    : rshift_pcc_25;
            (16777216 &&& 0xff000000)    : rshift_pcc_24;
            (8388608 &&& 0xff800000)    : rshift_pcc_23;
            (4194304 &&& 0xffc00000)    : rshift_pcc_22;
            (2097152 &&& 0xffe00000)    : rshift_pcc_21;
            (1048576 &&& 0xfff00000)    : rshift_pcc_20;
            (524288 &&& 0xfff80000)     : rshift_pcc_19;
            (262144 &&& 0xfffc0000)     : rshift_pcc_18;
            (131072 &&& 0xfffe0000)     : rshift_pcc_17;
            (65536 &&& 0xffff0000)      : rshift_pcc_16;
            (32768 &&& 0xffff8000)      : rshift_pcc_15;
            (16384 &&& 0xffffc000)      : rshift_pcc_14;
            (8192 &&& 0xffffe000)       : rshift_pcc_13;
            (4096 &&& 0xfffff000)       : rshift_pcc_12;
            (2048 &&& 0xfffff800)       : rshift_pcc_11;
            (1024 &&& 0xfffffc00)       : rshift_pcc_10;
            (512 &&& 0xfffffe00)        : rshift_pcc_9;
            (256 &&& 0xffffff00)        : rshift_pcc_8;
            (128 &&& 0xffffff80)        : rshift_pcc_7;
            (64 &&& 0xffffffc0)         : rshift_pcc_6;
            (32 &&& 0xffffffe0)         : rshift_pcc_5;
            (16 &&& 0xfffffff0)         : rshift_pcc_4;
            (8 &&& 0xfffffff8)          : rshift_pcc_3;
            (4 &&& 0xfffffffc)          : rshift_pcc_2;
            (2 &&& 0xfffffffe)          : rshift_pcc_1;
            (1 &&& 0xffffffff)          : rshift_pcc_0;
        }
	}

	apply {

		// Hash calculation.
		hash_calc_five_t_0();
		hash_calc_five_t_1();
		hash_calc_five_t_xor();
		hash_calc_five_t_decay();

		// Check if the stored values correspond to the current flow direction.
		flow_dir();

	    // Check if more than 60 secs have elapsed since the last update for the current flow.
		decay_check.apply();

		// Increment the current packet count and length.
		pkt_cnt_0_incr();
		pkt_len_incr();

		// Squared sum (packet length) calculation.
		ss_0_incr();

		// Mean calculation using right bit-shift.
		// Equivalent to pkt length / pkt count.
		// Division is performed by rounding up the current pkt count to a power of 2.
		// Additionally, we also calculate the mean for the squared sum values.
		mean_0.apply();

		// Residue calculation.

		// Calculate the residue value for the current flow.
		res_0_calc();
		// Update the stored residue values corresponding to both flow directions, as required, based on the previous check.
		res_update.apply();

		// Residual product calculation.
		res_prod.apply();

		// Sum of residual products calculation (64 bit value).

		// Sum of residual products - [31:0].
		sum_res_prod_lo.apply();
		// Inverse value of the residual product, needed for the carry calculation.
		res_prod_lo_inv_calc();
		// Obtain the carry value, if it exists. Apply the current decay, if needed.
		sum_res_prod_get_carry.apply();
		// Sum of residual products - [63:32].
		sum_res_prod_hi.apply();

		pkt_cnt_update.apply();
		ss_update.apply();
		mean_update.apply();

		// Mean ss calculation.
		mean_ss_0.apply();
		mean_ss_1.apply();

		// Mean squared calculation (math_unit).
		// mean_sqr_0_calc();
		// mean_sqr_1_calc();

		// Mean squared calculation (sharma).
		mean_sqr_0.apply(hdr.peregrine.five_t_mean, eg_md.stats_five_t.mean_sqr_0);
		mean_sqr_1.apply(eg_md.stats_five_t.mean_1, eg_md.stats_five_t.mean_sqr_1);

		mean_sqr_sum();

		// Magnitude calculation (math_unit).
		// magnitude_calc();

		// Magnitude calculation (sharma).
		magnitude.apply(eg_md.stats_five_t.mean_sqr_0, hdr.peregrine.five_t_magnitude);

		// Variance calculation.

		variance_0_calc();
		variance_1_calc();
		variance_abs();

		// Std dev calculation (math_unit).
		// std_dev_0_calc();
		// std_dev_1_calc();

		// Std dev calculation (sharma).
		std_dev_0.apply(eg_md.stats_five_t.variance_0, hdr.peregrine.five_t_std_dev);
		std_dev_1.apply(eg_md.stats_five_t.variance_1, eg_md.stats_five_t.std_dev_1);

		// Variance squared calculation (math_unit).
		// variance_sqr_0_calc();
		// variance_sqr_1_calc();

		// Variance squared calculation (sharma).
		variance_sqr_0.apply(eg_md.stats_five_t.variance_0, eg_md.stats_five_t.variance_sqr_0);
		variance_sqr_1.apply(eg_md.stats_five_t.variance_1, eg_md.stats_five_t.variance_sqr_1);

		variance_sqr_sum();

		// Radius calculation (math_unit).
		// radius_calc();

		// Radius calculation (sharma).
		radius.apply(eg_md.stats_five_t.variance_sqr_0, hdr.peregrine.five_t_radius);

		// Approx. Covariance calculation.

		// Weight 1 + Weight 2.
		pkt_cnt_sum();

		cov.apply();

		// Correlation Coefficient calculation.

		std_dev_prod.apply();
		pcc.apply();
	}
}

#endif
