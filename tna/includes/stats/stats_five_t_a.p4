control c_stats_five_t_a(inout header_t hdr, inout ingress_metadata_a_t ig_md) {

	// ----------------------------------------
	// Hashes
	// ----------------------------------------

	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_five_t_0;			// Hash for flow id (a->b)
	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_five_t_1;			// Hash for flow id (b->a)

	// ----------------------------------------
	// Registers and temp. variables
	// ----------------------------------------

	Register<bit<32>, _>(REG_SIZE) reg_five_t_ts;
	Register<bit<32>, _>(REG_SIZE) reg_five_t_cnt_0; 		// Packet count for flow id (a->b)
	Register<bit<32>, _>(REG_SIZE) reg_five_t_cnt_1; 		// Packet count for flow id (b->a)
	Register<bit<32>, _>(REG_SIZE) reg_five_t_len;   		// Packet length
	Register<bit<32>, _>(REG_SIZE) reg_five_t_ss_0;    		// Squared sum of the packet length
	Register<bit<32>, _>(REG_SIZE) reg_five_t_ss_1;    		// Squared sum of the packet length
	Register<bit<32>, _>(REG_SIZE) reg_five_t_mean;			// Mean
	Register<bit<32>, _>(REG_SIZE) reg_five_t_res_check;	// Residue values
	Register<res_current, _>(REG_SIZE) reg_five_t_res;		// Residue values

	Register<bit<32>, _>(REG_SIZE) reg_five_t_sum_res_prod_lo;			// Sum of residual products
	Register<bit<32>, _>(REG_SIZE) reg_five_t_sum_res_prod_lo_carry;	// Sum of residual products
	Register<bit<32>, _>(REG_SIZE) reg_five_t_sum_res_prod_hi;			// Sum of residual products

	bit<32> res_prod_lo_inv;
	bit<32> sum_res_prod_hi_carry;

	// ----------------------------------------
	// Register actions
	// ----------------------------------------

	// Check if more than 100 ms have elapsed since the last update for the current flow.
	// If so, increase the stored value by 100 ms and set a flag.
	// 1525 corresponds to the bit-sliced value for 100 ms (in ns).
    RegisterAction<_, _, bit<32>>(reg_five_t_ts) ract_decay_check_100_ms = {
        void apply(inout bit<32> value, out bit<32> result) {
            result = 0;
            if (DECAY_100_MS < ig_md.meta.current_ts - value && value != 0) {
                value = value + DECAY_100_MS;
                result = 1;
            } else {
                value = ig_md.meta.current_ts;
            }
        }
    };

	// Check if more than 1 sec has elapsed since the last update for the current flow.
	// If so, increase the stored value by 1 sec and set a flag.
	// 15258 corresponds to the bit-sliced value for 1 sec (in ns).
    RegisterAction<_, _, bit<32>>(reg_five_t_ts) ract_decay_check_1_s = {
        void apply(inout bit<32> value, out bit<32> result) {
            result = 0;
            if (DECAY_1_S < ig_md.meta.current_ts - value && value != 0) {
                value = value + DECAY_1_S;
                result = 1;
            } else {
                value = ig_md.meta.current_ts;
            }
        }
    };

	// Check if more than 10 secs have elapsed since the last update for the current flow.
	// If so, increase the stored value by 10 secs and set a flag.
	// 152587 corresponds to the bit-sliced value for 10 secs (in ns).
    RegisterAction<_, _, bit<32>>(reg_five_t_ts) ract_decay_check_10_s = {
        void apply(inout bit<32> value, out bit<32> result) {
            result = 0;
            if (DECAY_10_S < ig_md.meta.current_ts - value && value != 0) {
                value = value + DECAY_10_S;
                result = 1;
            } else {
                value = ig_md.meta.current_ts;
            }
        }
    };

	// Check if more than 60 secs have elapsed since the last update for the current flow.
	// If so, increase the stored value by 60 secs and set a flag.
	// 915527 corresponds to the bit-sliced value for 60 secs (in ns).
    RegisterAction<_, _, bit<32>>(reg_five_t_ts) ract_decay_check_60_s = {
        void apply(inout bit<32> value, out bit<32> result) {
            result = 0;
            if (DECAY_60_S < ig_md.meta.current_ts - value && value != 0) {
                value = value + DECAY_60_S;
                result = 1;
            } else {
                value = ig_md.meta.current_ts;
            }
        }
    };

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_cnt;
	RegisterAction<_, _, bit<32>>(reg_five_t_cnt_0) ract_pkt_cnt_0_incr = {
		void apply(inout bit<32> value, out bit<32> result) {
			if (ig_md.stats_five_t.decay_check == 0) {
				value = value + 1;
			} else {
				value = div_pkt_cnt.execute(value) + 1;
			}
			result = value;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_cnt_1) ract_pkt_cnt_1_incr = {
		void apply(inout bit<32> value) {
			value = ig_md.stats_five_t.pkt_cnt_0;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_cnt_1) ract_pkt_cnt_1_read = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = value;
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_len;
	RegisterAction<_, _, bit<32>>(reg_five_t_len) ract_pkt_len_incr = {
		void apply(inout bit<32> value, out bit<32> result) {
			if (ig_md.stats_five_t.decay_check == 0) {
				value = value + (bit<32>)hdr.ipv4.len;
			} else {
				value = div_pkt_len.execute(value);
			}
			result = value;
		}
	};

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_ss;
    RegisterAction<_, _, bit<32>>(reg_five_t_ss_0) ract_ss_0_incr = {
        void apply(inout bit<32> value, out bit<32> result) {
            if (ig_md.stats_five_t.decay_check == 0) {
                value = value + ig_md.meta.pkt_len_squared;
            } else {
                value = div_ss.execute(value);
            }
            result = value;
        }
    };

	RegisterAction<_, _, bit<32>>(reg_five_t_ss_1) ract_ss_1_incr = {
		void apply(inout bit<32> value) {
			value = ig_md.stats_five_t.ss_0;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_ss_1) ract_ss_1_read = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = value;
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_lo;
	RegisterAction<_, _, bit<32>>(reg_five_t_sum_res_prod_lo) ract_sum_res_prod_lo = {
		void apply(inout bit<32> value, out bit<32> result) {
			if (ig_md.stats_five_t.decay_check == 0) {
				value = value + ig_md.stats_five_t.res_prod[31:0];
			} else {
				value = div_sum_res_prod_lo.execute(value);
			}
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_lo_carry;
	RegisterAction<_, _, bit<32>>(reg_five_t_sum_res_prod_lo_carry) ract_sum_res_prod_lo_carry_decay = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = div_sum_res_prod_lo_carry.execute(value);
			result = value;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_sum_res_prod_lo_carry) ract_sum_res_prod_lo_carry = {
		void apply(inout bit<32> value, out bit<32> result) {
			if (res_prod_lo_inv < value) {
				result = 1;
			} else {
				result = 0;
			}
			value = value + ig_md.stats_five_t.res_prod[31:0];
		}
	};

	MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_sum_res_prod_hi;
	RegisterAction<_, _, bit<32>>(reg_five_t_sum_res_prod_hi) ract_sum_res_prod_hi = {
		void apply(inout bit<32> value, out bit<32> result) {
			if (ig_md.stats_five_t.decay_check == 0) {
				value = value + sum_res_prod_hi_carry;
			} else {
				value = div_sum_res_prod_hi.execute(value);
			}
			result = value;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_mean) ract_mean_0_write = {
		void apply(inout bit<32> value) {
			value = ig_md.stats_five_t.mean_0;
		}
	};

	RegisterAction<_, _, bit<32>>(reg_five_t_mean) ract_mean_1_read = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = value;
			result = value;
		}
	};

	// Check if the current flow hash corresponds to the stored reg value.
	// If not, then the stored value is from the reverse flow and must be updated.
	RegisterAction<_, _, bit<32>>(reg_five_t_res_check) ract_res_check = {
		void apply(inout bit<16> value, out bit<32> result) {
			result = 0;
			if (value != ig_md.hash.five_t_0) {
				value = ig_md.hash.five_t_0;
				result = 1;
			}
		}
	};

	// The stored values correspond to the current flow direction.
	// Update the current residue and return the value for the other direction.
	RegisterAction<res_current, _, bit<32>>(reg_five_t_res) ract_res_read = {
		void apply(inout res_current res, out bit<32> result) {
			result = res.res_1;
			res.res_0_old = ig_md.stats_five_t.res_0;
		}
	};

	// The stored values correspond to the reverse flow direction.
	// Save the stored old residue as the reverse value (res_1) and update the current residue (res_0).
	RegisterAction<res_current, _, bit<32>>(reg_five_t_res) ract_res_update = {
		void apply(inout res_current res, out bit<32> result) {
			result = res.res_0_old;
			res.res_1 = res.res_0_old;
			res.res_0_old = ig_md.stats_five_t.res_0;
		}
	};

	// ----------------------------------------
	// Actions
	// ----------------------------------------

	action hash_calc_five_t_0() {
		ig_md.hash.five_t_0 = (bit<16>)hash_five_t_0.get({hdr.ipv4.src_addr,
														  hdr.ipv4.dst_addr,
										   		          hdr.ipv4.protocol,
										   		          ig_md.meta.l4_src_port,
										   		          ig_md.meta.l4_dst_port})[12:0];
	}

	action hash_calc_five_t_1() {
		ig_md.hash.five_t_1 = (bit<16>)hash_five_t_1.get({hdr.ipv4.dst_addr,
											              hdr.ipv4.src_addr,
										   		          hdr.ipv4.protocol,
										   		          ig_md.meta.l4_dst_port,
										   		          ig_md.meta.l4_src_port})[12:0];
	}

    action decay_check_100_ms() {
        ig_md.stats_five_t.decay_check = ract_decay_check_100_ms.execute(ig_md.hash.five_t_0);
    }

    action decay_check_1_s() {
        ig_md.stats_five_t.decay_check = ract_decay_check_1_s.execute(ig_md.hash.five_t_0);
    }

    action decay_check_10_s() {
        ig_md.stats_five_t.decay_check = ract_decay_check_10_s.execute(ig_md.hash.five_t_0);
    }

    action decay_check_60_s() {
        ig_md.stats_five_t.decay_check = ract_decay_check_60_s.execute(ig_md.hash.five_t_0);
    }

	action pkt_cnt_0_incr() {
		ig_md.stats_five_t.pkt_cnt_0 = ract_pkt_cnt_0_incr.execute(ig_md.hash.five_t_0);
	}

	action pkt_cnt_1_incr() {
		ract_pkt_cnt_1_incr.execute(ig_md.hash.five_t_1);
	}

	action pkt_cnt_1_read() {
		ig_md.stats_five_t.pkt_cnt_1 = ract_pkt_cnt_1_read.execute(ig_md.hash.five_t_1);
	}

	action pkt_len_incr() {
		ig_md.stats_five_t.pkt_len = ract_pkt_len_incr.execute(ig_md.hash.five_t_0);
	}

	action ss_0_incr() {
		ig_md.stats_five_t.ss_0 = ract_ss_0_incr.execute(ig_md.hash.five_t_0);
	}

	action ss_1_incr() {
		ract_ss_1_incr.execute(ig_md.hash.five_t_1);
	}

	action ss_1_read() {
		ig_md.stats_five_t.ss_1 = ract_ss_1_read.execute(ig_md.hash.five_t_1);
	}

	action res_0_calc() {
		ig_md.stats_five_t.res_0 = ig_md.stats_five_t.pkt_len - ig_md.stats_five_t.mean_0;
	}

	action res_check() {
		ig_md.stats_five_t.res_check = ract_res_check.execute(ig_md.hash.five_t_sub_abs);
	}

	action res_read() {
		ig_md.stats_five_t.res_1 = ract_res_read.execute(ig_md.hash.five_t_sub_abs);
	}

	action res_update() {
		ig_md.stats_five_t.res_1 = ract_res_update.execute(ig_md.hash.five_t_sub_abs);
	}

	action sum_res_prod_lo() {
		ig_md.stats_five_t.sum_res_prod[31:0] = ract_sum_res_prod_lo.execute(ig_md.hash.five_t_sub_abs);
	}

	action sum_res_prod_get_carry_decay_0() {
		sum_res_prod_hi_carry = ig_md.stats_five_t.res_prod[63:32] + ract_sum_res_prod_lo_carry.execute(ig_md.hash.five_t_sub_abs);
	}

	action sum_res_prod_get_carry_decay_1() {
		sum_res_prod_hi_carry = ig_md.stats_five_t.res_prod[63:32] + ract_sum_res_prod_lo_carry_decay.execute(ig_md.hash.five_t_sub_abs);
	}

	action sum_res_prod_hi() {
		ig_md.stats_five_t.sum_res_prod[63:32] = ract_sum_res_prod_hi.execute(ig_md.hash.five_t_sub_abs);
	}

	action mean_0_write() {
		ract_mean_0_write.execute(ig_md.hash.five_t_1);
	}

	action mean_1_read() {
		ig_md.stats_five_t.mean_1 = ract_mean_1_read.execute(ig_md.hash.five_t_1);
	}

	action rshift_mean_0() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len;
	}

	action rshift_mean_1() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 1;
	}

	action rshift_mean_2() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 2;
	}

	action rshift_mean_3() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 3;
	}

	action rshift_mean_4() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 4;
	}

	action rshift_mean_5() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 5;
	}

	action rshift_mean_6() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 6;
	}

	action rshift_mean_7() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 7;
	}

	action rshift_mean_8() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 8;
	}

	action rshift_mean_9() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 9;
	}

	action rshift_mean_10() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 10;
	}

	action rshift_mean_11() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 11;
	}

	action rshift_mean_12() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 12;
	}

	action rshift_mean_13() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 13;
	}

	action rshift_mean_14() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 14;
	}

	action rshift_mean_15() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 15;
	}

	action rshift_mean_16() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 16;
	}

	action rshift_mean_17() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 17;
	}

	action rshift_mean_18() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 18;
	}

	action rshift_mean_19() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 19;
	}

	action rshift_mean_20() {
		ig_md.stats_five_t.mean_0 = ig_md.stats_five_t.pkt_len >> 20;
	}

	action lshift_res_prod_0() {
		ig_md.stats_five_t.res_prod = (bit<64>)ig_md.stats_five_t.res_0;
	}

	action lshift_res_prod_1() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 1);
	}

	action lshift_res_prod_2() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 2);
	}

	action lshift_res_prod_3() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 3);
	}

	action lshift_res_prod_4() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 4);
	}

	action lshift_res_prod_5() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 5);
	}

	action lshift_res_prod_6() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 6);
	}

	action lshift_res_prod_7() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 7);
	}

	action lshift_res_prod_8() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 8);
	}

	action lshift_res_prod_9() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 9);
	}

	action lshift_res_prod_10() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 10);
	}

	action lshift_res_prod_11() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 11);
	}

	action lshift_res_prod_12() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 12);
	}

	action lshift_res_prod_13() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 13);
	}

	action lshift_res_prod_14() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 14);
	}

	action lshift_res_prod_15() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 15);
	}

	action lshift_res_prod_16() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 16);
	}

	action lshift_res_prod_17() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 17);
	}

	action lshift_res_prod_18() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 18);
	}

	action lshift_res_prod_19() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 19);
	}

	action lshift_res_prod_20() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 20);
	}

	action lshift_res_prod_21() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 21);
	}

	action lshift_res_prod_22() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 22);
	}

	action lshift_res_prod_23() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 23);
	}

	action lshift_res_prod_24() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 24);
	}

	action lshift_res_prod_25() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 25);
	}

	action lshift_res_prod_26() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 26);
	}

	action lshift_res_prod_27() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 27);
	}

	action lshift_res_prod_28() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 28);
	}

	action lshift_res_prod_29() {
		ig_md.stats_five_t.res_prod = (bit<64>)(ig_md.stats_five_t.res_0 << 29);
	}

	action miss() {}

    table decay_check {
        key = {
            ig_md.meta.decay_cntr : exact;
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
    }

	table mean_0 {
		key = {
			ig_md.stats_five_t.pkt_cnt_0 : ternary;
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
		size = 32;
	}

	table res_struct_update {
		key = {
			ig_md.stats_five_t.res_check : exact;
		}
		actions = {
			res_read;
			res_update;
		}
		size = 2;
	}

	table res_prod {
		key = {
			ig_md.stats_five_t.res_1 : ternary;
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
			lshift_res_prod_21;
			lshift_res_prod_22;
			lshift_res_prod_23;
			lshift_res_prod_24;
			lshift_res_prod_25;
			lshift_res_prod_26;
			lshift_res_prod_27;
			lshift_res_prod_28;
			lshift_res_prod_29;
			miss;
		}
		const default_action = miss;
		size = 32;
	}

	table sum_res_prod_get_carry {
		key = {
			ig_md.stats_five_t.decay_check : exact;
		}
		actions = {
			sum_res_prod_get_carry_decay_0;
			sum_res_prod_get_carry_decay_1;
		}
		size = 2;
	}

	table pkt_cnt_1_access {
		key = {
			ig_md.meta.recirc_toggle : exact;
		}
		actions = {
			pkt_cnt_1_incr;
			pkt_cnt_1_read;
		}
		size = 3;
	}

	table ss_1_access {
		key = {
			ig_md.meta.recirc_toggle : exact;
		}
		actions = {
			ss_1_incr;
			ss_1_read;
		}
		size = 3;
	}

	table mean_1_access {
		key = {
			ig_md.meta.recirc_toggle : exact;
		}
		actions = {
			mean_0_write;
			mean_1_read;
		}
		size = 3;
	}

	// ----------------------------------------
	// Apply
	// ----------------------------------------

	apply {

		// Hash calculation.
		hash_calc_five_t_0();
		hash_calc_five_t_1();

		ig_md.hash.five_t_sub_abs = ig_md.hash.five_t_0 ^ ig_md.hash.five_t_1;

		ig_md.hash.five_t_0 = ig_md.hash.five_t_0 + ig_md.meta.decay_cntr;
		ig_md.hash.five_t_1 = ig_md.hash.five_t_1 + ig_md.meta.decay_cntr;
		ig_md.hash.five_t_sub_abs = ig_md.hash.five_t_sub_abs + ig_md.meta.decay_cntr;

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
		// Check if the stored residue values correspond to the current flow direction.
		res_check();
		// Update the stored residue values corresponding to both flow directions, as required, based on the previous check.
		res_struct_update.apply();

		// Residual product calculation.
		res_prod.apply();

		// Sum of residual products calculation (64 bit value).

		// Sum of residual products - [31:0].
		sum_res_prod_lo();
		// Inverse value of the residual product, needed for the carry calculation.
		res_prod_lo_inv = ~ig_md.stats_five_t.res_prod[31:0];
		// Obtain the carry value, if it exists. Apply the current decay, if needed.
		sum_res_prod_get_carry.apply();
		// Sum of residual products - [63:32].
		sum_res_prod_hi();

		if (ig_md.meta.recirc_toggle == 1) {
			ig_md.hash.five_t_1 = ig_md.hash.five_t_0;
		}

		pkt_cnt_1_access.apply();
		ss_1_access.apply();
		mean_1_access.apply();
	}
}
