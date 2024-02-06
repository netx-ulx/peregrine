control c_stats_mac_ip_src_b(inout header_t hdr, inout ingress_metadata_b_t ig_md) {

    // ----------------------------------------
    // Registers and temp. variables
    // ----------------------------------------

    Register<bit<32>, _>(1) reg_mac_ip_src_mean_squared;    // Squared mean
    Register<bit<32>, _>(1) reg_mac_ip_src_std_dev;         // Std. dev

    // ----------------------------------------
    // Register actions
    // ----------------------------------------

    MathUnit<bit<32>>(MathOp_t.SQR, 1) square_mean;
    RegisterAction<_, _, bit<32>>(reg_mac_ip_src_mean_squared) ract_mean_squared_calc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = square_mean.execute(hdr.peregrine.mac_ip_src_mean);
            result = value;
        }
    };

    MathUnit<bit<32>>(MathOp_t.SQRT, 1) std_dev;
    RegisterAction<_, _, bit<32>>(reg_mac_ip_src_std_dev) ract_std_dev_calc = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = std_dev.execute(ig_md.stats_mac_ip_src.variance);
            result = value;
        }
    };

    // ----------------------------------------
    // Actions
    // ----------------------------------------

	action rshift_mean_0() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss;
	}

	action rshift_mean_1() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 1;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 1;
	}

	action rshift_mean_2() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 2;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 2;
	}

	action rshift_mean_3() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 3;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 3;
	}

	action rshift_mean_4() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 4;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 4;
	}

	action rshift_mean_5() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 5;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 5;
	}

	action rshift_mean_6() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 6;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 6;
	}

	action rshift_mean_7() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 7;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 7;
	}

	action rshift_mean_8() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 8;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 8;
	}

	action rshift_mean_9() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 9;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 9;
	}

	action rshift_mean_10() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 10;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 10;
	}

	action rshift_mean_11() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 11;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 11;
	}

	action rshift_mean_12() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 12;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 12;
	}

	action rshift_mean_13() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 13;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 13;
	}

	action rshift_mean_14() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 14;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 14;
	}

	action rshift_mean_15() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 15;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 15;
	}

	action rshift_mean_16() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 16;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 16;
	}

	action rshift_mean_17() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 17;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 17;
	}

	action rshift_mean_18() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 18;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 18;
	}

	action rshift_mean_19() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 19;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 19;
	}

	action rshift_mean_20() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 20;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 20;
	}

	action rshift_mean_21() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 21;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 21;
	}

	action rshift_mean_22() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 22;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 22;
	}

	action rshift_mean_23() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 23;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 23;
	}

	action rshift_mean_24() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 24;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 24;
	}

	action rshift_mean_25() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 25;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 25;
	}

	action rshift_mean_26() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 26;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 26;
	}

	action rshift_mean_27() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 27;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 27;
	}

	action rshift_mean_28() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 28;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 28;
	}

	action rshift_mean_29() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 29;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 29;
	}

	action rshift_mean_30() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 30;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 30;
	}

	action rshift_mean_31() {
		hdr.peregrine.mac_ip_src_mean = hdr.peregrine.mac_ip_src_pkt_len >> 31;
		ig_md.stats_mac_ip_src.mean_ss = hdr.peregrine.mac_ip_src_ss >> 31;
	}

	action mean_squared_calc() {
		ig_md.stats_mac_ip_src.mean_squared = ract_mean_squared_calc.execute(0);
	}

	action variance_calc() {
		ig_md.stats_mac_ip_src.variance = ig_md.stats_mac_ip_src.mean_squared - ig_md.stats_mac_ip_src.mean_ss;
		ig_md.stats_mac_ip_src.variance_neg = ig_md.stats_mac_ip_src.mean_ss - ig_md.stats_mac_ip_src.mean_squared;
	}

	action std_dev_calc() {
		hdr.peregrine.mac_ip_src_std_dev = ract_std_dev_calc.execute(0);
	}

    action miss() {}

    table mean {
		key = {
			hdr.peregrine.mac_ip_src_pkt_cnt : ternary;
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
			rshift_mean_21;
			rshift_mean_22;
			rshift_mean_23;
			rshift_mean_24;
			rshift_mean_25;
			rshift_mean_26;
			rshift_mean_27;
			rshift_mean_28;
			rshift_mean_29;
			rshift_mean_30;
			rshift_mean_31;
            miss;
		}
		const default_action = miss;
		size = 32;
	}

    // ----------------------------------------
    // Apply
    // ----------------------------------------

    apply {

        // Mean calculation using right bit-shift.
        // Equivalent to pkt length / pkt count.
        // Division is performed by rounding up the current pkt count to a power of 2.
        // Additionally, we also calculate the mean for the squared sum values.
        mean.apply();

        // Mean squared calculation.
        mean_squared_calc();

        // Variance 0 calculation.
        variance_calc();

		if (ig_md.stats_mac_ip_src.variance[31:31] != 0) {
			ig_md.stats_mac_ip_src.variance = ig_md.stats_mac_ip_src.variance_neg;
		}

        std_dev_calc();
    }
}
