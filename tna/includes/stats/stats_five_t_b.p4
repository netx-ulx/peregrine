control c_stats_five_t_b(inout header_t hdr, inout ingress_metadata_b_t ig_md) {

	// ----------------------------------------
	// Registers and temp. variables
	// ----------------------------------------

	Register<bit<32>, _>(1) reg_five_t_mean_squared_0;		// Squared mean for flow id (a->b)
	Register<bit<32>, _>(1) reg_five_t_mean_squared_1;		// Squared mean for flow id (b->a)
	Register<bit<32>, _>(1) reg_five_t_variance_squared_0;	// Squared variance for flow id (a->b)
	Register<bit<32>, _>(1) reg_five_t_variance_squared_1;	// Squared variance for flow id (b->a)
	Register<bit<32>, _>(1) reg_five_t_std_dev_0;			// Std. deviation for flow id (a->b)
	Register<bit<32>, _>(1) reg_five_t_std_dev_1;			// Std. deviation for flow id (b->a)
	Register<bit<32>, _>(1) reg_five_t_magnitude; 			// Magnitude
	Register<bit<32>, _>(1) reg_five_t_radius;				// Radius

	// Temporary variables for stats calculation.
	bit<32> magnitude_temp = 0;
	bit<32> radius_temp = 0;

	// ----------------------------------------
	// Register actions
	// ----------------------------------------

	MathUnit<bit<32>>(MathOp_t.SQR, 1) square_mean_0;
	RegisterAction<_, _, bit<32>>(reg_five_t_mean_squared_0) ract_mean_squared_0_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = square_mean_0.execute(hdr.peregrine.five_t_mean_0);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQR, 1) square_mean_1;
	RegisterAction<_, _, bit<32>>(reg_five_t_mean_squared_1) ract_mean_squared_1_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = square_mean_1.execute(hdr.peregrine.five_t_mean_1);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_std_dev_0;
	RegisterAction<_, _, bit<32>>(reg_five_t_std_dev_0) ract_std_dev_0_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = sqrt_std_dev_0.execute(ig_md.stats_five_t.variance_0_abs);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_std_dev_1;
	RegisterAction<_, _, bit<32>>(reg_five_t_std_dev_1) ract_std_dev_1_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = sqrt_std_dev_1.execute(ig_md.stats_five_t.variance_1_abs);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_magnitude;
	RegisterAction<_, _, bit<32>>(reg_five_t_magnitude) ract_magnitude_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = sqrt_magnitude.execute(magnitude_temp);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQR, 1) square_variance_0;
	RegisterAction<_, _, bit<32>>(reg_five_t_variance_squared_0) ract_variance_squared_0_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = square_variance_0.execute(ig_md.stats_five_t.variance_0_abs);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQR, 1) square_variance_1;
	RegisterAction<_, _, bit<32>>(reg_five_t_variance_squared_1) ract_variance_squared_1_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = square_variance_1.execute(ig_md.stats_five_t.variance_1_abs);
			result = value;
		}
	};

	MathUnit<bit<32>>(MathOp_t.SQRT, 1) sqrt_radius;
	RegisterAction<_, _, bit<32>>(reg_five_t_radius) ract_radius_calc = {
		void apply(inout bit<32> value, out bit<32> result) {
			value = sqrt_radius.execute(radius_temp);
			result = value;
		}
	};

	// ----------------------------------------
	// Actions
	// ----------------------------------------

	action mean_squared_0_calc() {
		ig_md.stats_five_t.mean_squared_0 = ract_mean_squared_0_calc.execute(0);
	}

	action mean_squared_1_calc() {
		ig_md.stats_five_t.mean_squared_1 = ract_mean_squared_1_calc.execute(0);
	}

	action variance_0_pos() {
		ig_md.stats_five_t.variance_0_abs = ig_md.stats_five_t.variance_0;
	}

	action variance_0_neg() {
		ig_md.stats_five_t.variance_0_abs = ig_md.stats_five_t.variance_0_neg;
	}

	action variance_1_pos() {
		ig_md.stats_five_t.variance_1_abs = ig_md.stats_five_t.variance_1;
	}

	action variance_1_neg() {
		ig_md.stats_five_t.variance_1_abs = ig_md.stats_five_t.variance_1_neg;
	}

	action rshift_mean_ss_0_0() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0;
	}

	action rshift_mean_ss_0_1() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 1;
	}

	action rshift_mean_ss_0_2() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 2;
	}

	action rshift_mean_ss_0_3() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 3;
	}

	action rshift_mean_ss_0_4() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 4;
	}

	action rshift_mean_ss_0_5() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 5;
	}

	action rshift_mean_ss_0_6() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 6;
	}

	action rshift_mean_ss_0_7() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 7;
	}

	action rshift_mean_ss_0_8() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 8;
	}

	action rshift_mean_ss_0_9() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 9;
	}

	action rshift_mean_ss_0_10() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 10;
	}

	action rshift_mean_ss_0_11() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 11;
	}

	action rshift_mean_ss_0_12() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 12;
	}

	action rshift_mean_ss_0_13() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 13;
	}

	action rshift_mean_ss_0_14() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 14;
	}

	action rshift_mean_ss_0_15() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 15;
	}

	action rshift_mean_ss_0_16() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 16;
	}

	action rshift_mean_ss_0_17() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 17;
	}

	action rshift_mean_ss_0_18() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 18;
	}

	action rshift_mean_ss_0_19() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 19;
	}

	action rshift_mean_ss_0_20() {
		ig_md.stats_five_t.mean_ss_0 = hdr.peregrine.five_t_ss_0 >> 20;
	}

	action rshift_mean_ss_1_0() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1;
	}

	action rshift_mean_ss_1_1() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 1;
	}

	action rshift_mean_ss_1_2() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 2;
	}

	action rshift_mean_ss_1_3() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 3;
	}

	action rshift_mean_ss_1_4() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 4;
	}

	action rshift_mean_ss_1_5() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 5;
	}

	action rshift_mean_ss_1_6() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 6;
	}

	action rshift_mean_ss_1_7() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 7;
	}

	action rshift_mean_ss_1_8() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 8;
	}

	action rshift_mean_ss_1_9() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 9;
	}

	action rshift_mean_ss_1_10() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 10;
	}

	action rshift_mean_ss_1_11() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 11;
	}

	action rshift_mean_ss_1_12() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 12;
	}

	action rshift_mean_ss_1_13() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 13;
	}

	action rshift_mean_ss_1_14() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 14;
	}

	action rshift_mean_ss_1_15() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 15;
	}

	action rshift_mean_ss_1_16() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 16;
	}

	action rshift_mean_ss_1_17() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 17;
	}

	action rshift_mean_ss_1_18() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 18;
	}

	action rshift_mean_ss_1_19() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 19;
	}

	action rshift_mean_ss_1_20() {
		ig_md.stats_five_t.mean_ss_1 = hdr.peregrine.five_t_ss_1 >> 20;
	}

	action std_dev_0_calc() {
		hdr.peregrine.five_t_std_dev_0 = ract_std_dev_0_calc.execute(0);
	}

	action std_dev_1_calc() {
		ig_md.stats_five_t.std_dev_1 = ract_std_dev_1_calc.execute(0);
	}

	action magnitude_calc() {
		ig_md.stats_five_t.magnitude = ract_magnitude_calc.execute(0);
	}

	action variance_squared_0_calc() {
		ig_md.stats_five_t.variance_squared_0 = ract_variance_squared_0_calc.execute(0);
	}

	action variance_squared_1_calc() {
		ig_md.stats_five_t.variance_squared_1 = ract_variance_squared_1_calc.execute(0);
	}

	action radius_calc() {
		ig_md.stats_five_t.radius = ract_radius_calc.execute(0);
	}

	action rshift_cov_0() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov;
	}

	action rshift_cov_1() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 1;
	}

	action rshift_cov_2() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 2;
	}

	action rshift_cov_3() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 3;
	}

	action rshift_cov_4() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 4;
	}

	action rshift_cov_5() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 5;
	}

	action rshift_cov_6() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 6;
	}

	action rshift_cov_7() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 7;
	}

	action rshift_cov_8() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 8;
	}

	action rshift_cov_9() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 9;
	}

	action rshift_cov_10() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 10;
	}

	action rshift_cov_11() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 11;
	}

	action rshift_cov_12() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 12;
	}

	action rshift_cov_13() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 13;
	}

	action rshift_cov_14() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 14;
	}

	action rshift_cov_15() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 15;
	}

	action rshift_cov_16() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 16;
	}

	action rshift_cov_17() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 17;
	}

	action rshift_cov_18() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 18;
	}

	action rshift_cov_19() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 19;
	}

	action rshift_cov_20() {
		ig_md.stats_five_t.cov = hdr.peregrine.five_t_sum_res_prod_cov >> 20;
	}

	action lshift_std_dev_prod_0() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0;
	}

	action lshift_std_dev_prod_1() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 1;
	}

	action lshift_std_dev_prod_2() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 2;
	}

	action lshift_std_dev_prod_3() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 3;
	}

	action lshift_std_dev_prod_4() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 4;
	}

	action lshift_std_dev_prod_5() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 5;
	}

	action lshift_std_dev_prod_6() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 6;
	}

	action lshift_std_dev_prod_7() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 7;
	}

	action lshift_std_dev_prod_8() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 8;
	}

	action lshift_std_dev_prod_9() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 9;
	}

	action lshift_std_dev_prod_10() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 10;
	}

	action lshift_std_dev_prod_11() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 11;
	}

	action lshift_std_dev_prod_12() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 12;
	}

	action lshift_std_dev_prod_13() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 13;
	}

	action lshift_std_dev_prod_14() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 14;
	}

	action lshift_std_dev_prod_15() {
		ig_md.stats_five_t.std_dev_prod = hdr.peregrine.five_t_std_dev_0 << 15;
	}

	action rshift_pcc_0() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov;
	}

	action rshift_pcc_1() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 1;
	}

	action rshift_pcc_2() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 2;
	}

	action rshift_pcc_3() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 3;
	}

	action rshift_pcc_4() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 4;
	}

	action rshift_pcc_5() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 5;
	}

	action rshift_pcc_6() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 6;
	}

	action rshift_pcc_7() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 7;
	}

	action rshift_pcc_8() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 8;
	}

	action rshift_pcc_9() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 9;
	}

	action rshift_pcc_10() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 10;
	}

	action rshift_pcc_11() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 11;
	}

	action rshift_pcc_12() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 12;
	}

	action rshift_pcc_13() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 13;
	}

	action rshift_pcc_14() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 14;
	}

	action rshift_pcc_15() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 15;
	}

	action rshift_pcc_16() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 16;
	}

	action rshift_pcc_17() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 17;
	}

	action rshift_pcc_18() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 18;
	}

	action rshift_pcc_19() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 19;
	}

	action rshift_pcc_20() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 20;
	}

	action rshift_pcc_21() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 21;
	}

	action rshift_pcc_22() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 22;
	}

	action rshift_pcc_23() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 23;
	}

	action rshift_pcc_24() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 24;
	}

	action rshift_pcc_25() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 25;
	}

	action rshift_pcc_26() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 26;
	}

	action rshift_pcc_27() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 27;
	}

	action rshift_pcc_28() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 28;
	}

	action rshift_pcc_29() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 29;
	}

	action rshift_pcc_30() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 30;
	}

	action rshift_pcc_31() {
		ig_md.stats_five_t.pcc = ig_md.stats_five_t.cov >> 31;
	}

	action miss() {}

	table mean_ss_0 {
		key = {
			hdr.peregrine.five_t_pkt_cnt : ternary;
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
		size = 32;
	}

	table mean_ss_1 {
		key = {
			hdr.peregrine.five_t_pkt_cnt_1 : ternary;
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
		size = 32;
	}

	table variance_0_abs {
		key = {
			ig_md.stats_five_t.variance_0 : ternary;
		}
		actions = {
			variance_0_pos;
			variance_0_neg;
		}
		size = 2;
	}

	table variance_1_abs {
		key = {
			ig_md.stats_five_t.variance_1 : ternary;
		}
		actions = {
			variance_1_pos;
			variance_1_neg;
		}
		size = 2;
	}

	table cov {
		key = {
			hdr.peregrine.five_t_pkt_cnt_1 : ternary;
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
		size = 32;
	}

	table std_dev_prod {
		key = {
			ig_md.stats_five_t.std_dev_1 : ternary;
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
			lshift_std_dev_prod_12;
			lshift_std_dev_prod_13;
			lshift_std_dev_prod_14;
			lshift_std_dev_prod_15;
			miss;
		}
		const default_action = miss;
		size = 32;
	}

	table pcc {
		key = {
			ig_md.stats_five_t.std_dev_prod : ternary;
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
	}

	// ----------------------------------------
	// Apply
	// ----------------------------------------

	apply {

		// Mean ss calculation.
		mean_ss_0.apply();
		mean_ss_1.apply();

		// Mean squared calculation.
		mean_squared_0_calc();
		mean_squared_1_calc();

		// Variance calculation.

		ig_md.stats_five_t.variance_0 = ig_md.stats_five_t.mean_squared_0 - ig_md.stats_five_t.mean_ss_0;
		ig_md.stats_five_t.variance_0_neg = ig_md.stats_five_t.mean_ss_0 - ig_md.stats_five_t.mean_squared_0;
		variance_0_abs.apply();

		ig_md.stats_five_t.variance_1 = ig_md.stats_five_t.mean_squared_1 - ig_md.stats_five_t.mean_ss_1;
		ig_md.stats_five_t.variance_1_neg = ig_md.stats_five_t.mean_ss_1 - ig_md.stats_five_t.mean_squared_1;
		variance_1_abs.apply();

		// Std. dev calculation.
		std_dev_0_calc();
		std_dev_1_calc();

		// Variance squared calculation.
		variance_squared_0_calc();
		variance_squared_1_calc();

		// Magnitude calculation.

		magnitude_temp = ig_md.stats_five_t.mean_squared_0 + ig_md.stats_five_t.mean_squared_1;
		magnitude_calc();

		// Radius calculation.

		radius_temp = ig_md.stats_five_t.variance_squared_0 + ig_md.stats_five_t.variance_squared_1;
		radius_calc();

		// Approx. Covariance calculation.

		// Weight 1 + Weight 2.
		hdr.peregrine.five_t_pkt_cnt_1 = hdr.peregrine.five_t_pkt_cnt_1 + hdr.peregrine.five_t_pkt_cnt;

		cov.apply();

		// Correlation Coefficient calculation.

		std_dev_prod.apply();
		pcc.apply();
	}
}
