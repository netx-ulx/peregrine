#ifndef _STATS_MAC_IP_SRC_
#define _STATS_MAC_IP_SRC_

#include "../math/sqr.p4"
#include "../math/sqrt.p4"

control c_stats_mac_ip_src(inout header_t hdr, inout ingress_metadata_t ig_md) {

    c_sqr()     mean_sqr;
    c_sqrt()    std_dev;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_mac_ip_src;

    Register<bit<32>, bit<16>>(REG_SIZE) reg_mac_ip_src_ts;

    Register<bit<32>, bit<16>>(REG_SIZE) reg_mac_ip_src_cnt;  // Packet count
    Register<bit<32>, bit<16>>(REG_SIZE) reg_mac_ip_src_len;  // Packet length
    Register<bit<32>, bit<16>>(REG_SIZE) reg_mac_ip_src_ss;   // Squared sum of the packet length

    // Register<bit<32>, bit<1>>(1) reg_mac_ip_src_mean_sqr;    // Squared mean
    // Register<bit<32>, bit<1>>(1) reg_mac_ip_src_std_dev;     // Std. dev

	// Check if more than 100 ms have elapsed since the last update for the current flow.
	// If so, increase the stored value by 100 ms and set a flag.
	// 1525 corresponds to the bit-sliced value for 100 ms (in ns).
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_ts) ract_decay_check_100_ms = {
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
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_ts) ract_decay_check_1_s = {
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
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_ts) ract_decay_check_10_s = {
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
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_ts) ract_decay_check_60_s = {
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
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_cnt) ract_pkt_cnt_incr = {
        void apply(inout bit<32> val, out bit<32> res) {
            if (ig_md.stats_mac_ip_src.decay_check == 0) {
                val = val + 1;
            } else {
                val = div_pkt_cnt.execute(val) + 1;
            }
            res = val;
        }
    };

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_len;
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_len) ract_pkt_len_incr = {
        void apply(inout bit<32> val, out bit<32> res) {
            if (ig_md.stats_mac_ip_src.decay_check == 0) {
                val = val + (bit<32>)hdr.ipv4.len;
            } else {
                val = div_pkt_len.execute(val);
            }
            res = val;
        }
    };

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_ss;
    RegisterAction<_, bit<16>, bit<32>>(reg_mac_ip_src_ss) ract_ss_calc = {
        void apply(inout bit<32> val, out bit<32> res) {
            if (ig_md.stats_mac_ip_src.decay_check == 0) {
                val = val + hdr.meta.pkt_len_sqr;
            } else {
                val = div_ss.execute(val);
            }
            res = val;
        }
    };

    /*
    MathUnit<bit<32>>(MathOp_t.SQR, 1) mean_sqr;
    RegisterAction<_, bit<1>, bit<32>>(reg_mac_ip_src_mean_sqr) ract_mean_sqr_calc = {
        void apply(inout bit<32> val, out bit<32> res) {
            val = mean_sqr.execute(hdr.peregrine.mac_ip_src_mean);
            res = val;
        }
    };
    */

    /*
    MathUnit<bit<32>>(MathOp_t.SQRT, 1) std_dev;
    RegisterAction<_, bit<1>, bit<32>>(reg_mac_ip_src_std_dev) ract_std_dev_calc = {
        void apply(inout bit<32> val, out bit<32> res) {
            val = std_dev.execute(ig_md.stats_mac_ip_src.variance);
            res = val;
        }
    };
    */

    action hash_calc_mac_ip_src() {
        ig_md.stats_mac_ip_src.hash_0 = (bit<16>)hash_mac_ip_src.get({hdr.ethernet.src_addr, hdr.ipv4.src_addr})[12:0];
    }

    action hash_calc_mac_ip_src_decay() {
		ig_md.stats_mac_ip_src.hash_0 = ig_md.stats_mac_ip_src.hash_0 + hdr.meta.decay_cntr;
    }

    action decay_check_100_ms() {
        ig_md.stats_mac_ip_src.decay_check = ract_decay_check_100_ms.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action decay_check_1_s() {
        ig_md.stats_mac_ip_src.decay_check = ract_decay_check_1_s.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action decay_check_10_s() {
        ig_md.stats_mac_ip_src.decay_check = ract_decay_check_10_s.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action decay_check_60_s() {
        ig_md.stats_mac_ip_src.decay_check = ract_decay_check_60_s.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action pkt_cnt_incr() {
        hdr.peregrine.mac_ip_src_pkt_cnt = ract_pkt_cnt_incr.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action pkt_len_incr() {
        ig_md.stats_mac_ip_src.pkt_len = ract_pkt_len_incr.execute(ig_md.stats_mac_ip_src.hash_0);
    }

    action ss_calc() {
        ig_md.stats_mac_ip_src.ss = ract_ss_calc.execute(ig_md.stats_mac_ip_src.hash_0);
    }

	action rshift_mean_0() {
        hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss;
	}

	action rshift_mean_1() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 1;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 1;
	}

	action rshift_mean_2() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 2;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 2;
	}

	action rshift_mean_3() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 3;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 3;
	}

	action rshift_mean_4() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 4;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 4;
	}

	action rshift_mean_5() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 5;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 5;
	}

	action rshift_mean_6() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 6;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 6;
	}

	action rshift_mean_7() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 7;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 7;
	}

	action rshift_mean_8() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 8;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 8;
	}

	action rshift_mean_9() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 9;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 9;
	}

	action rshift_mean_10() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 10;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 10;
	}

	action rshift_mean_11() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 11;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 11;
	}

	action rshift_mean_12() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 12;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 12;
	}

	action rshift_mean_13() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 13;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 13;
	}

	action rshift_mean_14() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 14;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 14;
	}

	action rshift_mean_15() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 15;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 15;
	}

	action rshift_mean_16() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 16;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 16;
	}

	action rshift_mean_17() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 17;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 17;
	}

	action rshift_mean_18() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 18;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 18;
	}

	action rshift_mean_19() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 19;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 19;
	}

	action rshift_mean_20() {
		hdr.peregrine.mac_ip_src_mean = ig_md.stats_mac_ip_src.pkt_len >> 20;
		ig_md.stats_mac_ip_src.mean_ss = ig_md.stats_mac_ip_src.ss >> 20;
	}

    /*
	action mean_sqr_calc() {
		ig_md.stats_mac_ip_src.mean_sqr = ract_mean_sqr_calc.execute(0);
	}
    */

	action variance_calc() {
		ig_md.stats_mac_ip_src.variance = ig_md.stats_mac_ip_src.mean_sqr - ig_md.stats_mac_ip_src.mean_ss;
		ig_md.stats_mac_ip_src.variance_neg = ig_md.stats_mac_ip_src.mean_ss - ig_md.stats_mac_ip_src.mean_sqr;
	}

	action variance_abs() {
        ig_md.stats_mac_ip_src.variance = min(ig_md.stats_mac_ip_src.variance, ig_md.stats_mac_ip_src.variance_neg);
	}

    /*
	action std_dev_calc() {
		hdr.peregrine.mac_ip_src_std_dev = ract_std_dev_calc.execute(0);
	}
    */

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

    apply {

        // Hash calculation.
        hash_calc_mac_ip_src();
        hash_calc_mac_ip_src_decay();

	    // Check if the current decay interval has elapsed.
        decay_check.apply();

        // Increment the current packet count and length.
        pkt_cnt_incr();
        pkt_len_incr();

        // Squared sum (packet length) calculation.
        ss_calc();

        // Mean calculation using right bit-shift.
        // Equivalent to pkt length / pkt count.
        // Division is performed by rounding up the current pkt count to a power of 2.
        // Additionally, we also calculate the mean for the squared sum values.
        mean.apply();

        // Mean squared calculation (math_unit).
        /* mean_sqr_calc(); */

        // Mean squared calculation (sharma).
        mean_sqr.apply(hdr.peregrine.mac_ip_src_mean, ig_md.stats_mac_ip_src.mean_sqr);

        // Variance calculation.
        variance_calc();
        variance_abs();

        // Std dev calculation (math_unit).
        // std_dev_calc();

        // Std dev calculation (sharma).
        std_dev.apply(ig_md.stats_mac_ip_src.variance, hdr.peregrine.mac_ip_src_std_dev);
    }
}

#endif
