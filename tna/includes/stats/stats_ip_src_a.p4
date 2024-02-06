control c_stats_ip_src_a(inout header_t hdr, inout ingress_metadata_a_t ig_md) {

    // ----------------------------------------
    // Hashes
    // ----------------------------------------

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_ip_src;

    // ----------------------------------------
    // Registers and temp. variables
    // ----------------------------------------

    Register<bit<32>, _>(REG_SIZE) reg_ip_src_ts;

    Register<bit<32>, _>(REG_SIZE) reg_ip_src_cnt;      // Packet count
    Register<bit<32>, _>(REG_SIZE) reg_ip_src_len;      // Packet length
    Register<bit<32>, _>(REG_SIZE) reg_ip_src_ss;       // Squared sum of the packet length

    // ----------------------------------------
    // Register actions
    // ----------------------------------------

	// Check if more than 100 ms have elapsed since the last update for the current flow.
	// If so, increase the stored value by 100 ms and set a flag.
	// 1525 corresponds to the bit-sliced value for 100 ms (in ns).
    RegisterAction<_, _, bit<32>>(reg_ip_src_ts) ract_decay_check_100_ms = {
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
    RegisterAction<_, _, bit<32>>(reg_ip_src_ts) ract_decay_check_1_s = {
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
    RegisterAction<_, _, bit<32>>(reg_ip_src_ts) ract_decay_check_10_s = {
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
    RegisterAction<_, _, bit<32>>(reg_ip_src_ts) ract_decay_check_60_s = {
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
    RegisterAction<_, _, bit<32>>(reg_ip_src_cnt) ract_pkt_cnt_incr = {
        void apply(inout bit<32> value, out bit<32> result) {
            if (ig_md.stats_ip_src.decay_check == 0) {
                value = value + 1;
            } else {
                value = div_pkt_cnt.execute(value) + 1;
            }
            result = value;
        }
    };

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_pkt_len;
    RegisterAction<_, _, bit<32>>(reg_ip_src_len) ract_pkt_len_incr = {
        void apply(inout bit<32> value, out bit<32> result) {
            if (ig_md.stats_ip_src.decay_check == 0) {
                value = value + (bit<32>)hdr.ipv4.len;
            } else {
                value = div_pkt_len.execute(value);
            }
            result = value;
        }
    };

    MathUnit<bit<32>>(MathOp_t.MUL, 1, 2) div_ss;
    RegisterAction<_, _, bit<32>>(reg_ip_src_ss) ract_ss_calc = {
        void apply(inout bit<32> value, out bit<32> result) {
            if (ig_md.stats_ip_src.decay_check == 0) {
                value = value + ig_md.meta.pkt_len_squared;
            } else {
                value = div_ss.execute(value);
            }
            result = value;
        }
    };

    // ----------------------------------------
    // Actions
    // ----------------------------------------

    action hash_calc_ip_src() {
        ig_md.hash.ip_src = (bit<16>)hash_ip_src.get({hdr.ipv4.src_addr})[12:0];
    }

    action decay_check_100_ms() {
        ig_md.stats_ip_src.decay_check = ract_decay_check_100_ms.execute(ig_md.hash.ip_src);
    }

    action decay_check_1_s() {
        ig_md.stats_ip_src.decay_check = ract_decay_check_1_s.execute(ig_md.hash.ip_src);
    }

    action decay_check_10_s() {
        ig_md.stats_ip_src.decay_check = ract_decay_check_10_s.execute(ig_md.hash.ip_src);
    }

    action decay_check_60_s() {
        ig_md.stats_ip_src.decay_check = ract_decay_check_60_s.execute(ig_md.hash.ip_src);
    }

    action pkt_cnt_incr() {
        ig_md.stats_ip_src.pkt_cnt_0 = ract_pkt_cnt_incr.execute(ig_md.hash.ip_src);
    }

    action pkt_len_incr() {
        ig_md.stats_ip_src.pkt_len = ract_pkt_len_incr.execute(ig_md.hash.ip_src);
    }

    action ss_calc() {
        ig_md.stats_ip_src.ss = ract_ss_calc.execute(ig_md.hash.ip_src);
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

    // ----------------------------------------
    // Apply
    // ----------------------------------------

    apply {

        // Hash calculation.
        hash_calc_ip_src();
		ig_md.hash.ip_src = ig_md.hash.ip_src + ig_md.meta.decay_cntr;

	    // Check if the current decay interval has elapsed.
        decay_check.apply();

        // Increment the current packet count and length.
        pkt_cnt_incr();
        pkt_len_incr();

        // Squared sum (packet length) calculation.
        ss_calc();
    }
}
