#ifndef _SQR_
#define _SQR_

#include "../constants.p4"

control c_sqr(in op_t value, out op_t result) {
    action no_match() {
        result = 0;
    }

    action set_result(op_t res) {
        result = res;
    }

    table lookup {
        key = {
            value: ternary;
        }

        actions = {
            set_result;
            no_match;
        }

        size = 383;
        default_action = no_match();
    }

    apply {
        lookup.apply();
    }
}

#endif
