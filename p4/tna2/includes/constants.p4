#ifndef _CONSTANTS_
#define _CONSTANTS_

#define MAX_PORTS 255

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_ICMP = 1;
const ip_proto_t IP_PROTO_IPV4 = 4;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

typedef bit<9> port_t;

const port_t CPU_PORT = 255;

#define REG_SIZE 32768
#define SAMPLING 1024
#define FORWARD_TABLE_SIZE 1024

// The decay intervals are 100ms, 1s, 10s and 60.
// Due to limitations in the max packet rate supported by the SDE,
// we define decays which are multiples of these,
// and slow down the rate at which the trace is executed accordingly.

/*
#define DECAY_100_MS 1525
#define DECAY_1_S 15258
#define DECAY_10_S 152587
#define DECAY_60_S 915527
*/

// Eval: x2 decay constants
/*
#define DECAY_100_MS 3051
#define DECAY_1_S 30517
#define DECAY_10_S 305175
#define DECAY_60_S 1831054
*/

// Eval: x4 decay constants
#define DECAY_100_MS 6103
#define DECAY_1_S 61035
#define DECAY_10_S 610351
#define DECAY_60_S 1220703

// Eval: x8 decay constants
/*
#define DECAY_100_MS 12207
#define DECAY_1_S 122070
#define DECAY_10_S 1220703
#define DECAY_60_S 7324218
*/

#endif
