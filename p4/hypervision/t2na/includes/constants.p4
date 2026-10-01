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

#define REG_SIZE 16384

#define TIME_10_S 152587

// 16ms
#define BIN_TS_0_SPLIT 244
// 48ms
#define BIN_TS_1_SPLIT 732
// 80ms
#define BIN_TS_2_SPLIT 1220
// 112ms
#define BIN_TS_3_SPLIT 1708
// 144ms
#define BIN_TS_4_SPLIT 2197

#define BIN_LEN_0_SPLIT 256
#define BIN_LEN_1_SPLIT 768
#define BIN_LEN_2_SPLIT 1280
#define BIN_LEN_3_SPLIT 1792
#define BIN_LEN_4_SPLIT 2304

#endif
