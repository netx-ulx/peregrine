#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import json
import random
import time
from pathlib import Path
# add BF Python to search path
import pipeline
from pipeline import pkt_pipeline
from eval_metrics import eval_metrics

logger = None
grpc_client = None

SAMPLING_RATE = 1024

port_to_veth = {0: 'veth0',
                1: 'veth2',
                2: 'veth4',
                3: 'veth6',
                4: 'veth8',
                5: 'veth10',
                6: 'veth12',
                7: 'veth14',
                8: 'veth16',
                9: 'veth18',
                10: 'veth20',
                11: 'veth22',
                12: 'veth24',
                13: 'veth26',
                14: 'veth28',
                15: 'veth30',
                16: 'veth32',
                64: 'veth250'}


def make_port(pipe, local_port):
    """ Given a pipe and a port within that pipe construct the full port number. """
    return (pipe << 7) | local_port


def port_to_local_port(port):
    """ Given a port return its ID within a pipe. """
    # print('port', port)
    local_port = port & 0x7F
    assert (local_port < 72)
    return local_port


def port_to_pipe(port):
    """ Given a port return the pipe it belongs to. """
    local_port = port_to_local_port(port)
    pipe = (port >> 7) & 0x3
    assert (port == make_port(pipe, local_port))
    return pipe


def get_internal_port_from_external(ext_port, internal_pipes, external_pipes):
    pipe_local_port = port_to_local_port(ext_port)
    int_pipe = internal_pipes[external_pipes.index(port_to_pipe(ext_port))]

    # For Tofino-1 we are use a 1-to-1 mapping from external port to internal port so just replace the pipe-id.
    return make_port(int_pipe, pipe_local_port)


def get_port_from_pipes(pipes, swports_by_pipe):
    ports = list()
    for pipe in pipes:
        ports = ports + swports_by_pipe[pipe]
    return random.choice(ports)


def setup_grpc_client(server, port, program):
    global grpc_client

    # connect to GRPC server
    logger.info("Connecting to GRPC server {}:{} and binding to program {}...".format(args.grpc_server,
                                                                                      args.grpc_port,
                                                                                      args.program))
    grpc_client = gc.ClientInterface("{}:{}".format(args.grpc_server, args.grpc_port), 0, 0)
    grpc_client.bind_pipeline_config(args.program)


def configure_switch(program, topology):
    # get all tables for program
    bfrt_info = grpc_client.bfrt_info_get(program)

    # Setup ports.
    Ports.ports = Ports(gc, bfrt_info)

    for entry in topology['ports']:
        Ports.ports.add_port(entry['port'], 0, entry['capacity'], 'none')

    # 4 pipes in total.
    pipes = list(range(4))

    swports = []
    swports_by_pipe = {p: list() for p in pipes}
    ports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 64]
    for port in ports:
        swports.append(port)
        swports.sort()
        for port in swports:
            pipe = port_to_pipe(port)
            swports_by_pipe[pipe].append(port)

    # Tofino 1 uses pipes 0 and 2 as the external pipes while 1 and 3 are the internal pipes.
    external_pipes = [0, 2]
    internal_pipes = [1, 3]

    # ig_port = get_port_from_pipes(external_pipes, swports_by_pipe)
    ig_port = 0
    # eg_port = get_port_from_pipes(external_pipes, swports_by_pipe)
    eg_port = 2

    cur_eg_veth = port_to_veth[eg_port]

    int_port = get_internal_port_from_external(ig_port, internal_pipes, external_pipes)
    logger.info("Expected forwarding path:")
    logger.info(" 1. Ingress processing in external pipe %d, ingress port %d", port_to_pipe(ig_port), ig_port)
    logger.info(" 2. Egress processing in internal pipe %d, internal port %d", port_to_pipe(int_port), int_port)
    logger.info(" 3. Loopback on internal port %d", int_port)
    logger.info(" 4. Ingress processing in internal pipe %d, internal port %d", port_to_pipe(int_port), int_port)
    logger.info(" 5. Egress processing in external pipe %d, egress port %d", port_to_pipe(eg_port), eg_port)

    # Setup tables

    a_fwd_recirculation = FwdRecirculation_a(gc, bfrt_info)
    mac_ip_src_decay_check = MacIpSrcDecayCheck(gc, bfrt_info)
    ip_src_decay_check = IpSrcDecayCheck(gc, bfrt_info)
    ip_decay_check = IpDecayCheck(gc, bfrt_info)
    five_t_decay_check = FiveTDecayCheck(gc, bfrt_info)

    a_fwd_recirculation = FwdRecirculation_a(gc, bfrt_info)
    b_fwd_recirculation = FwdRecirculation_b(gc, bfrt_info)

    mac_ip_src_mean = MacIpSrcMean(gc, bfrt_info)
    ip_src_mean = IpSrcMean(gc, bfrt_info)

    ip_mean_0 = IpMean0(gc, bfrt_info)
    ip_res_struct_update = IpResStructUpdate(gc, bfrt_info)
    ip_res_prod = IpResProd(gc, bfrt_info)
    ip_sum_res_prod_get_carry = IpSumResProdGetCarry(gc, bfrt_info)
    ip_pkt_cnt_1_access = IpPktCnt1Access(gc, bfrt_info)
    ip_ss_1_access = IpSs1Access(gc, bfrt_info)
    ip_mean_1_access = IpMean1Access(gc, bfrt_info)
    ip_mean_ss_0 = IpMeanSs0(gc, bfrt_info)
    ip_mean_ss_1 = IpMeanSs1(gc, bfrt_info)
    ip_variance_0_abs = IpVariance0Abs(gc, bfrt_info)
    ip_variance_1_abs = IpVariance1Abs(gc, bfrt_info)
    ip_cov = IpCov(gc, bfrt_info)
    ip_std_dev_prod = IpStdDevProd(gc, bfrt_info)
    ip_pcc = IpPcc(gc, bfrt_info)

    five_t_mean_0 = FiveTMean0(gc, bfrt_info)
    five_t_res_struct_update = FiveTResStructUpdate(gc, bfrt_info)
    five_t_res_prod = FiveTResProd(gc, bfrt_info)
    five_t_sum_res_prod_get_carry = FiveTSumResProdGetCarry(gc, bfrt_info)
    five_t_pkt_cnt_1_access = FiveTPktCnt1Access(gc, bfrt_info)
    five_t_ss_1_access = FiveTSs1Access(gc, bfrt_info)
    five_t_mean_1_access = FiveTMean1Access(gc, bfrt_info)
    five_t_mean_ss_0 = FiveTMeanSs0(gc, bfrt_info)
    five_t_mean_ss_1 = FiveTMeanSs1(gc, bfrt_info)
    five_t_variance_0_abs = FiveTVariance0Abs(gc, bfrt_info)
    five_t_variance_1_abs = FiveTVariance1Abs(gc, bfrt_info)
    five_t_cov = FiveTCov(gc, bfrt_info)
    five_t_std_dev_prod = FiveTStdDevProd(gc, bfrt_info)
    five_t_pcc = FiveTPcc(gc, bfrt_info)

    mac_ip_src_decay_check.add_entry(0, '100_ms')
    mac_ip_src_decay_check.add_entry(8192, '1_s')
    mac_ip_src_decay_check.add_entry(16384, '10_s')
    mac_ip_src_decay_check.add_entry(24576, '60_s')

    ip_src_decay_check.add_entry(0, '100_ms')
    ip_src_decay_check.add_entry(8192, '1_s')
    ip_src_decay_check.add_entry(16384, '10_s')
    ip_src_decay_check.add_entry(24576, '60_s')

    ip_decay_check.add_entry(0, '100_ms')
    ip_decay_check.add_entry(8192, '1_s')
    ip_decay_check.add_entry(16384, '10_s')
    ip_decay_check.add_entry(24576, '60_s')

    five_t_decay_check.add_entry(0, '100_ms')
    five_t_decay_check.add_entry(8192, '1_s')
    five_t_decay_check.add_entry(16384, '10_s')
    five_t_decay_check.add_entry(24576, '60_s')

    # a_fwd_recirculation.add_entry(ig_port, False, eg_port)
    a_fwd_recirculation.add_entry(ig_port, True, int_port)
    b_fwd_recirculation.add_entry(int_port, eg_port)

    mac_ip_src_mean.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    mac_ip_src_mean.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    mac_ip_src_mean.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    mac_ip_src_mean.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    mac_ip_src_mean.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    mac_ip_src_mean.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    mac_ip_src_mean.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    mac_ip_src_mean.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    mac_ip_src_mean.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    mac_ip_src_mean.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    mac_ip_src_mean.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    mac_ip_src_mean.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    mac_ip_src_mean.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    mac_ip_src_mean.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    mac_ip_src_mean.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    mac_ip_src_mean.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    mac_ip_src_mean.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    mac_ip_src_mean.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    mac_ip_src_mean.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    mac_ip_src_mean.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    mac_ip_src_mean.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    mac_ip_src_mean.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    mac_ip_src_mean.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    mac_ip_src_mean.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    mac_ip_src_mean.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    mac_ip_src_mean.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    mac_ip_src_mean.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    mac_ip_src_mean.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    mac_ip_src_mean.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    mac_ip_src_mean.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)
    mac_ip_src_mean.add_entry(2, 1073741824, 0b11000000000000000000000000000000, 30)
    mac_ip_src_mean.add_entry(1, 2147483648, 0b10000000000000000000000000000000, 31)

    ip_src_mean.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_src_mean.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_src_mean.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_src_mean.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_src_mean.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_src_mean.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_src_mean.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_src_mean.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_src_mean.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_src_mean.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_src_mean.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_src_mean.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_src_mean.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_src_mean.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_src_mean.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_src_mean.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_src_mean.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_src_mean.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_src_mean.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_src_mean.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_src_mean.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    ip_src_mean.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    ip_src_mean.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    ip_src_mean.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    ip_src_mean.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    ip_src_mean.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    ip_src_mean.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    ip_src_mean.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    ip_src_mean.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    ip_src_mean.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)
    ip_src_mean.add_entry(2, 1073741824, 0b11000000000000000000000000000000, 30)
    ip_src_mean.add_entry(1, 2147483648, 0b10000000000000000000000000000000, 31)

    ip_mean_0.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_mean_0.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_mean_0.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_mean_0.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_mean_0.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_mean_0.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_mean_0.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_mean_0.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_mean_0.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_mean_0.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_mean_0.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_mean_0.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_mean_0.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_mean_0.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_mean_0.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_mean_0.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_mean_0.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_mean_0.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_mean_0.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_mean_0.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_mean_0.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    ip_res_struct_update.add_entry(0, 'read')
    ip_res_struct_update.add_entry(1, 'update')

    ip_res_prod.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_res_prod.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_res_prod.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_res_prod.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_res_prod.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_res_prod.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_res_prod.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_res_prod.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_res_prod.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_res_prod.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_res_prod.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_res_prod.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_res_prod.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_res_prod.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_res_prod.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_res_prod.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_res_prod.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_res_prod.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_res_prod.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_res_prod.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_res_prod.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    ip_res_prod.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    ip_res_prod.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    ip_res_prod.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    ip_res_prod.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    ip_res_prod.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    ip_res_prod.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    ip_res_prod.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    ip_res_prod.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    ip_res_prod.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)

    ip_sum_res_prod_get_carry.add_entry(0, '0')
    ip_sum_res_prod_get_carry.add_entry(1, '1')

    ip_pkt_cnt_1_access.add_entry(0, 'incr')
    ip_pkt_cnt_1_access.add_entry(1, 'read')

    ip_ss_1_access.add_entry(0, 'incr')
    ip_ss_1_access.add_entry(1, 'read')

    ip_mean_1_access.add_entry(0, '0_write')
    ip_mean_1_access.add_entry(1, '1_read')

    ip_mean_ss_0.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_mean_ss_0.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_mean_ss_0.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_mean_ss_0.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_mean_ss_0.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_mean_ss_0.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_mean_ss_0.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_mean_ss_0.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_mean_ss_0.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_mean_ss_0.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_mean_ss_0.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_mean_ss_0.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_mean_ss_0.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_mean_ss_0.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_mean_ss_0.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_mean_ss_0.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_mean_ss_0.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_mean_ss_0.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_mean_ss_0.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_mean_ss_0.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_mean_ss_0.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    ip_mean_ss_1.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_mean_ss_1.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_mean_ss_1.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_mean_ss_1.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_mean_ss_1.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_mean_ss_1.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_mean_ss_1.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_mean_ss_1.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_mean_ss_1.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_mean_ss_1.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_mean_ss_1.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_mean_ss_1.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_mean_ss_1.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_mean_ss_1.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_mean_ss_1.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_mean_ss_1.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_mean_ss_1.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_mean_ss_1.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_mean_ss_1.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_mean_ss_1.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_mean_ss_1.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    ip_variance_0_abs.add_entry(2,
                                0b00000000000000000000000000000000,
                                0b10000000000000000000000000000000,
                                'pos')
    ip_variance_0_abs.add_entry(1,
                                0b10000000000000000000000000000000,
                                0b10000000000000000000000000000000,
                                'neg')

    ip_variance_1_abs.add_entry(2,
                                0b00000000000000000000000000000000,
                                0b10000000000000000000000000000000,
                                'pos')
    ip_variance_1_abs.add_entry(1,
                                0b10000000000000000000000000000000,
                                0b10000000000000000000000000000000,
                                'neg')

    ip_cov.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_cov.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_cov.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_cov.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_cov.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_cov.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_cov.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_cov.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_cov.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_cov.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_cov.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_cov.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_cov.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_cov.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_cov.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_cov.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_cov.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_cov.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_cov.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_cov.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_cov.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    ip_std_dev_prod.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_std_dev_prod.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_std_dev_prod.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_std_dev_prod.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_std_dev_prod.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_std_dev_prod.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_std_dev_prod.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_std_dev_prod.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_std_dev_prod.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_std_dev_prod.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_std_dev_prod.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_std_dev_prod.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_std_dev_prod.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_std_dev_prod.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_std_dev_prod.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_std_dev_prod.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)

    ip_pcc.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    ip_pcc.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    ip_pcc.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    ip_pcc.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    ip_pcc.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    ip_pcc.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    ip_pcc.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    ip_pcc.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    ip_pcc.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    ip_pcc.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    ip_pcc.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    ip_pcc.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    ip_pcc.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    ip_pcc.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    ip_pcc.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    ip_pcc.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    ip_pcc.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    ip_pcc.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    ip_pcc.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    ip_pcc.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    ip_pcc.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    ip_pcc.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    ip_pcc.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    ip_pcc.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    ip_pcc.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    ip_pcc.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    ip_pcc.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    ip_pcc.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    ip_pcc.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    ip_pcc.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)
    ip_pcc.add_entry(2, 1073741824, 0b11000000000000000000000000000000, 30)
    ip_pcc.add_entry(1, 2147483648, 0b10000000000000000000000000000000, 31)

    five_t_mean_0.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_mean_0.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_mean_0.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_mean_0.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_mean_0.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_mean_0.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_mean_0.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_mean_0.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_mean_0.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_mean_0.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_mean_0.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_mean_0.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_mean_0.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_mean_0.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_mean_0.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_mean_0.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_mean_0.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_mean_0.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_mean_0.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_mean_0.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_mean_0.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    five_t_res_struct_update.add_entry(0, 'read')
    five_t_res_struct_update.add_entry(1, 'update')

    five_t_res_prod.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_res_prod.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_res_prod.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_res_prod.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_res_prod.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_res_prod.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_res_prod.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_res_prod.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_res_prod.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_res_prod.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_res_prod.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_res_prod.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_res_prod.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_res_prod.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_res_prod.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_res_prod.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_res_prod.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_res_prod.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_res_prod.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_res_prod.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_res_prod.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    five_t_res_prod.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    five_t_res_prod.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    five_t_res_prod.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    five_t_res_prod.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    five_t_res_prod.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    five_t_res_prod.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    five_t_res_prod.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    five_t_res_prod.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    five_t_res_prod.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)

    five_t_sum_res_prod_get_carry.add_entry(0, '0')
    five_t_sum_res_prod_get_carry.add_entry(1, '1')

    five_t_pkt_cnt_1_access.add_entry(0, 'incr')
    five_t_pkt_cnt_1_access.add_entry(1, 'read')

    five_t_ss_1_access.add_entry(0, 'incr')
    five_t_ss_1_access.add_entry(1, 'read')

    five_t_mean_1_access.add_entry(0, '0_write')
    five_t_mean_1_access.add_entry(1, '1_read')

    five_t_mean_ss_0.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_mean_ss_0.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_mean_ss_0.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_mean_ss_0.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_mean_ss_0.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_mean_ss_0.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_mean_ss_0.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_mean_ss_0.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_mean_ss_0.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_mean_ss_0.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_mean_ss_0.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_mean_ss_0.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_mean_ss_0.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_mean_ss_0.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_mean_ss_0.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_mean_ss_0.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_mean_ss_0.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_mean_ss_0.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_mean_ss_0.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_mean_ss_0.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_mean_ss_0.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    five_t_mean_ss_1.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_mean_ss_1.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_mean_ss_1.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_mean_ss_1.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_mean_ss_1.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_mean_ss_1.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_mean_ss_1.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_mean_ss_1.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_mean_ss_1.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_mean_ss_1.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_mean_ss_1.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_mean_ss_1.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_mean_ss_1.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_mean_ss_1.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_mean_ss_1.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_mean_ss_1.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_mean_ss_1.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_mean_ss_1.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_mean_ss_1.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_mean_ss_1.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_mean_ss_1.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    five_t_variance_0_abs.add_entry(2,
                                    0b00000000000000000000000000000000,
                                    0b10000000000000000000000000000000,
                                    'pos')
    five_t_variance_0_abs.add_entry(1,
                                    0b10000000000000000000000000000000,
                                    0b10000000000000000000000000000000,
                                    'neg')

    five_t_variance_1_abs.add_entry(2,
                                    0b00000000000000000000000000000000,
                                    0b10000000000000000000000000000000,
                                    'pos')
    five_t_variance_1_abs.add_entry(1,
                                    0b10000000000000000000000000000000,
                                    0b10000000000000000000000000000000,
                                    'neg')

    five_t_cov.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_cov.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_cov.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_cov.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_cov.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_cov.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_cov.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_cov.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_cov.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_cov.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_cov.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_cov.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_cov.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_cov.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_cov.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_cov.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_cov.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_cov.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_cov.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_cov.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_cov.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)

    five_t_std_dev_prod.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_std_dev_prod.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_std_dev_prod.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_std_dev_prod.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_std_dev_prod.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_std_dev_prod.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_std_dev_prod.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_std_dev_prod.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_std_dev_prod.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_std_dev_prod.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_std_dev_prod.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_std_dev_prod.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_std_dev_prod.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_std_dev_prod.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_std_dev_prod.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_std_dev_prod.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)

    five_t_pcc.add_entry(32, 1, 0b11111111111111111111111111111111, 0)
    five_t_pcc.add_entry(31, 2, 0b11111111111111111111111111111110, 1)
    five_t_pcc.add_entry(30, 4, 0b11111111111111111111111111111100, 2)
    five_t_pcc.add_entry(29, 8, 0b11111111111111111111111111111000, 3)
    five_t_pcc.add_entry(28, 16, 0b11111111111111111111111111110000, 4)
    five_t_pcc.add_entry(27, 32, 0b11111111111111111111111111100000, 5)
    five_t_pcc.add_entry(26, 64, 0b11111111111111111111111111000000, 6)
    five_t_pcc.add_entry(25, 128, 0b11111111111111111111111110000000, 7)
    five_t_pcc.add_entry(24, 256, 0b11111111111111111111111100000000, 8)
    five_t_pcc.add_entry(23, 512, 0b11111111111111111111111000000000, 9)
    five_t_pcc.add_entry(22, 1024, 0b11111111111111111111110000000000, 10)
    five_t_pcc.add_entry(21, 2048, 0b11111111111111111111100000000000, 11)
    five_t_pcc.add_entry(20, 4096, 0b11111111111111111111000000000000, 12)
    five_t_pcc.add_entry(19, 8192, 0b11111111111111111110000000000000, 13)
    five_t_pcc.add_entry(18, 16384, 0b11111111111111111100000000000000, 14)
    five_t_pcc.add_entry(17, 32768, 0b11111111111111111000000000000000, 15)
    five_t_pcc.add_entry(16, 65536, 0b11111111111111110000000000000000, 16)
    five_t_pcc.add_entry(15, 131072, 0b11111111111111100000000000000000, 17)
    five_t_pcc.add_entry(14, 262144, 0b11111111111111000000000000000000, 18)
    five_t_pcc.add_entry(13, 524288, 0b11111111111110000000000000000000, 19)
    five_t_pcc.add_entry(12, 1048576, 0b11111111111100000000000000000000, 20)
    five_t_pcc.add_entry(11, 2097152, 0b11111111111000000000000000000000, 21)
    five_t_pcc.add_entry(10, 4194304, 0b11111111110000000000000000000000, 22)
    five_t_pcc.add_entry(9, 8388608, 0b11111111100000000000000000000000, 23)
    five_t_pcc.add_entry(8, 16777216, 0b11111111000000000000000000000000, 24)
    five_t_pcc.add_entry(7, 33554432, 0b11111110000000000000000000000000, 25)
    five_t_pcc.add_entry(6, 67108864, 0b11111100000000000000000000000000, 26)
    five_t_pcc.add_entry(5, 134217728, 0b11111000000000000000000000000000, 27)
    five_t_pcc.add_entry(4, 268435456, 0b11110000000000000000000000000000, 28)
    five_t_pcc.add_entry(3, 536870912, 0b11100000000000000000000000000000, 29)
    five_t_pcc.add_entry(2, 1073741824, 0b11000000000000000000000000000000, 30)
    five_t_pcc.add_entry(1, 2147483648, 0b10000000000000000000000000000000, 31)

    # Done with configuration
    logger.info("Switch configured successfully!")

    return cur_eg_veth

def get_topology(topology_file):
    with open(topology_file, "r") as f:
        data = f.read()
        topology = json.loads(data)
        return topology


if __name__ == "__main__":
    # set up options
    argparser = argparse.ArgumentParser(description="Peregrine controller.")
    argparser.add_argument('--grpc_server', type=str, default='localhost', help='GRPC server name/address')
    argparser.add_argument('--grpc_port', type=int, default=50052, help='GRPC server port')
    argparser.add_argument('--program', type=str, default='peregrine', help='P4 program name')
    argparser.add_argument('--topo', type=str, default=str(Path(__file__).parents[0])+'/topology.json', help='Topology')
    argparser.add_argument('--trace', type=str, help='Pcap file path')
    argparser.add_argument('--labels', type=str, help='Trace labels path')
    argparser.add_argument('--sampling', type=int, help='Execution phase sampling rate')
    argparser.add_argument('--fm_grace', type=int, default=100000, help='FM grace period.')
    argparser.add_argument('--ad_grace', type=int, default=900000, help='AD grace period.')
    argparser.add_argument('--max_ae', type=int, default=10, help='KitNET: m value')
    argparser.add_argument('--train_exact_ratio', type=float, default=0, help='Ratio of exact stats in the overall training phase.')
    argparser.add_argument('--train_stats', type=str, default=None, help='Prev. trained stats struct path')
    argparser.add_argument('--fm_model', type=str, default=None, help='Prev. trained FM model path')
    argparser.add_argument('--el_model', type=str, default=None, help='Prev. trained EL path')
    argparser.add_argument('--ol_model', type=str, default=None, help='Prev. trained OL path')
    argparser.add_argument('--attack', type=str, help='Current trace attack name')
    argparser.add_argument('--exact_stats', action='store_true')
    args = argparser.parse_args()

    # configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(args.program)

    try:
        import bfrt_grpc.client as gc
    except ImportError:
        sys.path.append(os.environ['SDE_INSTALL'] + '/lib/python3.8/site-packages/tofino')
        import bfrt_grpc.client as gc
    from ports import Ports
    from peregrine_tables import MacIpSrcDecayCheck, IpSrcDecayCheck, IpDecayCheck, FiveTDecayCheck
    from peregrine_tables import FwdRecirculation_a, FwdRecirculation_b
    from peregrine_tables import MacIpSrcMean, IpSrcMean
    from peregrine_tables import IpMean0, IpResStructUpdate, IpResProd, IpSumResProdGetCarry
    from peregrine_tables import IpPktCnt1Access, IpSs1Access, IpMean1Access
    from peregrine_tables import IpMeanSs0, IpMeanSs1, IpVariance0Abs, IpVariance1Abs, IpCov, IpStdDevProd, IpPcc
    from peregrine_tables import FiveTMean0, FiveTResStructUpdate, FiveTResProd, FiveTSumResProdGetCarry
    from peregrine_tables import FiveTPktCnt1Access, FiveTSs1Access, FiveTMean1Access
    from peregrine_tables import FiveTMeanSs0, FiveTMeanSs1, FiveTVariance0Abs, FiveTVariance1Abs
    from peregrine_tables import FiveTCov, FiveTStdDevProd, FiveTPcc
    topology = get_topology(args.topo)
    setup_grpc_client(args.grpc_server, args.grpc_port, args.program)
    cur_eg_veth = configure_switch(args.program, topology)

    start = time.time()
    print(cur_eg_veth)

    # Call function to run the packet processing pipeline.
    # Encompasses both training phase + execution phase.
    pipeline_out = pkt_pipeline(cur_eg_veth, args.trace, args.labels, args.sampling, args.fm_grace,
                                args.ad_grace, args.max_ae, args.fm_model, args.el_model,
                                args.ol_model, args.train_stats, args.attack, args.exact_stats,
                                args.train_exact_ratio)

    stop = time.time()
    total_time = stop - start

    print('Complete. Time elapsed: ', total_time)
    print('Threshold: ', pipeline.threshold)

    # Call function to perform eval/csv, also based on kitsune's main.
    # pipeline_out: rmse_list [0], cur_stats_global [1], peregrine_eval[2],
    # threshold [3], train_skip flag [4].
    eval_metrics(pipeline_out[0], pipeline_out[1], pipeline_out[2], pipeline_out[3], pipeline_out[4],
                 args.fm_grace, args.ad_grace, args.attack, args.sampling, args.max_ae,
                 args.train_exact_ratio, total_time)

    # exit (bug workaround)
    logger.info("Exiting!")

    # flush logs, stdout, stderr
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()

    # exit (bug workaround)
    # os.kill(os.getpid(), signal.SIGTERM)
