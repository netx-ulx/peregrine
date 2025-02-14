import os
import subprocess
import pandas as pd
import binascii
import socket
import struct
from math import isnan, sqrt, pow, log
from math_unit import MathUnit
import crcmod

sqr = MathUnit(shift=1, invert=False, scale=-6,
               lookup=[x*x for x in range(15, -1, -1)])

# Custom sqrt lookup table to match the results obtained on the Tofino.
lookup_sqrt = [240, 240, 222, 222, 202, 202, 182, 182, 175, 169, 163, 157, 150, 143, 136, 128]
sqrt_mu = MathUnit(shift=-1, invert=False, scale=-7,
                   lookup=lookup_sqrt)


class StatsCalc:
    def __init__(self, file_path, sampling_rate, train_pkts, train_skip):
        self.file_path = file_path              # Path of the trace file / csv.
        self.df_csv = None                      # Dataframe for the trace csv.
        self.cur_pkt = pd.DataFrame()           # Stats of the packet being processed.
        self.sampling_rate = sampling_rate      # Sampling rate during the execution phase.
        self.train_pkts = train_pkts            # Number of packets in the training phase.
        if train_skip:
            self.global_pkt_index = train_pkts
        else:
            self.global_pkt_index = 0
        self.phase_pkt_index = 0                # Packet index for the current phase.
        self.sampl_pkt_index = 0                # Packet index to track the sampling rate (based on the tna impl).

        # Decay control variables.
        self.decay_cntr = 0
        self.decay_ip = 1
        self.decay_five_t = 1

        # Calculated 1D and 2D statistics for all flow keys.
        self.stats_mac_ip_src = {}
        self.stats_ip_src = {}
        self.stats_ip = {}
        self.stats_five_t = {}

        # Support structures for residue calculation.
        self.ip_res = {}
        self.ip_res_sum = {}
        self.five_t_res = {}
        self.five_t_res_sum = {}

        # CRC 16 parameters, following the TNA.
        self.crc16 = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0x0000, xorOut=0x0000)

        # Hash values for all flow keys.
        self.hash_mac_ip_src = 0
        self.hash_ip_src = 0
        self.hash_ip_0 = 0
        self.hash_ip_1 = 0
        self.hash_ip_xor = 0
        self.hash_five_t_0 = 0
        self.hash_five_t_1 = 0
        self.hash_five_t_xor = 0

        # Check if the pcap -> csv already exists and pass it to a dataframe.
        self.__check_csv__()

    def __check_csv__(self):
        # Check the file type.
        file_path = self.file_path.split('.')[0]

        if not os.path.isfile(file_path + '.csv'):
            self.parse_pcap(self.file_path)

        self.df_csv = pd.read_csv(file_path + '.csv')

    def trace_size(self):
        return len(self.df_csv)

    def parse_pcap(self, pcap_path):
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst \
                    -e ip.src -e ip.dst -e ip.len -e ip.proto -e tcp.srcport \
                    -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type \
                    -e icmp.code -e arp.opcode -e arp.src.hw_mac \
                    -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 \
                    -e ipv6.src -e ipv6.dst"
        cmd = 'tshark -r ' + pcap_path + ' -T fields ' + \
            fields + ' -E separator=\',\' -E header=y -E occurrence=f > ' + self.file_path.split('.')[0] + '.csv'

        print('Parsing pcap file to csv.')
        subprocess.call(cmd, shell=True)

    def feature_extract(self):
        # Parse the next packet from the csv.
        if self.global_pkt_index == self.train_pkts:
            self.stats_mac_ip_src = {}
            self.stats_ip_src = {}
            self.stats_ip = {}
            self.stats_five_t = {}
            self.ip_res = {}
            self.ip_res_sum = {}
            self.five_t_res = {}
            self.five_t_res_sum = {}
            self.decay_cntr = 1
            self.phase_pkt_index = 0

        timestamp = float(self.df_csv.iat[self.global_pkt_index, 0])
        mac_src = str(self.df_csv.iat[self.global_pkt_index, 2])
        mac_dst = str(self.df_csv.iat[self.global_pkt_index, 3])
        pkt_len = self.df_csv.iat[self.global_pkt_index, 6]
        if isnan(pkt_len):
            pkt_len = 0
        ip_src = self.df_csv.iat[self.global_pkt_index, 4]
        if str(ip_src) == 'nan':
            ip_src = '0.0.0.0'
        ip_dst = self.df_csv.iat[self.global_pkt_index, 5]
        if str(ip_dst) == 'nan':
            ip_dst = '0.0.0.0'
        ip_proto = self.df_csv.iat[self.global_pkt_index, 7]
        if isnan(ip_proto):
            ip_proto = 0
        if ip_proto == 17:
            port_src = self.df_csv.iat[self.global_pkt_index, 10]
            port_dst = self.df_csv.iat[self.global_pkt_index, 11]
        elif ip_proto == 6:
            port_src = self.df_csv.iat[self.global_pkt_index, 8]
            port_dst = self.df_csv.iat[self.global_pkt_index, 9]
        else:
            port_src = 0
            port_dst = 0
        if isnan(port_src) or isnan(port_dst):
            port_src = 0
            port_dst = 0

        self.global_pkt_index = self.global_pkt_index + 1
        self.phase_pkt_index = self.phase_pkt_index + 1
        self.cur_pkt = [pkt_len, timestamp, mac_dst, mac_src, ip_src, ip_dst,
                        str(int(ip_proto)), str(int(port_src)), str(int(port_dst))]

    def process(self, phase):
        # Update the current decay counter value.
        # If we're in the training phase or the sampling rate is 1,
        # simply alternate the decay counter values.
        if phase == 'training' or self.sampling_rate == 1:
            if self.decay_cntr < 4:
                self.decay_cntr += 1
            else:
                self.decay_cntr = 1
        # Else, for every epoch we must skip a decay counter change.
        # This is necessary to ensure that the sampled packets keep
        # alternating the decay counter values.
        # (As we have 4 decay values, any sampling_rate equal to a multiple would always
        # result in packets with the same decay counters being sent to the classifier)
        else:
            if self.sampl_pkt_index < self.sampling_rate:
                if self.decay_cntr < 4:
                    self.decay_cntr += 1
                else:
                    self.decay_cntr = 1
                self.sampl_pkt_index += 1
            else:
                self.sampl_pkt_index = 1

        # Hash calculation.
        # CRC16, sliced to 13 bits (0-8191).
        # To each hash value we then sum 8192 * (self.decay_cntr - 1)
        # in order to obtain the current position based on the decay counter value.
        mac_src_bytes = binascii.unhexlify(self.cur_pkt[3].replace(':', ''))
        ip_src_bytes = socket.inet_aton(self.cur_pkt[4])
        ip_dst_bytes = socket.inet_aton(self.cur_pkt[5])
        ip_proto_bytes = struct.pack("!B", int(self.cur_pkt[6]))
        proto_src_bytes = struct.pack("!H", int(self.cur_pkt[7]))
        proto_dst_bytes = struct.pack("!H", int(self.cur_pkt[8]))

        hash_mac_ip_src_temp = self.crc16(mac_src_bytes)
        hash_mac_ip_src_temp = '{:016b}'.format(self.crc16(ip_src_bytes, hash_mac_ip_src_temp))

        self.hash_mac_ip_src = int(hash_mac_ip_src_temp[-13:], 2) + 8192 * (self.decay_cntr - 1)

        hash_ip_src_temp = '{:016b}'.format(self.crc16(ip_src_bytes))
        self.hash_ip_src = int(hash_ip_src_temp[-13:], 2) + 8192 * (self.decay_cntr - 1)

        # Hash xor value is used to access the sum of residual products.
        # Xor is used since the value is the same for both flow directions.

        hash_ip_0_temp = self.crc16(ip_src_bytes)
        hash_ip_0_temp = '{:016b}'.format(self.crc16(ip_dst_bytes, hash_ip_0_temp))
        self.hash_ip_0 = int(hash_ip_0_temp[-13:], 2)

        hash_ip_1_temp = self.crc16(ip_dst_bytes)
        hash_ip_1_temp = '{:016b}'.format(self.crc16(ip_src_bytes, hash_ip_1_temp))
        self.hash_ip_1 = int(hash_ip_1_temp[-13:], 2)

        self.hash_ip_xor = self.hash_ip_0 ^ self.hash_ip_1

        self.hash_ip_0 += 8192 * (self.decay_cntr - 1)
        self.hash_ip_1 += 8192 * (self.decay_cntr - 1)
        self.hash_ip_xor += 8192 * (self.decay_cntr - 1)

        hash_five_t_0_temp = self.crc16(ip_src_bytes)
        hash_five_t_0_temp = self.crc16(ip_dst_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = self.crc16(ip_proto_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = self.crc16(proto_src_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = '{:016b}'.format(self.crc16(proto_dst_bytes, hash_five_t_0_temp))
        self.hash_five_t_0 = int(hash_five_t_0_temp[-13:], 2)

        hash_five_t_1_temp = self.crc16(ip_dst_bytes)
        hash_five_t_1_temp = self.crc16(ip_src_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = self.crc16(ip_proto_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = self.crc16(proto_dst_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = '{:016b}'.format(self.crc16(proto_src_bytes, hash_five_t_1_temp))
        self.hash_five_t_1 = int(hash_five_t_1_temp[-13:], 2)

        self.hash_five_t_xor = self.hash_five_t_0 ^ self.hash_five_t_1

        self.hash_five_t_0 += 8192 * (self.decay_cntr - 1)
        self.hash_five_t_1 += 8192 * (self.decay_cntr - 1)
        self.hash_five_t_xor += 8192 * (self.decay_cntr - 1)

        # Decay check for all flow keys.
        self.decay_check()

        # Calculate the 1D/2D statistics for each flow key.

        # 1D: Mac src, IP src
        mac_ip_src_pkt_cnt = int(self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][0])
        mac_ip_src_mean, mac_ip_src_std_dev = \
            self.stats_calc_1d(mac_ip_src_pkt_cnt,
                               int(self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1]),
                               int(self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2]))
        # 1D: IP src
        ip_src_pkt_cnt = int(self.stats_ip_src[self.hash_ip_src][self.decay_cntr][0])
        ip_src_mean, ip_src_std_dev = \
            self.stats_calc_1d(ip_src_pkt_cnt,
                               int(self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1]),
                               int(self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2]))
        # 1D: IP

        ip_pkt_cnt_0 = int(self.stats_ip[self.hash_ip_0][self.decay_cntr][0])
        ip_pkt_len = int(self.stats_ip[self.hash_ip_0][self.decay_cntr][1])
        ip_pkt_len_sqr = int(self.stats_ip[self.hash_ip_0][self.decay_cntr][2])
        ip_mean_0, ip_std_dev_0 = \
            self.stats_calc_1d(ip_pkt_cnt_0, ip_pkt_len, ip_pkt_len_sqr)

        # Calculate the residual products from flows A->B and B->A.
        ip_res_0 = ip_pkt_len - ip_mean_0
        self.ip_res[self.hash_ip_0][self.decay_cntr-1] = ip_res_0
        if self.hash_ip_1 in self.stats_ip:
            ip_res_1 = int(self.ip_res[self.hash_ip_1][self.decay_cntr-1])
        else:
            ip_res_1 = 0

        # Update the Sum of Residual Products.
        if ip_res_1 != 0 and self.decay_ip == 1:
            self.ip_res_sum[self.hash_ip_xor][self.decay_cntr] += (ip_res_0 << self.pow_2(ip_res_1))

        # Update the counters for flow A->B / Read the counters for flow B->A.
        # Training phase: both are performed for all flows.
        if phase == 'training' or self.sampling_rate == 1:
            self.stats_ip[self.hash_ip_0][self.decay_cntr][3] = ip_pkt_cnt_0
            self.stats_ip[self.hash_ip_0][self.decay_cntr][4] = ip_pkt_len_sqr
            self.stats_ip[self.hash_ip_0][self.decay_cntr][5] = ip_mean_0
            if self.hash_ip_1 in self.stats_ip:
                ip_pkt_cnt_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][3])
                ip_pkt_len_sqr_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][4])
                ip_mean_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][5])
            else:
                ip_pkt_cnt_1 = 0
                ip_pkt_len_sqr_1 = 0
                ip_mean_1 = 0

        # Execution phase: we switch between writing the counters for flow A->B
        # and reading the previously stored counters for flow B->A according to the sampling rate.
        elif self.phase_pkt_index % self.sampling_rate != 0:
            # Update
            self.stats_ip[self.hash_ip_0][self.decay_cntr][3] = ip_pkt_cnt_0
            self.stats_ip[self.hash_ip_0][self.decay_cntr][4] = ip_pkt_len_sqr
            self.stats_ip[self.hash_ip_0][self.decay_cntr][5] = ip_mean_0
        else:
            # Read
            if self.hash_ip_1 in self.stats_ip:
                ip_pkt_cnt_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][3])
                ip_pkt_len_sqr_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][4])
                ip_mean_1 = int(self.stats_ip[self.hash_ip_1][self.decay_cntr][5])
            else:
                ip_pkt_cnt_1 = 0
                ip_pkt_len_sqr_1 = 0
                ip_mean_1 = 0

        # 1D: 5-tuple

        five_t_pkt_cnt_0 = int(self.stats_five_t[self.hash_five_t_0][self.decay_cntr][0])
        five_t_pkt_len = int(self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1])
        five_t_pkt_len_sqr = int(self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2])
        five_t_mean_0, five_t_std_dev_0 = \
            self.stats_calc_1d(five_t_pkt_cnt_0, five_t_pkt_len, five_t_pkt_len_sqr)

        # Calculate the residual products from flows A->B and B->A.
        five_t_res_0 = five_t_pkt_len - five_t_mean_0
        self.five_t_res[self.hash_five_t_0][self.decay_cntr-1] = five_t_res_0
        if self.hash_five_t_1 in self.stats_five_t:
            five_t_res_1 = int(self.five_t_res[self.hash_five_t_1][self.decay_cntr-1])
        else:
            five_t_res_1 = 0

        # Update the Sum of Residual Products.
        if five_t_res_1 != 0 and self.decay_five_t == 1:
            self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr] += (five_t_res_0 << self.pow_2(five_t_res_1))

        # Update the counters for flow A->B / Read the counters for flow B->A.
        # Training phase: both are performed for all flows.
        if phase == 'training' or self.sampling_rate == 1:
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][3] = five_t_pkt_cnt_0
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][4] = five_t_pkt_len_sqr
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][5] = five_t_mean_0
            if self.hash_five_t_1 in self.stats_five_t:
                five_t_pkt_cnt_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][3])
                five_t_pkt_len_sqr_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][4])
                five_t_mean_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][5])
            else:
                five_t_pkt_cnt_1 = 0
                five_t_pkt_len_sqr_1 = 0
                five_t_mean_1 = 0

        # Execution phase: we switch between writing the counters for flow A->B
        # and reading the previously stored counters for flow B->A according to the sampling rate.
        elif self.phase_pkt_index % self.sampling_rate != 0:
            # Update
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][3] = five_t_pkt_cnt_0
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][4] = five_t_pkt_len_sqr
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][5] = five_t_mean_0
        else:
            # Read
            if self.hash_five_t_1 in self.stats_five_t:
                five_t_pkt_cnt_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][3])
                five_t_pkt_len_sqr_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][4])
                five_t_mean_1 = int(self.stats_five_t[self.hash_five_t_1][self.decay_cntr][5])
            else:
                five_t_pkt_cnt_1 = 0
                five_t_pkt_len_sqr_1 = 0
                five_t_mean_1 = 0

        # 2D: IP

        ip_variance_0 = abs((ip_pkt_len_sqr >> self.pow_2(ip_pkt_cnt_0))
                            - sqr.compute(ip_mean_0))

        if phase == 'training' or self.phase_pkt_index % self.sampling_rate == 0:
            ip_variance_1 = abs((ip_pkt_len_sqr_1 >> self.pow_2(ip_pkt_cnt_1))
                                - sqr.compute(ip_mean_1))
            ip_std_dev_1 = sqrt_mu.compute(ip_variance_1)
            ip_magnitude, ip_radius, ip_cov, ip_pcc \
                = self.stats_calc_2d(ip_pkt_cnt_0, ip_pkt_cnt_1, ip_mean_0, ip_mean_1,
                                     int(self.ip_res_sum[self.hash_ip_xor][self.decay_cntr]),
                                     ip_variance_0, ip_variance_1, ip_std_dev_0, ip_std_dev_1)
        else:
            ip_magnitude = 0
            ip_radius = 0
            ip_cov = 0
            ip_pcc = 0

        # 2D: 5-tuple

        five_t_variance_0 = abs((five_t_pkt_len_sqr >> self.pow_2(five_t_pkt_cnt_0))
                                - sqr.compute(five_t_mean_0))

        if phase == 'training' or self.phase_pkt_index % self.sampling_rate == 0:
            five_t_variance_1 = abs((five_t_pkt_len_sqr_1 >> self.pow_2(five_t_pkt_cnt_1))
                                    - sqr.compute(five_t_mean_1))
            five_t_std_dev_1 = sqrt_mu.compute(five_t_variance_1)
            five_t_magnitude, five_t_radius, five_t_cov, five_t_pcc \
                = self.stats_calc_2d(five_t_pkt_cnt_0, five_t_pkt_cnt_1,
                                     five_t_mean_0, five_t_mean_1,
                                     int(self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr]),
                                     five_t_variance_0, five_t_variance_1,
                                     five_t_std_dev_0, five_t_std_dev_1)
        else:
            five_t_magnitude = 0
            five_t_radius = 0
            five_t_cov = 0
            five_t_pcc = 0

        # Send to KitNet
        cur_stats = [self.decay_cntr,
                     int(mac_ip_src_pkt_cnt), int(mac_ip_src_mean), int(mac_ip_src_std_dev),
                     int(ip_src_pkt_cnt), int(ip_src_mean), int(ip_src_std_dev),
                     int(ip_pkt_cnt_0), int(ip_mean_0), int(ip_std_dev_0),
                     int(ip_magnitude), int(ip_radius), int(ip_cov), int(ip_pcc),
                     int(five_t_pkt_cnt_0), int(five_t_mean_0), int(five_t_std_dev_0),
                     int(five_t_magnitude), int(five_t_radius), int(five_t_cov), int(five_t_pcc)]

        self.cur_pkt = self.cur_pkt[3:]

        return [self.cur_pkt, cur_stats]

    def process_exact(self, phase):
        # Update the current decay counter value.
        # If we're in the training phase or the sampling rate is 1,
        # simply alternate the decay counter values.
        if phase == 'training' or self.sampling_rate == 1:
            if self.decay_cntr < 4:
                self.decay_cntr += 1
            else:
                self.decay_cntr = 1
        # Else, for every epoch we must skip a decay counter change.
        # This is necessary to ensure that the sampled packets keep
        # alternating the decay counter values.
        # (As we have 4 decay values, any sampling_rate equal to a multiple would always
        # result in packets with the same decay counters being sent to the classifier)
        else:
            if self.sampl_pkt_index < self.sampling_rate:
                if self.decay_cntr < 4:
                    self.decay_cntr += 1
                else:
                    self.decay_cntr = 1
                self.sampl_pkt_index += 1
            else:
                self.sampl_pkt_index = 1

        # Hash calculation.
        # CRC16, sliced to 13 bits (0-8191).
        # To each hash value we then sum 8192 * (self.decay_cntr - 1)
        # in order to obtain the current position based on the decay counter value.
        mac_src_bytes = binascii.unhexlify(self.cur_pkt[3].replace(':', ''))
        ip_src_bytes = socket.inet_aton(self.cur_pkt[4])
        ip_dst_bytes = socket.inet_aton(self.cur_pkt[5])
        ip_proto_bytes = struct.pack("!B", int(self.cur_pkt[6]))
        proto_src_bytes = struct.pack("!H", int(self.cur_pkt[7]))
        proto_dst_bytes = struct.pack("!H", int(self.cur_pkt[8]))

        hash_mac_ip_src_temp = self.crc16(mac_src_bytes)
        hash_mac_ip_src_temp = '{:016b}'.format(self.crc16(ip_src_bytes, hash_mac_ip_src_temp))
        self.hash_mac_ip_src = int(hash_mac_ip_src_temp[-13:], 2) + 8192 * (self.decay_cntr - 1)

        hash_ip_src_temp = '{:016b}'.format(self.crc16(ip_src_bytes))
        self.hash_ip_src = int(hash_ip_src_temp[-13:], 2) + 8192 * (self.decay_cntr - 1)

        # Hash xor value is used to access the sum of residual products.
        # Xor is used since the value is the same for both flow directions.

        hash_ip_0_temp = self.crc16(ip_src_bytes)
        hash_ip_0_temp = '{:016b}'.format(self.crc16(ip_dst_bytes, hash_ip_0_temp))
        self.hash_ip_0 = int(hash_ip_0_temp[-13:], 2)

        hash_ip_1_temp = self.crc16(ip_dst_bytes)
        hash_ip_1_temp = '{:016b}'.format(self.crc16(ip_src_bytes, hash_ip_1_temp))
        self.hash_ip_1 = int(hash_ip_1_temp[-13:], 2)

        self.hash_ip_xor = self.hash_ip_0 ^ self.hash_ip_1

        self.hash_ip_0 += 8192 * (self.decay_cntr - 1)
        self.hash_ip_1 += 8192 * (self.decay_cntr - 1)
        self.hash_ip_xor += 8192 * (self.decay_cntr - 1)

        hash_five_t_0_temp = self.crc16(ip_src_bytes)
        hash_five_t_0_temp = self.crc16(ip_dst_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = self.crc16(ip_proto_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = self.crc16(proto_src_bytes, hash_five_t_0_temp)
        hash_five_t_0_temp = '{:016b}'.format(self.crc16(proto_dst_bytes, hash_five_t_0_temp))
        self.hash_five_t_0 = int(hash_five_t_0_temp[-13:], 2)

        hash_five_t_1_temp = self.crc16(ip_dst_bytes)
        hash_five_t_1_temp = self.crc16(ip_src_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = self.crc16(ip_proto_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = self.crc16(proto_dst_bytes, hash_five_t_1_temp)
        hash_five_t_1_temp = '{:016b}'.format(self.crc16(proto_src_bytes, hash_five_t_1_temp))
        self.hash_five_t_1 = int(hash_five_t_1_temp[-13:], 2)

        self.hash_five_t_xor = self.hash_five_t_0 ^ self.hash_five_t_1

        self.hash_five_t_0 += 8192 * (self.decay_cntr - 1)
        self.hash_five_t_1 += 8192 * (self.decay_cntr - 1)
        self.hash_five_t_xor += 8192 * (self.decay_cntr - 1)

        # Decay check for all flow keys.
        self.decay_check_exact()

        # Calculate the 1D/2D statistics for each flow key.

        # 1D: Mac src, IP src
        mac_ip_src_pkt_cnt = self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][0]
        mac_ip_src_mean, mac_ip_src_std_dev = self.stats_calc_1d_exact(
                mac_ip_src_pkt_cnt,
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1],
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2])

        # 1D: IP src
        ip_src_pkt_cnt = self.stats_ip_src[self.hash_ip_src][self.decay_cntr][0]
        ip_src_mean, ip_src_std_dev = self.stats_calc_1d_exact(
            ip_src_pkt_cnt,
            self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1],
            self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2])
        # 1D: IP

        ip_pkt_cnt_0 = self.stats_ip[self.hash_ip_0][self.decay_cntr][0]
        ip_pkt_len = self.stats_ip[self.hash_ip_0][self.decay_cntr][1]
        ip_pkt_len_sqr = self.stats_ip[self.hash_ip_0][self.decay_cntr][2]
        ip_mean_0, ip_std_dev_0 = self.stats_calc_1d_exact(
                ip_pkt_cnt_0,
                ip_pkt_len,
                ip_pkt_len_sqr)

        # Calculate the residual products from flows A->B and B->A.
        ip_res_0 = ip_pkt_len - ip_mean_0
        self.ip_res[self.hash_ip_0][self.decay_cntr-1] = ip_res_0
        if self.hash_ip_1 in self.stats_ip:
            ip_res_1 = self.ip_res[self.hash_ip_1][self.decay_cntr-1]
        else:
            ip_res_1 = 0

        # Update the Sum of Residual Products.
        if ip_res_1 != 0 and self.decay_ip == 1:
            self.ip_res_sum[self.hash_ip_xor][self.decay_cntr] += (ip_res_0 * ip_res_1)

        # Update the counters for flow A->B / Read the counters for flow B->A.
        # Training phase: both are performed for all flows.
        if phase == 'training' or self.sampling_rate == 1:
            self.stats_ip[self.hash_ip_0][self.decay_cntr][3] = ip_pkt_cnt_0
            self.stats_ip[self.hash_ip_0][self.decay_cntr][4] = ip_pkt_len_sqr
            self.stats_ip[self.hash_ip_0][self.decay_cntr][5] = ip_mean_0
            if self.hash_ip_1 in self.stats_ip:
                ip_pkt_cnt_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][3]
                ip_pkt_len_sqr_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][4]
                ip_mean_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][5]
            else:
                ip_pkt_cnt_1 = 0
                ip_pkt_len_sqr_1 = 0
                ip_mean_1 = 0

        # Execution phase: we switch between writing the counters for flow A->B
        # and reading the previously stored counters for flow B->A according to the sampling rate.
        elif self.phase_pkt_index % self.sampling_rate != 0:
            # Update
            self.stats_ip[self.hash_ip_0][self.decay_cntr][3] = ip_pkt_cnt_0
            self.stats_ip[self.hash_ip_0][self.decay_cntr][4] = ip_pkt_len_sqr
            self.stats_ip[self.hash_ip_0][self.decay_cntr][5] = ip_mean_0
        else:
            # Read
            if self.hash_ip_1 in self.stats_ip:
                ip_pkt_cnt_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][3]
                ip_pkt_len_sqr_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][4]
                ip_mean_1 = self.stats_ip[self.hash_ip_1][self.decay_cntr][5]
            else:
                ip_pkt_cnt_1 = 0
                ip_pkt_len_sqr_1 = 0
                ip_mean_1 = 0

        # 1D: 5-tuple

        five_t_pkt_cnt_0 = self.stats_five_t[self.hash_five_t_0][self.decay_cntr][0]
        five_t_pkt_len = self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1]
        five_t_pkt_len_sqr = self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2]
        five_t_mean_0, five_t_std_dev_0 = \
            self.stats_calc_1d_exact(
                five_t_pkt_cnt_0,
                five_t_pkt_len,
                five_t_pkt_len_sqr)

        # Calculate the residual products from flows A->B and B->A.
        five_t_res_0 = five_t_pkt_len - five_t_mean_0
        self.five_t_res[self.hash_five_t_0][self.decay_cntr-1] = five_t_res_0
        if self.hash_five_t_1 in self.stats_five_t:
            five_t_res_1 = self.five_t_res[self.hash_five_t_1][self.decay_cntr-1]
        else:
            five_t_res_1 = 0

        # Update the Sum of Residual Products.
        if five_t_res_1 != 0 and self.decay_five_t == 1:
            self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr] += \
                (five_t_res_0 * five_t_res_1)

        # Update the counters for flow A->B / Read the counters for flow B->A.
        # Training phase: both are performed for all flows.
        if phase == 'training' or self.sampling_rate == 1:
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][3] = five_t_pkt_cnt_0
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][4] = five_t_pkt_len_sqr
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][5] = five_t_mean_0
            if self.hash_five_t_1 in self.stats_five_t:
                five_t_pkt_cnt_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][3]
                five_t_pkt_len_sqr_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][4]
                five_t_mean_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][5]
            else:
                five_t_pkt_cnt_1 = 0
                five_t_pkt_len_sqr_1 = 0
                five_t_mean_1 = 0

        # Execution phase: we switch between writing the counters for flow A->B
        # and reading the previously stored counters for flow B->A according to the sampling rate.
        elif self.phase_pkt_index % self.sampling_rate != 0:
            # Update
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][3] = five_t_pkt_cnt_0
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][4] = five_t_pkt_len_sqr
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][5] = five_t_mean_0
        else:
            # Read
            if self.hash_five_t_1 in self.stats_five_t:
                five_t_pkt_cnt_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][3]
                five_t_pkt_len_sqr_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][4]
                five_t_mean_1 = self.stats_five_t[self.hash_five_t_1][self.decay_cntr][5]
            else:
                five_t_pkt_cnt_1 = 0
                five_t_pkt_len_sqr_1 = 0
                five_t_mean_1 = 0

        # 2D: IP

        ip_variance_0 = abs((ip_pkt_len_sqr / ip_pkt_cnt_0) - pow(ip_mean_0, 2))

        if phase == 'training' or self.phase_pkt_index % self.sampling_rate == 0:
            if ip_pkt_cnt_1 != 0:
                ip_variance_1 = abs((ip_pkt_len_sqr_1 / ip_pkt_cnt_1) - pow(ip_mean_1, 2))
            else:
                ip_variance_1 = 0
            ip_std_dev_1 = sqrt(ip_variance_1)
            ip_magnitude, ip_radius, ip_cov, ip_pcc \
                = self.stats_calc_2d_exact(
                    ip_pkt_cnt_0, ip_pkt_cnt_1, ip_mean_0, ip_mean_1,
                    self.ip_res_sum[self.hash_ip_xor][self.decay_cntr],
                    ip_variance_0, ip_variance_1, ip_std_dev_0, ip_std_dev_1)
        else:
            ip_magnitude = 0
            ip_radius = 0
            ip_cov = 0
            ip_pcc = 0

        # 2D: 5-tuple

        five_t_variance_0 = abs((five_t_pkt_len_sqr / five_t_pkt_cnt_0)
                                - pow(five_t_mean_0, 2))

        if phase == 'training' or self.phase_pkt_index % self.sampling_rate == 0:
            if five_t_pkt_cnt_1 != 0:
                five_t_variance_1 = abs((five_t_pkt_len_sqr_1 / five_t_pkt_cnt_1)
                                        - pow(five_t_mean_1, 2))
            else:
                five_t_variance_1 = 0
            five_t_std_dev_1 = sqrt(five_t_variance_1)
            five_t_magnitude, five_t_radius, five_t_cov, five_t_pcc \
                = self.stats_calc_2d_exact(
                    five_t_pkt_cnt_0, five_t_pkt_cnt_1,
                    five_t_mean_0, five_t_mean_1,
                    self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr],
                    five_t_variance_0, five_t_variance_1,
                    five_t_std_dev_0, five_t_std_dev_1)
        else:
            five_t_magnitude = 0
            five_t_radius = 0
            five_t_cov = 0
            five_t_pcc = 0

        cur_stats = [self.decay_cntr,
                     int(mac_ip_src_pkt_cnt), int(mac_ip_src_mean), int(mac_ip_src_std_dev),
                     int(ip_src_pkt_cnt), int(ip_src_mean), int(ip_src_std_dev),
                     int(ip_pkt_cnt_0), int(ip_mean_0), int(ip_std_dev_0),
                     int(ip_magnitude), int(ip_radius), int(ip_cov), int(ip_pcc),
                     int(five_t_pkt_cnt_0), int(five_t_mean_0), int(five_t_std_dev_0),
                     int(five_t_magnitude), int(five_t_radius), int(five_t_cov), int(five_t_pcc)]

        self.cur_pkt = self.cur_pkt[3:]

        return [self.cur_pkt, cur_stats]

    def stats_calc_1d(self, pkt_cnt, pkt_len, pkt_len_sqr):
        # Mean
        mean = pkt_len >> self.pow_2(pkt_cnt)

        # Std. Dev
        std_dev = int(sqrt_mu.compute(abs((pkt_len_sqr >> self.pow_2(pkt_cnt)) - sqr.compute(mean))))

        return [mean, std_dev]

    def stats_calc_1d_exact(self, pkt_cnt, pkt_len, pkt_len_sqr):
        # Mean
        mean = pkt_len / pkt_cnt

        # Std. Dev.
        std_dev = sqrt(abs((pkt_len_sqr / pkt_cnt) - pow(mean, 2)))

        return [mean, std_dev]

    def stats_calc_2d(self, pkt_cnt_0, pkt_cnt_1, mean_0, mean_1, res_sum, variance_0,
                      variance_1, std_dev_0, std_dev_1):
        # Magnitude
        magnitude = sqrt_mu.compute(sqr.compute(mean_0) + sqr.compute(mean_1))

        # Radius
        radius = sqrt_mu.compute(sqr.compute(variance_0) + sqr.compute(variance_1))

        # Covariance
        cov = res_sum >> self.pow_2(pkt_cnt_0 + pkt_cnt_1)

        # PCC
        if self.pow_2(std_dev_1) != 0 and self.pow_2(std_dev_0 << self.pow_2(std_dev_1)) != 0:
            pcc = cov >> self.pow_2(std_dev_0 << self.pow_2(std_dev_1))
        else:
            pcc = 0

        return [magnitude, radius, cov, pcc]

    def stats_calc_2d_exact(self, pkt_cnt_0, pkt_cnt_1, mean_0, mean_1, res_sum, variance_0,
                            variance_1, std_dev_0, std_dev_1):
        # Magnitude
        magnitude = sqrt(pow(mean_0, 2) + pow(mean_1, 2))

        # Radius
        radius = sqrt(pow(variance_0, 2) + pow(variance_1, 2))

        # Covariance
        cov = res_sum / (pkt_cnt_0 + pkt_cnt_1)

        # PCC
        if std_dev_1 != 0 and std_dev_0 * std_dev_1 != 0:
            pcc = cov / (std_dev_0 * std_dev_1)
        else:
            pcc = 0

        return [magnitude, radius, cov, pcc]

    def decay_check(self):

        # IP and five t flow keys require the decay status during later stats calculation.
        self.decay_ip = 1
        self.decay_five_t = 1

        # MAC src, IP src

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_mac_ip_src in self.stats_mac_ip_src:
            mac_ip_src_ts_interval = \
                self.cur_pkt[1] - self.stats_mac_ip_src[self.hash_mac_ip_src][0][self.decay_cntr-1]

            decay = 1

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.
            if self.stats_mac_ip_src[self.hash_mac_ip_src][0][self.decay_cntr-1]:
                if self.decay_cntr == 1 and mac_ip_src_ts_interval > 0.1:
                    decay = 0.5
                    self.stats_mac_ip_src[self.hash_mac_ip_src][0][0] += 0.1
                elif self.decay_cntr == 2 and mac_ip_src_ts_interval > 1:
                    decay = 0.5
                    self.stats_mac_ip_src[self.hash_mac_ip_src][0][1] += 1
                elif self.decay_cntr == 3 and mac_ip_src_ts_interval > 10:
                    decay = 0.5
                    self.stats_mac_ip_src[self.hash_mac_ip_src][0][2] += 10
                elif self.decay_cntr == 4 and mac_ip_src_ts_interval > 60:
                    decay = 0.5
                    self.stats_mac_ip_src[self.hash_mac_ip_src][0][3] += 60
                else:
                    self.stats_mac_ip_src[self.hash_mac_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]
            else:
                self.stats_mac_ip_src[self.hash_mac_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][0] = \
                int(decay * self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][0] + 1)

            # If the decay will not be applied, simply update the values from the current pkt.
            # Else, update the values with the current decay factor.
            if decay == 1:
                # Pkt length.
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1] = \
                    int(self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1] + self.cur_pkt[0])
                # Pkt length squared.
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2] = \
                    int(self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2] + sqr.compute(self.cur_pkt[0]))
            else:
                # Pkt length.
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1] = \
                    int(decay * self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][1])
                # Pkt length squared.
                self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2] = \
                    int(decay * self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr][2])

        else:
            self.stats_mac_ip_src[self.hash_mac_ip_src] = ([[0, 0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0]])
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][self.decay_cntr] = \
                [1, self.cur_pkt[0], sqr.compute(self.cur_pkt[0])]

        # IP src

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_ip_src in self.stats_ip_src:
            ip_src_ts_interval = self.cur_pkt[1] - self.stats_ip_src[self.hash_ip_src][0][self.decay_cntr-1]

            decay = 1

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.
            if self.stats_ip_src[self.hash_ip_src][0][self.decay_cntr-1]:
                if self.decay_cntr == 1 and ip_src_ts_interval > 0.1:
                    decay = 0.5
                    self.stats_ip_src[self.hash_ip_src][0][0] += 0.1
                elif self.decay_cntr == 2 and ip_src_ts_interval > 1:
                    decay = 0.5
                    self.stats_ip_src[self.hash_ip_src][0][1] += 1
                elif self.decay_cntr == 3 and ip_src_ts_interval > 10:
                    decay = 0.5
                    self.stats_ip_src[self.hash_ip_src][0][2] += 10
                elif self.decay_cntr == 4 and ip_src_ts_interval > 60:
                    decay = 0.5
                    self.stats_ip_src[self.hash_ip_src][0][3] += 60
                else:
                    self.stats_ip_src[self.hash_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]
            else:
                self.stats_ip_src[self.hash_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_ip_src[self.hash_ip_src][self.decay_cntr][0] = \
                int(decay * self.stats_ip_src[self.hash_ip_src][self.decay_cntr][0] + 1)

            # If the decay will not be applied, simply update the values from the current pkt.
            # Else, update the values with the current decay factor.
            if decay == 1:
                # Pkt length.
                self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1] = \
                    int(self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1] + self.cur_pkt[0])
                # Pkt length squared.
                self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2] = \
                    int(self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2] + sqr.compute(self.cur_pkt[0]))
            else:
                # Pkt length.
                self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1] = \
                    int(decay * self.stats_ip_src[self.hash_ip_src][self.decay_cntr][1])
                # Pkt length squared.
                self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2] = \
                    int(decay * self.stats_ip_src[self.hash_ip_src][self.decay_cntr][2])

        else:
            self.stats_ip_src[self.hash_ip_src] = ([[0, 0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0]])
            self.stats_ip_src[self.hash_ip_src][0][self.decay_cntr-1] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][self.decay_cntr] = \
                [1, self.cur_pkt[0], sqr.compute(self.cur_pkt[0])]

        # IP

        if self.hash_ip_0 not in self.ip_res:
            self.ip_res[self.hash_ip_0] = [0, 0, 0, 0]

        if self.hash_ip_xor not in self.ip_res_sum:
            self.ip_res_sum[self.hash_ip_xor] = ([[0, 0, 0, 0], 0, 0, 0, 0])

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_ip_0 in self.stats_ip:
            ip_ts_interval = self.cur_pkt[1] - self.stats_ip[self.hash_ip_0][0][self.decay_cntr-1]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.
            if self.stats_ip[self.hash_ip_0][0][self.decay_cntr-1]:
                if self.decay_cntr == 1 and ip_ts_interval > 0.1:
                    self.decay_ip = 0.5
                    self.stats_ip[self.hash_ip_0][0][0] += 0.1
                    self.ip_res_sum[self.hash_ip_xor][0][0] += 0.1
                elif self.decay_cntr == 2 and ip_ts_interval > 1:
                    self.decay_ip = 0.5
                    self.stats_ip[self.hash_ip_0][0][1] += 1
                    self.ip_res_sum[self.hash_ip_xor][0][1] += 1
                elif self.decay_cntr == 3 and ip_ts_interval > 10:
                    self.decay_ip = 0.5
                    self.stats_ip[self.hash_ip_0][0][2] += 10
                    self.ip_res_sum[self.hash_ip_xor][0][2] += 10
                elif self.decay_cntr == 4 and ip_ts_interval > 60:
                    self.decay_ip = 0.5
                    self.stats_ip[self.hash_ip_0][0][3] += 60
                    self.ip_res_sum[self.hash_ip_xor][0][3] += 60
                else:
                    self.stats_ip[self.hash_ip_0][0][self.decay_cntr-1] = self.cur_pkt[1]
                    self.ip_res_sum[self.hash_ip_xor][0][self.decay_cntr-1] = self.cur_pkt[1]
            else:
                self.stats_ip[self.hash_ip_0][0][self.decay_cntr-1] = self.cur_pkt[1]
                self.ip_res_sum[self.hash_ip_xor][0][self.decay_cntr-1] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_ip[self.hash_ip_0][self.decay_cntr][0] = \
                int(self.decay_ip * self.stats_ip[self.hash_ip_0][self.decay_cntr][0] + 1)

            # If the decay will not be applied, simply update the values from the current pkt.
            # Else, update the values with the current decay factor.
            if self.decay_ip == 1:
                # Pkt length.
                self.stats_ip[self.hash_ip_0][self.decay_cntr][1] = \
                    int(self.stats_ip[self.hash_ip_0][self.decay_cntr][1] + self.cur_pkt[0])
                # Pkt length squared.
                self.stats_ip[self.hash_ip_0][self.decay_cntr][2] = \
                    int(self.stats_ip[self.hash_ip_0][self.decay_cntr][2] + sqr.compute(self.cur_pkt[0]))
            else:
                # Pkt length.
                self.stats_ip[self.hash_ip_0][self.decay_cntr][1] = \
                    int(self.decay_ip * self.stats_ip[self.hash_ip_0][self.decay_cntr][1])
                # Pkt length squared.
                self.stats_ip[self.hash_ip_0][self.decay_cntr][2] = \
                    int(self.decay_ip * self.stats_ip[self.hash_ip_0][self.decay_cntr][2])
                # Sum of residual products.
                self.ip_res_sum[self.hash_ip_xor][self.decay_cntr] = \
                    int(self.decay_ip * self.ip_res_sum[self.hash_ip_xor][self.decay_cntr])

        else:
            self.stats_ip[self.hash_ip_0] = ([[0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0]])
            self.stats_ip[self.hash_ip_0][0][self.decay_cntr-1] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][self.decay_cntr] = \
                [1, self.cur_pkt[0], sqr.compute(self.cur_pkt[0]), 0, 0, 0]

        # Five tuple

        if self.hash_five_t_0 not in self.five_t_res:
            self.five_t_res[self.hash_five_t_0] = [0, 0, 0, 0]

        if self.hash_five_t_xor not in self.five_t_res_sum:
            self.five_t_res_sum[self.hash_five_t_xor] = ([[0, 0, 0, 0], 0, 0, 0, 0])

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_five_t_0 in self.stats_five_t:
            five_t_ts_interval = \
                self.cur_pkt[1] - self.stats_five_t[self.hash_five_t_0][0][self.decay_cntr-1]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.
            if self.stats_five_t[self.hash_five_t_0][0][self.decay_cntr-1]:
                if self.decay_cntr == 1 and five_t_ts_interval > 0.1:
                    self.decay_five_t = 0.5
                    self.stats_five_t[self.hash_five_t_0][0][0] += 0.1
                    self.five_t_res_sum[self.hash_five_t_xor][0][0] += 0.1
                elif self.decay_cntr == 2 and five_t_ts_interval > 1:
                    self.decay_five_t = 0.5
                    self.stats_five_t[self.hash_five_t_0][0][1] += 1
                    self.five_t_res_sum[self.hash_five_t_xor][0][1] += 1
                elif self.decay_cntr == 3 and five_t_ts_interval > 10:
                    self.decay_five_t = 0.5
                    self.stats_five_t[self.hash_five_t_0][0][2] += 10
                    self.five_t_res_sum[self.hash_five_t_xor][0][2] += 10
                elif self.decay_cntr == 4 and five_t_ts_interval > 60:
                    self.decay_five_t = 0.5
                    self.stats_five_t[self.hash_five_t_0][0][3] += 60
                    self.five_t_res_sum[self.hash_five_t_xor][0][3] += 60
                else:
                    self.stats_five_t[self.hash_five_t_0][0][self.decay_cntr-1] = self.cur_pkt[1]
                    self.five_t_res_sum[self.hash_five_t_xor][0][self.decay_cntr-1] = \
                        self.cur_pkt[1]
            else:
                self.stats_five_t[self.hash_five_t_0][0][self.decay_cntr-1] = self.cur_pkt[1]
                self.five_t_res_sum[self.hash_five_t_xor][0][self.decay_cntr-1] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr][0] = \
                int(self.decay_five_t *
                    self.stats_five_t[self.hash_five_t_0][self.decay_cntr][0] + 1)

            # If the decay will not be applied, simply update the values from the current pkt.
            # Else, update the values with the current decay factor.
            if self.decay_five_t == 1:
                # Pkt length.
                self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1] = \
                    int(self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1] + self.cur_pkt[0])
                # Pkt length squared.
                self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2] = \
                    int(self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2] +
                        sqr.compute(self.cur_pkt[0]))
            else:
                # Pkt length.
                self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1] = \
                    int(self.decay_five_t *
                        self.stats_five_t[self.hash_five_t_0][self.decay_cntr][1])
                # Pkt length squared.
                self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2] = \
                    int(self.decay_five_t *
                        self.stats_five_t[self.hash_five_t_0][self.decay_cntr][2])
                # Sum of residual products.
                self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr] = \
                    int(self.decay_five_t * self.five_t_res_sum[self.hash_five_t_xor][self.decay_cntr])

        else:
            self.stats_five_t[self.hash_five_t_0] = ([[0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0]])
            self.stats_five_t[self.hash_five_t_0][0][self.decay_cntr-1] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][self.decay_cntr] = \
                [1, self.cur_pkt[0], sqr.compute(self.cur_pkt[0]), 0, 0, 0]

    def decay_check_exact(self):

        # IP and five t flow keys require the decay status during later stats calculation.
        self.decay_ip = 1
        self.decay_five_t = 1

        # MAC src, IP src

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_mac_ip_src in self.stats_mac_ip_src:
            mac_ip_src_ts_interval_0 = \
                self.cur_pkt[1] - self.stats_mac_ip_src[self.hash_mac_ip_src][0][0]
            mac_ip_src_ts_interval_1 = \
                self.cur_pkt[1] - self.stats_mac_ip_src[self.hash_mac_ip_src][0][1]
            mac_ip_src_ts_interval_2 = \
                self.cur_pkt[1] - self.stats_mac_ip_src[self.hash_mac_ip_src][0][2]
            mac_ip_src_ts_interval_3 = \
                self.cur_pkt[1] - self.stats_mac_ip_src[self.hash_mac_ip_src][0][3]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.

            self.stats_mac_ip_src[self.hash_mac_ip_src][0][0] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][1] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][2] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][3] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_mac_ip_src[self.hash_mac_ip_src][1][0] = \
                pow(2, (-10 * mac_ip_src_ts_interval_0)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][1][0] + 1
            self.stats_mac_ip_src[self.hash_mac_ip_src][2][0] = \
                pow(2, (-1 * mac_ip_src_ts_interval_1)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][2][0] + 1
            self.stats_mac_ip_src[self.hash_mac_ip_src][3][0] = \
                pow(2, (-0.1 * mac_ip_src_ts_interval_2)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][3][0] + 1
            self.stats_mac_ip_src[self.hash_mac_ip_src][4][0] = \
                pow(2, (-(1/60) * mac_ip_src_ts_interval_3)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][4][0] + 1

            # Decay factor: pkt length.
            self.stats_mac_ip_src[self.hash_mac_ip_src][1][1] = \
                pow(2, (-10 * mac_ip_src_ts_interval_0)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][1][1] + self.cur_pkt[0]
            self.stats_mac_ip_src[self.hash_mac_ip_src][2][1] = \
                pow(2, (-1 * mac_ip_src_ts_interval_1)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][2][1] + self.cur_pkt[0]
            self.stats_mac_ip_src[self.hash_mac_ip_src][3][1] = \
                pow(2, (-0.1 * mac_ip_src_ts_interval_2)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][3][1] + self.cur_pkt[0]
            self.stats_mac_ip_src[self.hash_mac_ip_src][4][1] = \
                pow(2, (-(1/60) * mac_ip_src_ts_interval_3)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][4][1] + self.cur_pkt[0]

            # Decay factor: pkt length squared.
            self.stats_mac_ip_src[self.hash_mac_ip_src][1][2] = \
                pow(2, (-10 * mac_ip_src_ts_interval_0)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][1][2] + pow(self.cur_pkt[0], 2)
            self.stats_mac_ip_src[self.hash_mac_ip_src][2][2] = \
                pow(2, (-1 * mac_ip_src_ts_interval_1)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][2][2] + pow(self.cur_pkt[0], 2)
            self.stats_mac_ip_src[self.hash_mac_ip_src][3][2] = \
                pow(2, (-0.1 * mac_ip_src_ts_interval_2)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][3][2] + pow(self.cur_pkt[0], 2)
            self.stats_mac_ip_src[self.hash_mac_ip_src][4][2] = \
                pow(2, (-(1/60) * mac_ip_src_ts_interval_3)) * \
                self.stats_mac_ip_src[self.hash_mac_ip_src][4][2] + pow(self.cur_pkt[0], 2)
        else:
            self.stats_mac_ip_src[self.hash_mac_ip_src] = ([[0, 0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0],
                                                            [0, 0, 0]])
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][0] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][1] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][2] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][0][3] = self.cur_pkt[1]
            self.stats_mac_ip_src[self.hash_mac_ip_src][1] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_mac_ip_src[self.hash_mac_ip_src][2] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_mac_ip_src[self.hash_mac_ip_src][3] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_mac_ip_src[self.hash_mac_ip_src][4] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]

        # IP src

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_ip_src in self.stats_ip_src:
            ip_src_ts_interval_0 = \
                self.cur_pkt[1] - self.stats_ip_src[self.hash_ip_src][0][0]
            ip_src_ts_interval_1 = \
                self.cur_pkt[1] - self.stats_ip_src[self.hash_ip_src][0][1]
            ip_src_ts_interval_2 = \
                self.cur_pkt[1] - self.stats_ip_src[self.hash_ip_src][0][2]
            ip_src_ts_interval_3 = \
                self.cur_pkt[1] - self.stats_ip_src[self.hash_ip_src][0][3]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.

            self.stats_ip_src[self.hash_ip_src][0][0] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][1] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][2] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][3] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_ip_src[self.hash_ip_src][1][0] = \
                pow(2, (-10 * ip_src_ts_interval_0)) * \
                self.stats_ip_src[self.hash_ip_src][1][0] + 1
            self.stats_ip_src[self.hash_ip_src][2][0] = \
                pow(2, (-1 * ip_src_ts_interval_1)) * \
                self.stats_ip_src[self.hash_ip_src][2][0] + 1
            self.stats_ip_src[self.hash_ip_src][3][0] = \
                pow(2, (-0.1 * ip_src_ts_interval_2)) * \
                self.stats_ip_src[self.hash_ip_src][3][0] + 1
            self.stats_ip_src[self.hash_ip_src][4][0] = \
                pow(2, (-(1/60) * ip_src_ts_interval_3)) * \
                self.stats_ip_src[self.hash_ip_src][4][0] + 1

            # Decay factor: pkt length.
            self.stats_ip_src[self.hash_ip_src][1][1] = \
                pow(2, (-10 * ip_src_ts_interval_0)) * \
                self.stats_ip_src[self.hash_ip_src][1][1] + self.cur_pkt[0]
            self.stats_ip_src[self.hash_ip_src][2][1] = \
                pow(2, (-1 * ip_src_ts_interval_1)) * \
                self.stats_ip_src[self.hash_ip_src][2][1] + self.cur_pkt[0]
            self.stats_ip_src[self.hash_ip_src][3][1] = \
                pow(2, (-0.1 * ip_src_ts_interval_2)) * \
                self.stats_ip_src[self.hash_ip_src][3][1] + self.cur_pkt[0]
            self.stats_ip_src[self.hash_ip_src][4][1] = \
                pow(2, (-(1/60) * ip_src_ts_interval_3)) * \
                self.stats_ip_src[self.hash_ip_src][4][1] + self.cur_pkt[0]

            # Decay factor: pkt length squared.
            self.stats_ip_src[self.hash_ip_src][1][2] = \
                pow(2, (-10 * ip_src_ts_interval_0)) * \
                self.stats_ip_src[self.hash_ip_src][1][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip_src[self.hash_ip_src][2][2] = \
                pow(2, (-1 * ip_src_ts_interval_1)) * \
                self.stats_ip_src[self.hash_ip_src][2][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip_src[self.hash_ip_src][3][2] = \
                pow(2, (-0.1 * ip_src_ts_interval_2)) * \
                self.stats_ip_src[self.hash_ip_src][3][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip_src[self.hash_ip_src][4][2] = \
                pow(2, (-(1/60) * ip_src_ts_interval_3)) * \
                self.stats_ip_src[self.hash_ip_src][4][2] + pow(self.cur_pkt[0], 2)
        else:
            self.stats_ip_src[self.hash_ip_src] = ([[0, 0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0],
                                                    [0, 0, 0]])
            self.stats_ip_src[self.hash_ip_src][0][0] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][1] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][2] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][0][3] = self.cur_pkt[1]
            self.stats_ip_src[self.hash_ip_src][1] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_ip_src[self.hash_ip_src][2] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_ip_src[self.hash_ip_src][3] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]
            self.stats_ip_src[self.hash_ip_src][4] = \
                [1,
                 self.cur_pkt[0],
                 pow(self.cur_pkt[0], 2)]

        # IP

        if self.hash_ip_0 not in self.ip_res:
            self.ip_res[self.hash_ip_0] = [0, 0, 0, 0]

        if self.hash_ip_xor not in self.ip_res_sum:
            self.ip_res_sum[self.hash_ip_xor] = ([[0, 0, 0, 0], 0, 0, 0, 0])

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_ip_0 in self.stats_ip:
            ip_ts_interval_0 = \
                self.cur_pkt[1] - self.stats_ip[self.hash_ip_0][0][0]
            ip_ts_interval_1 = \
                self.cur_pkt[1] - self.stats_ip[self.hash_ip_0][0][1]
            ip_ts_interval_2 = \
                self.cur_pkt[1] - self.stats_ip[self.hash_ip_0][0][2]
            ip_ts_interval_3 = \
                self.cur_pkt[1] - self.stats_ip[self.hash_ip_0][0][3]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.

            self.stats_ip[self.hash_ip_0][0][0] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][1] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][2] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][3] = self.cur_pkt[1]

            self.ip_res_sum[self.hash_ip_xor][0][0] = self.cur_pkt[1]
            self.ip_res_sum[self.hash_ip_xor][0][1] = self.cur_pkt[1]
            self.ip_res_sum[self.hash_ip_xor][0][2] = self.cur_pkt[1]
            self.ip_res_sum[self.hash_ip_xor][0][3] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_ip[self.hash_ip_0][1][0] = \
                pow(2, (-10 * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][1][0] + 1
            self.stats_ip[self.hash_ip_0][2][0] = \
                pow(2, (-1 * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][2][0] + 1
            self.stats_ip[self.hash_ip_0][3][0] = \
                pow(2, (-0.1 * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][3][0] + 1
            self.stats_ip[self.hash_ip_0][4][0] = \
                pow(2, (-(1/60) * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][4][0] + 1

            # Decay factor: pkt length.
            self.stats_ip[self.hash_ip_0][1][1] = \
                pow(2, (-10 * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][1][1] + self.cur_pkt[0]
            self.stats_ip[self.hash_ip_0][2][1] = \
                pow(2, (-1 * ip_ts_interval_1)) * \
                self.stats_ip[self.hash_ip_0][2][1] + self.cur_pkt[0]
            self.stats_ip[self.hash_ip_0][3][1] = \
                pow(2, (-0.1 * ip_ts_interval_2)) * \
                self.stats_ip[self.hash_ip_0][3][1] + self.cur_pkt[0]
            self.stats_ip[self.hash_ip_0][4][1] = \
                pow(2, (-(1/60) * ip_ts_interval_3)) * \
                self.stats_ip[self.hash_ip_0][4][1] + self.cur_pkt[0]

            # Decay factor: pkt length squared.
            self.stats_ip[self.hash_ip_0][1][2] = \
                pow(2, (-10 * ip_ts_interval_0)) * \
                self.stats_ip[self.hash_ip_0][1][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip[self.hash_ip_0][2][2] = \
                pow(2, (-1 * ip_ts_interval_1)) * \
                self.stats_ip[self.hash_ip_0][2][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip[self.hash_ip_0][3][2] = \
                pow(2, (-0.1 * ip_ts_interval_2)) * \
                self.stats_ip[self.hash_ip_0][3][2] + pow(self.cur_pkt[0], 2)
            self.stats_ip[self.hash_ip_0][4][2] = \
                pow(2, (-(1/60) * ip_ts_interval_3)) * \
                self.stats_ip[self.hash_ip_0][4][2] + pow(self.cur_pkt[0], 2)

            self.ip_res_sum[self.hash_ip_xor][1] = \
                pow(2, (-10 * ip_ts_interval_0)) * self.ip_res_sum[self.hash_ip_xor][1]
            self.ip_res_sum[self.hash_ip_xor][2] = \
                pow(2, (-1 * ip_ts_interval_1)) * self.ip_res_sum[self.hash_ip_xor][2]
            self.ip_res_sum[self.hash_ip_xor][3] = \
                pow(2, (-0.1 * ip_ts_interval_2)) * self.ip_res_sum[self.hash_ip_xor][3]
            self.ip_res_sum[self.hash_ip_xor][4] = \
                pow(2, (-(1/60) * ip_ts_interval_3)) * self.ip_res_sum[self.hash_ip_xor][4]
        else:
            self.stats_ip[self.hash_ip_0] = ([[0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0],
                                              [0, 0, 0, 0, 0, 0]])
            self.stats_ip[self.hash_ip_0][0][0] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][1] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][2] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][0][3] = self.cur_pkt[1]
            self.stats_ip[self.hash_ip_0][1] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_ip[self.hash_ip_0][2] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_ip[self.hash_ip_0][3] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_ip[self.hash_ip_0][4] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]

        # Five tuple

        if self.hash_five_t_0 not in self.five_t_res:
            self.five_t_res[self.hash_five_t_0] = [0, 0, 0, 0]

        if self.hash_five_t_xor not in self.five_t_res_sum:
            self.five_t_res_sum[self.hash_five_t_xor] = ([[0, 0, 0, 0], 0, 0, 0, 0])

        # Check if the current flow ID has already been seen.
        # If it exists, calculate the decay.
        # Else, initialize all values and perform the update from the current pkt.
        if self.hash_five_t_0 in self.stats_five_t:
            five_t_ts_interval_0 = \
                self.cur_pkt[1] - self.stats_five_t[self.hash_five_t_0][0][0]
            five_t_ts_interval_1 = \
                self.cur_pkt[1] - self.stats_five_t[self.hash_five_t_0][0][1]
            five_t_ts_interval_2 = \
                self.cur_pkt[1] - self.stats_five_t[self.hash_five_t_0][0][2]
            five_t_ts_interval_3 = \
                self.cur_pkt[1] - self.stats_five_t[self.hash_five_t_0][0][3]

            # Check if the current decay counter has been previously updated.
            # If so, perform the decay factor update.
            # Else, the current decay counter value becomes the current pkt timestamp.

            self.stats_five_t[self.hash_five_t_0][0][0] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][1] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][2] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][3] = self.cur_pkt[1]

            self.five_t_res_sum[self.hash_five_t_xor][0][0] = self.cur_pkt[1]
            self.five_t_res_sum[self.hash_five_t_xor][0][1] = self.cur_pkt[1]
            self.five_t_res_sum[self.hash_five_t_xor][0][2] = self.cur_pkt[1]
            self.five_t_res_sum[self.hash_five_t_xor][0][3] = self.cur_pkt[1]

            # Decay factor: pkt count.
            self.stats_five_t[self.hash_five_t_0][1][0] = \
                pow(2, (-10 * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][1][0] + 1
            self.stats_five_t[self.hash_five_t_0][2][0] = \
                pow(2, (-1 * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][2][0] + 1
            self.stats_five_t[self.hash_five_t_0][3][0] = \
                pow(2, (-0.1 * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][3][0] + 1
            self.stats_five_t[self.hash_five_t_0][4][0] = \
                pow(2, (-(1/60) * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][4][0] + 1

            # Decay factor: pkt length.
            self.stats_five_t[self.hash_five_t_0][1][1] = \
                pow(2, (-10 * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][1][1] + self.cur_pkt[0]
            self.stats_five_t[self.hash_five_t_0][2][1] = \
                pow(2, (-1 * five_t_ts_interval_1)) * \
                self.stats_five_t[self.hash_five_t_0][2][1] + self.cur_pkt[0]
            self.stats_five_t[self.hash_five_t_0][3][1] = \
                pow(2, (-0.1 * five_t_ts_interval_2)) * \
                self.stats_five_t[self.hash_five_t_0][3][1] + self.cur_pkt[0]
            self.stats_five_t[self.hash_five_t_0][4][1] = \
                pow(2, (-(1/60) * five_t_ts_interval_3)) * \
                self.stats_five_t[self.hash_five_t_0][4][1] + self.cur_pkt[0]

            # Decay factor: pkt length squared.
            self.stats_five_t[self.hash_five_t_0][1][2] = \
                pow(2, (-10 * five_t_ts_interval_0)) * \
                self.stats_five_t[self.hash_five_t_0][1][2] + pow(self.cur_pkt[0], 2)
            self.stats_five_t[self.hash_five_t_0][2][2] = \
                pow(2, (-1 * five_t_ts_interval_1)) * \
                self.stats_five_t[self.hash_five_t_0][2][2] + pow(self.cur_pkt[0], 2)
            self.stats_five_t[self.hash_five_t_0][3][2] = \
                pow(2, (-0.1 * five_t_ts_interval_2)) * \
                self.stats_five_t[self.hash_five_t_0][3][2] + pow(self.cur_pkt[0], 2)
            self.stats_five_t[self.hash_five_t_0][4][2] = \
                pow(2, (-(1/60) * five_t_ts_interval_3)) * \
                self.stats_five_t[self.hash_five_t_0][4][2] + pow(self.cur_pkt[0], 2)

            self.five_t_res_sum[self.hash_five_t_xor][1] = \
                pow(2, (-10 * five_t_ts_interval_0)) * self.five_t_res_sum[self.hash_five_t_xor][1]
            self.five_t_res_sum[self.hash_five_t_xor][2] = \
                pow(2, (-1 * five_t_ts_interval_1)) * self.five_t_res_sum[self.hash_five_t_xor][2]
            self.five_t_res_sum[self.hash_five_t_xor][3] = \
                pow(2, (-0.1 * five_t_ts_interval_2)) * self.five_t_res_sum[self.hash_five_t_xor][3]
            self.five_t_res_sum[self.hash_five_t_xor][4] = \
                pow(2, (-(1/60) * five_t_ts_interval_3)) * self.five_t_res_sum[self.hash_five_t_xor][4]
        else:
            self.stats_five_t[self.hash_five_t_0] = ([[0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0],
                                                      [0, 0, 0, 0, 0, 0]])
            self.stats_five_t[self.hash_five_t_0][0][0] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][1] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][2] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][0][3] = self.cur_pkt[1]
            self.stats_five_t[self.hash_five_t_0][1] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_five_t[self.hash_five_t_0][2] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_five_t[self.hash_five_t_0][3] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
            self.stats_five_t[self.hash_five_t_0][4] = \
                [1, self.cur_pkt[0], pow(self.cur_pkt[0], 2), 0, 0, 0]
    # Returns the nearest lower power of two.
    def pow_2(self, n):
        if n > 1:
            return int(log(n, 2))
        else:
            return 0
