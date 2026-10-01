import time
import itertools
import numpy as np
import pandas as pd
from fc_kitnet import FCKitNET
from plugins.planter.planter import Planter

LAMBDAS = 4
LEARNING_RATE = 0.1
HIDDEN_RATIO = 0.75


class PipelinePlanter:
    def __init__(self, trace, labels, planter_conf, planter_base_dir, train_size, attack,
                 switch_model, pca_feats, time_start):
        self.train_size     = train_size
        self.attack         = attack
        self.switch_model   = switch_model
        self.pca_feats      = pca_feats

        self.decay_to_pos = {
            0: 0, 1: 0, 2: 1, 3: 2, 4: 3,
            8192: 1, 16384: 2, 24576: 3}

        self.attack_init_ts         = 0
        self.attack_pkt_num_cntr    = 0
        self.det_init_time          = -1
        self.det_init_pkt_num       = -1
        self.det_init_pkt_num_dp    = -1

        self.stats_train        = []
        self.stats_global       = []
        self.model_exec_out     = []
        self.tables_exec_out    = []
        self.trace_hdrs         = []

        self.pkt_cnt_train  = 0
        self.pkt_cnt_label  = 0
        self.pkt_cnt_exec   = 0

        self.input_stats = 0

        if not self.pca_feats:
            # Read the csv containing the ground truth labels.
            self.trace_labels = pd.read_csv(labels, header=None)

            self.stats_mac_ip_src   = {}
            self.stats_ip_src       = {}
            self.stats_ip           = {}
            self.stats_five_t       = {}

            # Initialize feature extraction/computation.
            self.fc = FCKitNET(trace, 1, self.train_size, 0, False, '', False)

            self.trace_size         = self.fc.trace_size()
            self.trace_initial_ts   = self.fc.trace_initial_ts()

        # Initialize Planter.
        self.planter        = Planter(planter_conf, planter_base_dir, switch_model)
        self.cur_model      = self.planter.cur_model()
        self.cur_model_size = self.planter.cur_model_size()

        self.corr_aggr      = []

    def process(self):
        time_old = 0
        time_new = 0

        model_trained = 0

        # Process the trace, packet by packet.
        while True:
            cur_stats   = 0
            time_new    = time.time()

            if (self.pkt_cnt_train + self.pkt_cnt_exec) % 10000 == 0 \
                    and (self.pkt_cnt_train + self.pkt_cnt_exec) < self.train_size:
                print(f'Processed pkts: {self.pkt_cnt_train + self.pkt_cnt_exec}. '
                        f'Elapsed time: {time_new - time_old} '
                        f'({int(10000/(time_new - time_old))} pps)')
                time_old = time_new
            elif (self.pkt_cnt_train + self.pkt_cnt_exec) % 10000 == 0 \
                    and (self.pkt_cnt_train + self.pkt_cnt_exec) >= self.train_size:
                print(f'Processed pkts: {self.pkt_cnt_train + self.pkt_cnt_exec}. '
                        f'Elapsed time: {time_new - time_old} '
                        f'({int(10000/(time_new - time_old))} pps)')
                time_old = time_new

            # ----------------------------------------
            # Training phase
            # ----------------------------------------

            if self.pkt_cnt_train < self.train_size:
                self.fc.feature_extract()
                cur_stats = self.fc.process('training')

                self.pkt_cnt_label += 1

                # If any statistics were obtained, send them to the ML pipeline.
                if cur_stats != 0:
                    # Only if the packet is IPv4.
                    if cur_stats == -1:
                        continue

                    self.pkt_cnt_train += 1

                    # Flatten the statistics' list of lists.
                    cur_stats = list(itertools.chain(*cur_stats))

                    # Update the stored global stats with the latest packet stats.
                    self.input_stats = self.update_stats(cur_stats)

                    self.stats_train.append(self.input_stats)

                    try:
                        # 1-5: pkt headers
                        # time_pkt_ml: processing time (ML classifier only)
                        self.trace_hdrs.append([
                            cur_stats[1], cur_stats[2], cur_stats[3],
                            cur_stats[4], cur_stats[5], cur_stats[6],
                            self.trace_labels.iat[self.pkt_cnt_label - 1, 0]])

                    except IndexError:
                        print(f'Trace size: {self.trace_labels.shape[0]}')
                        print(f'Cur pkt:    {self.pkt_cnt_label}')

                    if self.pkt_cnt_train == self.train_size and model_trained == 0:
                        self.planter.model_train(self.stats_train, self.switch_model)
                        model_trained = 1
                        self.input_stats = 0
                        # If pca, transform the training stats as well.
                        if self.cur_model == 'pca':
                            model_exec_out = self.planter.model_exec(self.stats_train)
                            self.model_exec_out.append(model_exec_out)
                            if self.switch_model:
                                tables_exec_out = self.planter.tables_exec(self.stats_train)
                                self.tables_exec_out.append(tables_exec_out)
                        continue

                    continue

            # ----------------------------------------
            # Execution phase
            # ----------------------------------------

            else:
                if self.pkt_cnt_label > self.trace_size:
                    if self.cur_model == 'pca' and self.switch_model:
                        self.corr_aggr = self.planter.cur_aggr_pcc()

                    if not isinstance(self.input_stats, int):
                        # print(f'input stats: {self.input_stats}')
                        model_exec_out  = self.planter.model_exec(self.input_stats)
                        self.model_exec_out.append(model_exec_out)

                        if self.switch_model:
                            tables_exec_out = self.planter.tables_exec(self.input_stats)
                            self.tables_exec_out.append(tables_exec_out)

                    break

                self.pkt_cnt_label += 1

                self.fc.feature_extract()
                cur_stats = self.fc.process('execution')

                # If any statistics were obtained, send them to the ML pipeline.
                if cur_stats != 0:
                    # Only if the packet is IPv4.
                    if cur_stats == -1:
                        continue

                    self.pkt_cnt_exec += 1

                    # Flatten the statistics' list of lists.
                    cur_stats = list(itertools.chain(*cur_stats))

                    if isinstance(self.input_stats, int):
                        self.input_stats = self.update_stats(cur_stats)
                    else:
                        # Update the stored global stats with the latest packet stats.
                        self.input_stats = np.vstack((self.input_stats, self.update_stats(cur_stats)))

                        if len(self.input_stats) % 1000 == 0:
                            model_exec_out  = self.planter.model_exec(self.input_stats)
                            self.model_exec_out.append(model_exec_out)

                            if self.switch_model:
                                tables_exec_out = self.planter.tables_exec(self.input_stats)
                                self.tables_exec_out.append(tables_exec_out)

                            self.input_stats = 0

                    try:
                        # 1-5: pkt headers
                        # time_pkt_ml: processing time (ML classifier only)
                        self.trace_hdrs.append([
                            cur_stats[1], cur_stats[2], cur_stats[3],
                            cur_stats[4], cur_stats[5], cur_stats[6],
                            self.trace_labels.iat[self.pkt_cnt_label - 1, 0]])
                    except IndexError:
                        print(f'Trace size: {self.trace_labels.shape[0]}')
                        print(f'Cur pkt:    {self.pkt_cnt_label}')

                    if self.pkt_cnt_label >= self.trace_size:
                        if not isinstance(self.input_stats, int):
                            model_exec_out  = self.planter.model_exec(self.input_stats)
                            self.model_exec_out.append(model_exec_out)

                            if self.switch_model:
                                tables_exec_out = self.planter.tables_exec(self.input_stats)
                                self.tables_exec_out.append(tables_exec_out)

                        if self.cur_model == 'pca' and self.switch_model:
                            self.corr_aggr = self.planter.cur_aggr_pcc()

                        break

    def process_pca_feats(self, pca_feats_path, pca_labels_path):
        time_old = 0
        time_new = 0

        model_trained = 0

        self.pd_pca_feats   = pd.read_csv(pca_feats_path)
        self.pd_pca_labels  = pd.read_csv(pca_labels_path)

        self.trace_size     = self.pd_pca_feats.shape[0]
        self.pca_feats_cols = self.pd_pca_feats.shape[1]

        # Process the trace, packet by packet.
        while True:
            cur_stats   = 0
            time_new    = time.time()

            if (self.pkt_cnt_train + self.pkt_cnt_exec) % 10000 == 0 \
                    and (self.pkt_cnt_train + self.pkt_cnt_exec) < self.train_size:
                print(f'Processed pkts: {self.pkt_cnt_train + self.pkt_cnt_exec}. '
                        f'Elapsed time: {time_new - time_old} '
                        f'({int(10000/(time_new - time_old))} pps)')
                time_old = time_new
            elif (self.pkt_cnt_train + self.pkt_cnt_exec) % 10000 == 0 \
                    and (self.pkt_cnt_train + self.pkt_cnt_exec) >= self.train_size:
                print(f'Processed pkts: {self.pkt_cnt_train + self.pkt_cnt_exec}. '
                        f'Elapsed time: {time_new - time_old} '
                        f'({int(10000/(time_new - time_old))} pps)')
                time_old = time_new

            # ----------------------------------------
            # Training phase
            # ----------------------------------------

            if self.pkt_cnt_train < self.train_size:
                cur_stats = self.pd_pca_feats.loc[self.pkt_cnt_label, :].values.flatten().tolist()

                self.pkt_cnt_label += 1
                self.pkt_cnt_train += 1

                self.stats_train.append(cur_stats)

                try:
                    self.trace_hdrs.append(self.pd_pca_labels.iat[self.pkt_cnt_label - 1, 0])

                except IndexError:
                    print(f'Trace size: {self.trace_labels.shape[0]}')
                    print(f'Cur pkt:    {self.pkt_cnt_label}')

                if self.pkt_cnt_train == self.train_size and model_trained == 0:
                    self.planter.model_train(self.stats_train,
                                             self.switch_model,
                                             self.pca_feats_cols)
                    model_trained = 1
                    continue

                continue

            # ----------------------------------------
            # Execution phase
            # ----------------------------------------

            else:
                if self.pkt_cnt_label > self.trace_size:
                    model_exec_out  = self.planter.model_exec(self.input_stats,
                                                              self.pca_feats_cols)
                    self.model_exec_out.append(model_exec_out)

                    if self.switch_model:
                        tables_exec_out = self.planter.tables_exec(self.input_stats)
                        self.tables_exec_out.append(tables_exec_out)

                    break


                cur_stats = self.pd_pca_feats.loc[self.pkt_cnt_label, :].values.flatten().tolist()

                self.pkt_cnt_label  += 1
                self.pkt_cnt_exec   += 1

                # Update the stored global stats with the latest packet stats.
                if isinstance(self.input_stats, int):
                    self.input_stats = [cur_stats]
                else:
                    self.input_stats.append(cur_stats)

                if len(self.input_stats) % 1000 == 0:
                    model_exec_out  = self.planter.model_exec(self.input_stats,
                                                              self.pca_feats_cols)
                    self.model_exec_out.append(model_exec_out)

                    if self.switch_model:
                        tables_exec_out = self.planter.tables_exec(self.input_stats)
                        self.tables_exec_out.append(tables_exec_out)

                    self.input_stats = 0

                try:
                    self.trace_hdrs.append(self.pd_pca_labels.iat[self.pkt_cnt_label - 1, 0])
                except IndexError:
                    print(f'Trace size: {self.trace_labels.shape[0]}')
                    print(f'Cur pkt:    {self.pkt_cnt_label}')

                if self.pkt_cnt_label >= self.trace_size:
                    model_exec_out  = self.planter.model_exec(self.input_stats,
                                                              self.pca_feats_cols)
                    self.model_exec_out.append(model_exec_out)

                    if self.switch_model:
                        tables_exec_out = self.planter.tables_exec(self.input_stats)
                        self.tables_exec_out.append(tables_exec_out)

                    break

    def update_stats(self, cur_stats):
        cur_decay_pos = self.decay_to_pos[cur_stats[7]]

        try:
            hdr_mac_ip_src = cur_stats[1] + cur_stats[2]
            hdr_ip_src = cur_stats[2]
            hdr_ip = cur_stats[2] + cur_stats[3]
            hdr_five_t = cur_stats[2] + cur_stats[3] + cur_stats[4] + cur_stats[5] + cur_stats[6]
        except TypeError:
            print(f'Type error: {cur_stats}')

        if hdr_mac_ip_src not in self.stats_mac_ip_src:
            self.stats_mac_ip_src[hdr_mac_ip_src] = np.zeros(3 * LAMBDAS)
        self.stats_mac_ip_src[hdr_mac_ip_src][(3*cur_decay_pos):(3*cur_decay_pos+3)] = \
            cur_stats[8:11]

        if hdr_ip_src not in self.stats_ip_src:
            self.stats_ip_src[hdr_ip_src] = np.zeros(3 * LAMBDAS)
        self.stats_ip_src[hdr_ip_src][(3*cur_decay_pos):(3*cur_decay_pos+3)] = \
            cur_stats[11:14]

        if hdr_ip not in self.stats_ip:
            self.stats_ip[hdr_ip] = np.zeros(7 * LAMBDAS)
        self.stats_ip[hdr_ip][(7*cur_decay_pos):(7*cur_decay_pos+7)] = \
            cur_stats[14:21]

        if hdr_five_t not in self.stats_five_t:
            self.stats_five_t[hdr_five_t] = np.zeros(7 * LAMBDAS)
        self.stats_five_t[hdr_five_t][(7*cur_decay_pos):(7*cur_decay_pos+7)] = \
            cur_stats[21:]

        self.input_stats = np.concatenate((
            self.stats_mac_ip_src[hdr_mac_ip_src],
            self.stats_ip_src[hdr_ip_src],
            self.stats_ip[hdr_ip],
            self.stats_five_t[hdr_five_t]))

        # Convert any existing NaNs to 0.
        self.input_stats[np.isnan(self.input_stats)] = 0

        return self.input_stats

    def reset_stats(self):
        print('Reset stats')

        self.stats_mac_ip_src = {}
        self.stats_ip_src = {}
        self.stats_ip = {}
        self.stats_five_t = {}
