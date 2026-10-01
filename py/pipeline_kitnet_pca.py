import os
import time
import pickle
import itertools
import numpy as np
import pandas as pd
from pathlib import Path
from fc_kitnet import FCKitNET
from plugins.KitNET.KitNET import KitNET

LAMBDAS = 4


class PipelineKitNET_PCA:
    def __init__(
            self, feats, labels, sampl, fm_grace, ad_grace, max_ae, learning_rate, hidden_ratio,
            only_ol, dataset, attack, save_stats_global, time_start):

        self.fm_grace       = fm_grace
        self.ad_grace       = ad_grace
        self.train_grace    = self.fm_grace + self.ad_grace

        self.dataset        = dataset
        self.attack         = attack
        self.m              = max_ae
        self.learning_rate  = learning_rate
        self.hidden_ratio   = hidden_ratio
        self.only_ol        = only_ol

        # Exec phase sampling rate.
        self.sampl              = sampl
        # Keep track of the global stats and save them to a csv.
        self.save_stats_global  = save_stats_global

        self.attack_init_ts             = 0
        self.attack_pkt_num_cntr        = 0
        self.attack_pkt_num_cntr_dp     = 0
        self.det_init_time              = -1
        self.det_init_pkt_num           = -1
        self.det_init_pkt_num_dp        = -1

        self.stats_global   = []
        self.rmse_list      = []
        self.peregrine_eval = []

        self.threshold      = 0
        self.pkt_cnt_global = 0
        self.exec_phase     = False

        self.pkt_cnt_train  = 0
        self.pkt_cnt_exec   = 0
        self.pkt_cnt_label  = 0
        self.pkt_skip       = 0

        # Read the csv containing the pca feats.
        self.trace_feats = pd.read_csv(feats)

        # Read the csv containing the ground truth labels.
        self.trace_labels = pd.read_csv(labels)

        # Initialize KitNET.
        self.kitnet = KitNET(
            5, max_ae, fm_grace, ad_grace, self.only_ol, self.learning_rate,
            self.hidden_ratio, None, None, None, attack, 0)

        self.trace_size         = len(self.trace_labels)

    def process(self):
        time_old = 0
        time_new = 0

        # Process the trace, packet by packet.
        while True:
            cur_stats = 0

            time_new = time.time()
            if (self.pkt_cnt_train + self.pkt_cnt_exec + self.pkt_skip) % 10000 == 0:
                print(f'Processed pkts: {self.pkt_cnt_train + self.pkt_cnt_exec + self.pkt_skip}. '
                        f'Elapsed time: {time_new - time_old} '
                        f'({int(10000/(time_new - time_old))} pps)')
                time_old = time_new

            if self.save_stats_global:
                self.update_stats_global()

            # ----------------------------------------
            # Training phase
            # ----------------------------------------

            if not self.exec_phase:
                self.pkt_cnt_label += 1

                # cur_stats = self.trace_feats.iloc[self.pkt_cnt_global]
                cur_stats = np.array([self.trace_feats.iat[self.pkt_cnt_global, 0],
                                      self.trace_feats.iat[self.pkt_cnt_global, 1],
                                      self.trace_feats.iat[self.pkt_cnt_global, 2],
                                      self.trace_feats.iat[self.pkt_cnt_global, 3],
                                      self.trace_feats.iat[self.pkt_cnt_global, 4]])

                self.pkt_cnt_train  += 1
                self.pkt_cnt_global += 1

                if self.save_stats_global:
                    self.stats_global.append(cur_stats)

                # Call function with the content of kitsune's main (before the eval/csv part).
                rmse = self.kitnet.process(cur_stats)

                self.rmse_list.append(rmse)

                if self.pkt_cnt_train + self.pkt_skip < self.train_grace and int(self.trace_labels.iat[self.pkt_cnt_train + self.pkt_skip - 1, 0]) == 1:
                    print('Error: attack traces appearing during the training phase')
                    print(f'      pkt_cnt_train: {self.pkt_cnt_train}')
                    print(f'      pkt_skip:      {self.pkt_skip}')
                    print(f'      train_grace:   {self.train_grace}')
                    break

                try:
                    # 1-5: pkt headers
                    # time_pkt_ml: processing time (ML classifier only)
                    self.peregrine_eval.append([
                        rmse,
                        self.trace_labels.iat[self.pkt_cnt_train + self.pkt_skip - 1, 0]])
                except IndexError:
                    print(f'trace labels len: {self.trace_labels.shape[0]}')

                # At the end of the training phase, store the highest rmse value as the threshold.
                # Also, save the stored stat values.
                if self.pkt_cnt_train == self.train_grace and not self.exec_phase:
                    print(self.pkt_cnt_train)
                    print(self.pkt_skip)
                    print(self.pkt_cnt_label)
                    self.threshold = max(self.rmse_list, key=float)
                    self.exec_phase = True
                    print('Starting execution phase...')

            # ----------------------------------------
            # Execution phase
            # ----------------------------------------

            else:
                self.pkt_cnt_label  += 1

                if self.pkt_cnt_label > self.trace_size:
                    if self.save_stats_global:
                        self.update_stats_global()
                    break

                # cur_stats = self.trace_feats.iloc[self.pkt_cnt_global]
                cur_stats = np.array([self.trace_feats.iat[self.pkt_cnt_global, 0],
                                      self.trace_feats.iat[self.pkt_cnt_global, 1],
                                      self.trace_feats.iat[self.pkt_cnt_global, 2],
                                      self.trace_feats.iat[self.pkt_cnt_global, 3],
                                      self.trace_feats.iat[self.pkt_cnt_global, 4]])

                self.pkt_cnt_global += 1

                if (self.pkt_cnt_label - self.train_grace) % self.sampl != 0:
                    self.pkt_cnt_exec   += 1
                    continue

                if self.attack_pkt_num_cntr_dp != -1 and int(self.trace_labels.iat[
                        self.pkt_cnt_label - 1, 0]) == 1:
                    self.attack_pkt_num_cntr_dp += 1

                # If any statistics were obtained, send them to the ML pipeline.
                # Execution phase: only proceed according to the sampling rate.
                self.pkt_cnt_exec   += 1

                if self.save_stats_global:
                    self.stats_global.append(cur_stats)

                # Call function with the content of kitsune's main (before the eval/csv part).
                rmse = self.kitnet.process(cur_stats)

                self.rmse_list.append(rmse)

                if self.attack_init_ts == 0 and int(self.trace_labels.iat[
                        self.pkt_cnt_label - 1, 0]) == 1:
                    print('Trace attack: start')
                    self.attack_init_ts         = cur_stats[0]
                    self.attack_pkt_num_cntr   += 1

                if float(rmse) > float(self.threshold) \
                        and self.attack_pkt_num_cntr != -1 \
                        and int(self.trace_labels.iat[
                            self.pkt_cnt_label - 1, 0]) == 1:
                    self.det_init_time          = cur_stats[0] - self.attack_init_ts
                    self.det_init_pkt_num       = self.attack_pkt_num_cntr
                    self.det_init_pkt_num_dp    = self.attack_pkt_num_cntr_dp
                    self.attack_pkt_num_cntr    = -1
                    self.attack_pkt_num_cntr_dp = -1

                if self.attack_pkt_num_cntr != -1 and int(self.trace_labels.iat[
                        self.pkt_cnt_label - 1, 0]) == 1:
                    self.attack_pkt_num_cntr += 1

                try:
                    # 1-5: pkt headers
                    # time_pkt_ml: processing time (ML classifier only)
                    self.peregrine_eval.append([
                            rmse,
                            self.trace_labels.iat[self.pkt_cnt_label - 1, 0]])
                except IndexError:
                    print(f'trace labels len: {self.trace_labels.shape[0]}')
                    print(f'pkt cnt label:    {self.pkt_cnt_label}')

                # Break when we reach the end of the trace file.
                if self.pkt_cnt_label >= self.trace_size:
                    if self.save_stats_global:
                        self.update_stats_global()
                    break

    def update_stats_global(self):
        outdir = f'{Path(__file__).parents[0]}/eval/kitnet/{self.dataset}'
        if not os.path.exists(f'{Path(__file__).parents[0]}/eval/kitnet/{self.dataset}'):
            os.makedirs(outdir, exist_ok=True)
        outpath_stats_global = os.path.join(
            outdir, f'{self.attack}-{self.sampl}-stats.csv')
        df_stats_global = pd.DataFrame(self.stats_global)
        df_stats_global.to_csv(outpath_stats_global, mode='a', chunksize=10000,
                               index=None, header=False)
        self.stats_global = []

    def reset_stats(self):
        print('Reset stats')

        self.stats_mac_ip_src = {}
        self.stats_ip_src = {}
        self.stats_ip = {}
        self.stats_five_t = {}
