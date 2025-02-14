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
LEARNING_RATE = 0.1
HIDDEN_RATIO = 0.75


class PipelineKitNET:
    def __init__(
            self, trace, labels, sampl, train_sampl, exec_sampl_offset, fm_grace, ad_grace,
            max_ae, fm_model, el_model, ol_model, train_stats, attack, train_exact_ratio,
            exact_stats, save_stats_global, save_spatial, time_start):

        self.decay_to_pos = {
            0: 0, 1: 0, 2: 1, 3: 2, 4: 3,
            8192: 1, 16384: 2, 24576: 3}

        self.fm_grace = fm_grace
        self.ad_grace = ad_grace
        self.train_grace = self.fm_grace + self.ad_grace

        self.attack = attack
        self.m = max_ae

        # Exec phase sampling rate.
        self.sampl = sampl
        # Sample the FC phase.
        self.train_sampl = train_sampl
        # Exec phase: packet number offset from which to start the sampling.
        self.exec_sampl_offset = exec_sampl_offset
        # Ratio of exact stats in the overall training phase.
        self.train_exact_ratio = train_exact_ratio
        # Calculate exact stats in the exec phase.
        self.exact_stats = exact_stats
        # Keep track of the global stats and save them to a csv.
        self.save_stats_global = save_stats_global
        # Save the model for spatial.
        self.save_spatial = save_spatial

        self.attack_init_ts = 0
        self.attack_pkt_num_cntr = 0
        self.attack_pkt_num_cntr_dp = 0
        self.det_init_time = -1
        self.det_init_pkt_num = -1
        self.det_init_pkt_num_dp = -1

        self.stats_global = []
        self.rmse_list = []
        self.peregrine_eval = []

        self.threshold = 0
        self.pkt_cnt_global = 0
        self.train_skip_pkt = 0
        self.train_skip = False

        # Read the csv containing the ground truth labels.
        self.trace_labels = pd.read_csv(labels, header=None)

        if fm_model is not None \
                and os.path.isfile(f'{Path(__file__).parents[0]}/{fm_model}') \
                and el_model is not None \
                and os.path.isfile(f'{Path(__file__).parents[0]}/{el_model}') \
                and ol_model is not None \
                and os.path.isfile(f'{Path(__file__).parents[0]}/{ol_model}') \
                and train_stats is not None \
                and os.path.isfile(f'{Path(__file__).parents[0]}/{train_stats}'):
            self.train_skip = True

        self.stats_mac_ip_src = {}
        self.stats_ip_src = {}
        self.stats_ip = {}
        self.stats_five_t = {}

        # If train_skip is true, import the previously generated models.
        if self.train_skip:
            with open(train_stats, 'rb') as f_stats:
                stats = pickle.load(f_stats)
                self.stats_mac_ip_src = stats[0]
                self.stats_ip_src = stats[1]
                self.stats_ip = stats[2]
                self.stats_five_t = stats[3]

        # Initialize KitNET.
        if self.train_sampl:
            self.kitnet = KitNET(
                80, max_ae, fm_grace // self.sampl, ad_grace // self.sampl,
                LEARNING_RATE, HIDDEN_RATIO, fm_model, el_model, ol_model, attack,
                train_exact_ratio)
        else:
            self.kitnet = KitNET(
                80, max_ae, fm_grace, ad_grace, LEARNING_RATE, HIDDEN_RATIO, fm_model, el_model,
                ol_model, attack, train_exact_ratio)

        # Initialize feature extraction/computation.
        self.fc = FCKitNET(trace, sampl, self.train_grace, exec_sampl_offset, self.train_skip,
                           train_stats)

        self.trace_size = self.fc.trace_size()
        self.trace_initial_ts = self.fc.trace_initial_ts()

    def process(self):
        # Offset value, corresponds to 0 during the training phase and
        # to self.exec_sampl_offset during the exec phase.
        if not self.train_skip:
            offset = 0
        else:
            offset = self.exec_sampl_offset

        time_old = 0
        time_new = 0

        # Process the trace, packet by packet.
        while True:
            cur_stats = 0

            time_new = time.time()
            if not self.train_skip:
                if (len(self.rmse_list) + self.train_skip_pkt) % 1000 == 0 and \
                        (len(self.rmse_list) + self.train_skip_pkt) < self.train_grace:
                    print(f'Processed pkts: {len(self.rmse_list) + self.train_skip_pkt}. '
                          f'Elapsed time: {time_new - time_old} '
                          f'({int(1000/(time_new - time_old))} pps)')
                    time_old = time_new
                elif self.pkt_cnt_global % 1000 == 0 and \
                        (len(self.rmse_list) + self.train_skip_pkt) >= self.train_grace:
                    print(f'Processed pkts: {self.train_grace + self.pkt_cnt_global}. '
                          f'Elapsed time: {time_new - time_old} '
                          f'({int(1000/(time_new - time_old))} pps)')
                    time_old = time_new
            else:
                if self.pkt_cnt_global % 1000 == 0:
                    print(f'Processed pkts: {self.train_grace + self.pkt_cnt_global}. '
                          f'Elapsed time: {time_new - time_old} '
                          f'({int(1000/(time_new - time_old))} pps)')
                    time_old = time_new

            if self.save_stats_global:
                self.update_stats_global()

            # Training phase.
            if (len(self.rmse_list) + self.train_skip_pkt) \
                    < (self.train_exact_ratio * (self.train_grace)) \
                    and not self.train_skip:
                self.fc.feature_extract()
                if self.train_sampl \
                        and (len(self.rmse_list) +1 + self.train_skip_pkt) % self.sampl != 0:
                    self.train_skip_pkt += 1
                    continue
                cur_stats = self.fc.process_exact('training')
            elif (len(self.rmse_list) + self.train_skip_pkt) \
                    < self.train_grace and not self.train_skip:
                self.fc.feature_extract()
                if self.train_sampl \
                        and (len(self.rmse_list) +1 + self.train_skip_pkt) % self.sampl != 0:
                    self.train_skip_pkt += 1
                    continue
                if self.exact_stats:
                    cur_stats = self.fc.process_exact('training')
                else:
                    cur_stats = self.fc.process('training')

            # Execution phase.
            else:
                self.pkt_cnt_global += 1
                if self.train_grace + self.pkt_cnt_global + self.exec_sampl_offset > self.trace_size:
                    if self.save_stats_global:
                        self.update_stats_global()
                    break
                self.fc.feature_extract()
                if self.attack_pkt_num_cntr_dp != -1 and int(self.trace_labels.iat[
                        self.train_grace + offset + self.pkt_cnt_global - 1, 0]) == 1:
                    self.attack_pkt_num_cntr_dp += 1
                if self.exact_stats:
                    cur_stats = self.fc.process_exact('execution')
                else:
                    cur_stats = self.fc.process('execution')

            # If any statistics were obtained, send them to the ML pipeline.
            # Execution phase: only proceed according to the sampling rate.
            if cur_stats != 0:
                # If the packet is not IPv4.
                if cur_stats == -1:
                    self.train_skip_pkt += 1
                    continue

                # Break when we reach the end of the trace file.
                if self.train_grace + self.pkt_cnt_global + self.exec_sampl_offset \
                        > self.trace_size:
                    if self.save_stats_global:
                        self.update_stats_global()
                    break
                if self.pkt_cnt_global % self.sampl != 0:
                    continue

                # Flatten the statistics' list of lists.
                cur_stats = list(itertools.chain(*cur_stats))

                # Update the stored global stats with the latest packet stats.
                input_stats = self.update_stats(cur_stats)

                if self.save_stats_global:
                    self.stats_global.append(input_stats)

                # Call function with the content of kitsune's main (before the eval/csv part).
                rmse = self.kitnet.process(input_stats)

                self.rmse_list.append(rmse)

                if len(self.rmse_list) < self.train_grace and int(self.trace_labels.iat[
                        len(self.rmse_list) + self.train_skip_pkt - 1, 0]) == 1:
                    print('Error: attack traces appearing during the training phase')
                    break

                if self.attack_init_ts == 0 and int(self.trace_labels.iat[
                        self.train_grace + offset + self.pkt_cnt_global - 1, 0]) == 1:
                    print('Trace attack: start')
                    self.attack_init_ts = cur_stats[0]
                    self.attack_pkt_num_cntr += 1

                if int(rmse) > int(self.threshold) \
                        and self.attack_pkt_num_cntr != -1 \
                        and int(self.trace_labels.iat[
                            self.train_grace + offset + self.pkt_cnt_global - 1, 0]) == 1:
                    self.det_init_time = cur_stats[0] - self.attack_init_ts
                    self.det_init_pkt_num = self.attack_pkt_num_cntr
                    self.det_init_pkt_num_dp = self.attack_pkt_num_cntr_dp
                    self.attack_pkt_num_cntr = -1
                    self.attack_pkt_num_cntr_dp = -1

                if self.attack_pkt_num_cntr != -1 and int(self.trace_labels.iat[
                        self.train_grace + offset + self.pkt_cnt_global - 1, 0]) == 1:
                    self.attack_pkt_num_cntr += 1

                try:
                    # 1-5: pkt headers
                    # time_pkt_ml: processing time (ML classifier only)
                    self.peregrine_eval.append([
                        cur_stats[1], cur_stats[2], cur_stats[3], cur_stats[4], cur_stats[5],
                        cur_stats[6], rmse, self.trace_labels.iat[
                            self.train_grace + offset + self.pkt_cnt_global - 1, 0]])
                except IndexError:
                    print(self.trace_labels.shape[0])
                    print(self.pkt_cnt_global)
                    print(self.train_grace + offset + self.pkt_cnt_global - 1)

                # At the end of the training phase, store the highest rmse value as the threshold.
                # Also, save the stored stat values.
                if not self.train_skip \
                        and (len(self.rmse_list) + self.train_skip_pkt) == self.train_grace:
                    offset = self.exec_sampl_offset
                    self.threshold = max(self.rmse_list, key=float)
                    self.save_train_stats()
                    print('Starting execution phase...')
                # Break when we reach the end of the trace file.
                elif self.train_grace + self.pkt_cnt_global \
                        + self.exec_sampl_offset >= self.trace_size:
                    if self.save_stats_global:
                        self.update_stats_global()
                    break
            else:
                print('TIMEOUT.')
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

        input_stats = np.concatenate((
            self.stats_mac_ip_src[hdr_mac_ip_src],
            self.stats_ip_src[hdr_ip_src],
            self.stats_ip[hdr_ip],
            self.stats_five_t[hdr_five_t]))

        # Convert any existing NaNs to 0.
        input_stats[np.isnan(input_stats)] = 0

        return input_stats

    def save_train_stats(self):
        train_stats = [
            self.stats_mac_ip_src,
            self.stats_ip_src,
            self.stats_ip,
            self.stats_five_t,
            self.fc.fc_mac_ip_src,
            self.fc.fc_ip_src,
            self.fc.fc_ip,
            self.fc.fc_five_t,
            self.fc.ip_res,
            self.fc.ip_res_sum,
            self.fc.five_t_res,
            self.fc.five_t_res_sum]

        outdir = str(Path(__file__).parents[0]) + '/plugins/KitNET/models'
        if not os.path.exists(str(Path(__file__).parents[0]) + '/plugins/KitNET/models'):
            os.mkdir(outdir)

        with open(outdir + '/' + self.attack + '-m-' + str(self.m)
                  + '-r-' + str(self.train_exact_ratio) + '-train-stats'
                  + '.txt', 'wb') as f_stats:
            pickle.dump(train_stats, f_stats)

        if self.save_spatial:
            outdir_params = f'{Path(__file__).parents[0]}/plugins/KitNET/models/spatial/{self.attack}'\
                            f'-m-{self.m}-r-{self.train_exact_ratio}/params'
            if not os.path.exists(outdir_params):
                os.makedirs(outdir_params)
            outdir_norms = f'{Path(__file__).parents[0]}/plugins/KitNET/models/spatial/{self.attack}'\
                        f'-m-{self.m}-r-{self.train_exact_ratio}/norms'
            if not os.path.exists(outdir_norms):
                os.makedirs(outdir_norms)
            outdir_maps = f'{Path(__file__).parents[0]}/plugins/KitNET/models/spatial/{self.attack}'\
                        f'-m-{self.m}-r-{self.train_exact_ratio}/maps'
            if not os.path.exists(outdir_maps):
                os.makedirs(outdir_maps)

            for i in range(len(self.kitnet.ensembleLayer)):
                pd.DataFrame(self.kitnet.ensembleLayer[i].W).to_csv(
                    f'{outdir_params}/L{i}_W.csv', header=False, index=False)
                pd.DataFrame(self.kitnet.ensembleLayer[i].hbias).to_csv(
                    f'{outdir_params}/L{i}_B1.csv', header=False, index=False)
                pd.DataFrame(self.kitnet.ensembleLayer[i].vbias).to_csv(
                    f'{outdir_params}/L{i}_B2.csv', header=False, index=False)
                pd.DataFrame(self.kitnet.ensembleLayer[i].norm_min).to_csv(
                    f'{outdir_norms}/L{i}_NORM_MIN.csv', header=False, index=False)
                pd.DataFrame(self.kitnet.ensembleLayer[i].norm_max).to_csv(
                    f'{outdir_norms}/L{i}_NORM_MAX.csv', header=False, index=False)

            pd.DataFrame(self.kitnet.outputLayer.W).to_csv(
                f'{outdir_params}/OUTL_W.csv', header=False, index=False)
            pd.DataFrame(self.kitnet.outputLayer.hbias).to_csv(
                f'{outdir_params}/OUTL_B1.csv', header=False, index=False)
            pd.DataFrame(self.kitnet.outputLayer.vbias).to_csv(
                f'{outdir_params}/OUTL_B2.csv', header=False, index=False)
            pd.DataFrame(self.kitnet.outputLayer.norm_min).to_csv(
                f'{outdir_norms}/OUTL_NORM_MIN.csv', header=False, index=False)
            pd.DataFrame(self.kitnet.outputLayer.norm_max).to_csv(
                f'{outdir_norms}/OUTL_NORM_MAX.csv', header=False, index=False)

            for i in range(len(self.kitnet.v)):
                pd.DataFrame(self.kitnet.v[i]).T.to_csv(
                    f'{outdir_maps}/L{i}_MAP.csv', header=False, index=False)
                pd.DataFrame([len(self.kitnet.v[i]),
                            int(np.ceil(len(self.kitnet.v[i])*0.75))]).T.to_csv(
                                f'{outdir_maps}/L{i}_NEURONS.csv', header=False, index=False)

            pd.DataFrame([len(self.kitnet.v)]).T.to_csv(
                f'{outdir_maps}/N_LAYERS.csv', header=False, index=False)

    def update_stats_global(self):
        outdir = f'{Path(__file__).parents[0]}/eval/kitnet'
        if not os.path.exists(f'{Path(__file__).parents[0]}/eval/kitnet'):
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
