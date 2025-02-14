import os
from KitNET.KitNET import KitNET
import numpy as np
import pandas as pd
import pickle
from pathlib import Path


class Peregrine:
    def __init__(self, max_autoencoder_size=10, fm_grace_period=None, ad_grace_period=10000,
                 learning_rate=0.1, hidden_ratio=0.75, lambdas=4,
                 feature_map=None, ensemble_layer=None, output_layer=None, train_stats=None,
                 attack='', train_skip=False, train_exact_ratio=0):

        # Initialize KitNET.
        self.AnomDetector = KitNET(80, max_autoencoder_size, fm_grace_period,
                                   ad_grace_period, learning_rate, hidden_ratio,
                                   feature_map, ensemble_layer, output_layer,
                                   attack, train_exact_ratio)

        self.decay_to_pos = {0: 0, 1: 0, 2: 1, 3: 2, 4: 3,
                             8192: 1, 16384: 2, 24576: 3}

        self.lambdas = lambdas
        self.fm_grace = fm_grace_period
        self.ad_grace = ad_grace_period
        self.attack = attack
        self.m = max_autoencoder_size
        self.train_exact_ratio = train_exact_ratio

        self.df_train_stats_list = []
        self.df_exec_stats_list = []

        # If train_skip is true, import the previously generated models.
        if train_skip:
            with open(train_stats, 'rb') as f_stats:
                stats = pickle.load(f_stats)
                self.stats_mac_ip_src = stats[0]
                self.stats_ip_src = stats[1]
                self.stats_ip = stats[2]
                self.stats_five_t = stats[3]
        else:
            self.stats_mac_ip_src = {}
            self.stats_ip_src = {}
            self.stats_ip = {}
            self.stats_five_t = {}

    def proc_next_packet(self, cur_stats):

        cur_decay_pos = self.decay_to_pos[cur_stats[6]]

        hdr_mac_ip_src = cur_stats[0] + cur_stats[1]
        hdr_ip_src = cur_stats[1]
        hdr_ip = cur_stats[1] + cur_stats[2]
        hdr_five_t = cur_stats[1] + cur_stats[2] + cur_stats[3] + cur_stats[4] + cur_stats[5]

        if hdr_mac_ip_src not in self.stats_mac_ip_src:
            self.stats_mac_ip_src[hdr_mac_ip_src] = np.zeros(3 * self.lambdas)
        self.stats_mac_ip_src[hdr_mac_ip_src][(3*cur_decay_pos):(3*cur_decay_pos+3)] = \
            cur_stats[7:10]

        if hdr_ip_src not in self.stats_ip_src:
            self.stats_ip_src[hdr_ip_src] = np.zeros(3 * self.lambdas)
        self.stats_ip_src[hdr_ip_src][(3*cur_decay_pos):(3*cur_decay_pos+3)] = \
            cur_stats[10:13]

        if hdr_ip not in self.stats_ip:
            self.stats_ip[hdr_ip] = np.zeros(7 * self.lambdas)
        self.stats_ip[hdr_ip][(7*cur_decay_pos):(7*cur_decay_pos+7)] = \
            cur_stats[13:20]

        if hdr_five_t not in self.stats_five_t:
            self.stats_five_t[hdr_five_t] = np.zeros(7 * self.lambdas)
        self.stats_five_t[hdr_five_t][(7*cur_decay_pos):(7*cur_decay_pos+7)] = \
            cur_stats[20:]

        processed_stats = np.concatenate((self.stats_mac_ip_src[hdr_mac_ip_src],
                                          self.stats_ip_src[hdr_ip_src],
                                          self.stats_ip[hdr_ip],
                                          self.stats_five_t[hdr_five_t]))

        # Convert any existing NaNs to 0.
        processed_stats[np.isnan(processed_stats)] = 0

        if len(self.df_train_stats_list) < self.fm_grace + self.ad_grace:
            self.df_train_stats_list.append(processed_stats)
        else:
            self.df_exec_stats_list.append(processed_stats)


        # Run KitNET with the current statistics.
        return self.AnomDetector.process(processed_stats)


    def save_train_stats(self):
        train_stats = [self.stats_mac_ip_src,
                       self.stats_ip_src,
                       self.stats_ip,
                       self.stats_five_t]

        outdir = str(Path(__file__).parents[0]) + '/KitNET/models'
        if not os.path.exists(str(Path(__file__).parents[0]) + '/KitNET/models'):
            os.mkdir(outdir)

        with open(outdir + '/' + self.attack + '-m-' + str(self.m)
                  + '-r-' + str(self.train_exact_ratio) + '-train-stats'
                  + '.txt', 'wb') as f_stats:
            pickle.dump(train_stats, f_stats)

        for i in range(0, len(self.df_train_stats_list), 50000):
            self.df_train_stats_list[i:i + 50000]
            df_train_stats = pd.DataFrame(self.df_train_stats_list[i:i + 50000])
            df_train_stats.to_pickle(
                f'{outdir}/{self.attack}-m-{self.m}-r-'
                f'{self.train_exact_ratio}-train-full-{int(i/50000)}.pkl'
            )

        outdir_params = f'{Path(__file__).parents[0]}/KitNET/models/spatial/{self.attack}'\
                        f'-m-{self.m}-r-{self.train_exact_ratio}/params'
        if not os.path.exists(outdir_params):
            os.makedirs(outdir_params)
        outdir_norms = f'{Path(__file__).parents[0]}/KitNET/models/spatial/{self.attack}'\
                       f'-m-{self.m}-r-{self.train_exact_ratio}/norms'
        if not os.path.exists(outdir_norms):
            os.makedirs(outdir_norms)
        outdir_maps = f'{Path(__file__).parents[0]}/KitNET/models/spatial/{self.attack}'\
                      f'-m-{self.m}-r-{self.train_exact_ratio}/maps'
        if not os.path.exists(outdir_maps):
            os.makedirs(outdir_maps)

        for i in range(len(self.AnomDetector.ensembleLayer)):
            pd.DataFrame(self.AnomDetector.ensembleLayer[i].W).to_csv(
                f'{outdir_params}/L{i}_W.csv', header=False, index=False
            )
            pd.DataFrame(self.AnomDetector.ensembleLayer[i].hbias).to_csv(
                f'{outdir_params}/L{i}_B1.csv', header=False, index=False
            )
            pd.DataFrame(self.AnomDetector.ensembleLayer[i].vbias).to_csv(
                f'{outdir_params}/L{i}_B2.csv', header=False, index=False
            )
            pd.DataFrame(self.AnomDetector.ensembleLayer[i].norm_min).to_csv(
                f'{outdir_norms}/L{i}_NORM_MIN.csv', header=False, index=False
            )
            pd.DataFrame(self.AnomDetector.ensembleLayer[i].norm_max).to_csv(
                f'{outdir_norms}/L{i}_NORM_MAX.csv', header=False, index=False
            )

        pd.DataFrame(self.AnomDetector.outputLayer.W).to_csv(
            f'{outdir_params}/OUTL_W.csv', header=False, index=False
        )
        pd.DataFrame(self.AnomDetector.outputLayer.hbias).to_csv(
            f'{outdir_params}/OUTL_B1.csv', header=False, index=False
        )
        pd.DataFrame(self.AnomDetector.outputLayer.vbias).to_csv(
            f'{outdir_params}/OUTL_B2.csv', header=False, index=False
        )
        pd.DataFrame(self.AnomDetector.outputLayer.norm_min).to_csv(
            f'{outdir_norms}/OUTL_NORM_MIN.csv', header=False, index=False
        )
        pd.DataFrame(self.AnomDetector.outputLayer.norm_max).to_csv(
            f'{outdir_norms}/OUTL_NORM_MAX.csv', header=False, index=False
        )

        for i in range(len(self.AnomDetector.v)):
            pd.DataFrame(self.AnomDetector.v[i]).T.to_csv(
                f'{outdir_maps}/L{i}_MAP.csv', header=False, index=False
            )
            pd.DataFrame([len(self.AnomDetector.v[i]),
                          int(np.ceil(len(self.AnomDetector.v[i])*0.75))]).T.to_csv(
                f'{outdir_maps}/L{i}_NEURONS.csv', header=False, index=False
            )

        pd.DataFrame([len(self.AnomDetector.v)]).T.to_csv(
            f'{outdir_maps}/N_LAYERS.csv', header=False, index=False
        )

    def save_exec_stats(self):
        outdir = str(Path(__file__).parents[0]) + '/KitNET/models'
        if not os.path.exists(str(Path(__file__).parents[0]) + '/KitNET/models'):
            os.mkdir(outdir)

        for i in range(0, len(self.df_exec_stats_list), 50000):
            self.df_exec_stats_list[i:i + 50000]
            df_exec_stats = pd.DataFrame(self.df_exec_stats_list[i:i + 50000])
            df_exec_stats.to_pickle(
                f'{outdir}/{self.attack}-m-{self.m}-r-'
                f'{self.train_exact_ratio}-exec-full-{int(i/50000)}.pkl'
            )

    def reset_stats(self):
        print('Reset stats')

        self.stats_mac_ip_src = {}
        self.stats_ip_src = {}
        self.stats_ip = {}
        self.stats_five_t = {}
