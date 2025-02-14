import os
import numpy as np
import pickle
from pathlib import Path
from .dA import DA, DAParams
from .CorClust import CorClust


# This class represents a KitNET machine learner. KitNET is a lightweight online anomaly detection algorithm based on
# an ensemble of autoencoders. For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble
# of Autoencoders for Online Network Intrusion Detection For licensing information, see the end of this document

class KitNET:
    # n: the number of features in your input dataset (i.e., x \in R^n) m: the maximum size of any autoencoder in the
    # ensemble layer AD_grace_period: the number of instances the network will learn from before producing anomaly
    # scores FM_grace_period: the number of instances which will be taken to learn the feature mapping. If 'None',
    # then FM_grace_period=AM_grace_period learning_rate: the default stochastic gradient descent learning rate for
    # all autoencoders in the KitNET instance. hidden_ratio: the default ratio of hidden to visible neurons. E.g.,
    # 0.75 will cause roughly a 25% compression in the hidden layer. feature_map: One may optionally provide a
    # feature map instead of learning one. The map must be a list, where the i-th entry contains a list of the
    # feature indices to be assigned to the i-th autoencoder in the ensemble. For example, [[2,5,3],[4,0,1],[6,7]]
    def __init__(self, n, max_autoencoder_size=10, fm_grace_period=None, ad_grace_period=10000,
                 learning_rate=0.1, hidden_ratio=0.75, feature_map=None, ensemble_layer=None,
                 output_layer=None, attack='', train_exact_ratio=0):
        # Parameters:
        self.AD_grace_period = ad_grace_period
        if fm_grace_period is None:
            self.FM_grace_period = ad_grace_period
        else:
            self.FM_grace_period = fm_grace_period
        if max_autoencoder_size <= 0:
            self.m = 1
        else:
            self.m = max_autoencoder_size
        self.lr = learning_rate
        self.hr = hidden_ratio
        self.n = n

        # Variables
        self.n_trained = 0  # the number of training instances so far
        self.n_executed = 0  # the number of executed instances so far
        self.ensembleLayer = []
        self.outputLayer = None
        self.attack = attack
        self.train_exact_ratio = train_exact_ratio

        # Check if the feature map, ensemble layer and output layer are provided as input.
        # If so, skip the training phase.

        if feature_map is not None:
            with open(feature_map, 'rb') as f_fm:
                self.v = pickle.load(f_fm)
            self.__createAD__()
            print("Feature-Mapper: execute-mode, Anomaly-Detector: train-mode")
        else:
            self.v = None
            print("Feature-Mapper: train-mode, Anomaly-Detector: off-mode")
        self.FM = CorClust(self.n)  # incremental feature clustering for the feature mapping process

        if ensemble_layer is not None and output_layer is not None:
            with open(ensemble_layer, 'rb') as f_el:
                self.ensembleLayer = pickle.load(f_el)
            with open(output_layer, 'rb') as f_ol:
                self.outputLayer = pickle.load(f_ol)
            self.n_trained = self.FM_grace_period + self.AD_grace_period + 1
            print("Feature-Mapper: execute-mode, Anomaly-Detector: execute-mode")

    # If FM_grace_period+AM_grace_period has passed, then this function executes KitNET on x.
    # Otherwise, this function learns from x. x: a numpy array of length n.
    # Note: KitNET automatically performs 0-1 normalization on all attributes.
    def process(self, x):
        # If both the FM and AD are in execute-mode
        if self.n_trained >= self.FM_grace_period + self.AD_grace_period:
            return self.execute(x)
        else:
            return self.train(x)

    # force train KitNET on x
    # returns the anomaly score of x during training (do not use for alerting)
    def train(self, x):
        if self.n_trained < self.FM_grace_period and self.v is None:
            # If the FM is in train-mode, and the user has not supplied a feature mapping
            # update the incremental correlation matrix
            self.FM.update(x)
            if self.n_trained == self.FM_grace_period - 1:  # If the feature mapping should be instantiated
                self.v = self.FM.cluster(self.m)
                self.__createAD__()
                print("The Feature-Mapper found a mapping: " + str(self.n) + " features to " + str(
                    len(self.v)) + " autoencoders.")
                print("Feature-Mapper: execute-mode, Anomaly-Detector: train-mode")
            self.n_trained += 1
            return 0.0
        else:  # train
            # Ensemble Layer
            S_l1 = np.zeros(len(self.ensembleLayer))
            for a in range(len(self.ensembleLayer)):
                # make sub instance for autoencoder 'a'
                xi = x[self.v[a]]
                S_l1[a] = self.ensembleLayer[a].train(xi)
            # OutputLayer
            output = self.outputLayer.train(S_l1)
            if self.n_trained == self.AD_grace_period + self.FM_grace_period - 1:
                print("Feature-Mapper: execute-mode, Anomaly-Detector: execute-mode")

                outdir = str(Path(__file__).parents[0]) + '/models'
                if not os.path.exists(str(Path(__file__).parents[0]) + '/models'):
                    os.mkdir(outdir)

                with open(outdir + '/' + self.attack + '-m-' + str(self.m)
                          + '-r-' + str(self.train_exact_ratio) + '-fm' + '.txt', 'wb') as f_fm:
                    pickle.dump(self.v, f_fm)
                with open(outdir + '/' + self.attack + '-m-' + str(self.m)
                          + '-r-' + str(self.train_exact_ratio) + '-el' + '.txt', 'wb') as f_el:
                    pickle.dump(self.ensembleLayer, f_el)
                with open(outdir + '/' + self.attack + '-m-' + str(self.m)
                          + '-r-' + str(self.train_exact_ratio) + '-ol' + '.txt', 'wb') as f_ol:
                    pickle.dump(self.outputLayer, f_ol)
            self.n_trained += 1
            return output

    # force execute KitNET on x
    def execute(self, x):
        if self.v is None:
            raise RuntimeError(
                'KitNET Cannot execute x, because a feature mapping has not yet been learned or provided. Try running '
                'process(x) instead.')
        else:
            self.n_executed += 1
            # Ensemble Layer
            S_l1 = np.zeros(len(self.ensembleLayer))
            for a in range(len(self.ensembleLayer)):
                # make sub inst
                xi = x[self.v[a]]
                S_l1[a] = self.ensembleLayer[a].execute(xi)
            # OutputLayer
            return self.outputLayer.execute(S_l1)

    def __createAD__(self):
        # construct ensemble layer
        for ad_map in self.v:
            params = DAParams(n_visible=len(ad_map), n_hidden=0, lr=self.lr, corruption_level=0,
                              grace_period=0, hidden_ratio=self.hr)
            self.ensembleLayer.append(DA(params))

        # construct output layer
        params = DAParams(len(self.v), n_hidden=0, lr=self.lr, corruption_level=0,
                          grace_period=0, hidden_ratio=self.hr)
        self.outputLayer = DA(params)

# Copyright (c) 2017 Yisroel Mirsky
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
