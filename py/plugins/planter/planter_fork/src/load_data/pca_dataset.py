import copy
import numpy as np
import pandas as pd
import socket
import struct
from sklearn.model_selection import train_test_split

def load_data(num_features, data, labels):
    df_data    = pd.read_csv(data,
                             usecols=['pca_0', 'pca_1'])

    print('df_data.head before:')
    print(df_data.head())

    df_labels = pd.read_csv(labels, header=None)

    df_labels.columns = ['label']

    df_full = pd.concat([df_data, df_labels], axis=1)

    print(df_full.head())

    used_features = ['pca_0', 'pca_1'][:num_features]

    X = copy.deepcopy(df_full[used_features].astype('int'))
    y = copy.deepcopy(df_full['label'].astype('int'))
    # del data
    # gc.collect()

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=1000000, shuffle=False)
    # X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.2, stratify=y, random_state=42, shuffle=True)

    print('dataset is loaded')

    print(X_train.head())

    return X_train, np.array(y_train), X_test, np.array(y_test), used_features
