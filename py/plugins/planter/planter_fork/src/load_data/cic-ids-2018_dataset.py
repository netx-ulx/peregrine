import copy
import numpy as np
import pandas as pd
import socket
import struct
from sklearn.model_selection import train_test_split

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def ip2bin(ip):
    ip1 = '.'.join([bin(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

def ip2hex(ip):
    ip1 = '-'.join([hex(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

def bin2dec(ip):
    return int(ip,2)

def load_data(num_features, data, labels):
    df_data = pd.read_csv(data,
                          usecols=['ip.src', 'ip.dst', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
                                   'udp.srcport', 'udp.dstport'])

    print('df_data.head before:')
    print(df_data.head())

    df_data['port.src'] = df_data['tcp.srcport'].fillna(df_data['udp.srcport'])
    df_data['port.dst'] = df_data['tcp.dstport'].fillna(df_data['udp.dstport'])

    df_data = df_data.drop('tcp.srcport', axis=1)
    df_data = df_data.drop('tcp.dstport', axis=1)
    df_data = df_data.drop('udp.srcport', axis=1)
    df_data = df_data.drop('udp.dstport', axis=1)

    print('df_data.head after:')
    print(df_data.head())

    df_labels = pd.read_csv(labels, header=None)

    df_labels.columns = ['label']

    df_full = pd.concat([df_data, df_labels], axis=1)

    print(f'size before: {len(df_full)}')
    df_full = df_full[(df_full['ip.proto'] == 17)
                       | (df_full['ip.proto'] == 6)
                       | (df_full['ip.proto'] == 1)]
    print(f'size after: {len(df_full)}')

    df_full[['ip.src.1', 'ip.src.2', 'ip.src.3', 'ip.src.4']] = \
            df_full['ip.src'].apply(ip2bin).str.split('.',expand=True)
    df_full[['ip.dst.1', 'ip.dst.2', 'ip.dst.3', 'ip.dst.4']] = \
            df_full['ip.dst'].apply(ip2bin).str.split('.',expand=True)

    df_full['ip.src.1'] = df_full['ip.src.1'].apply(bin2dec)
    df_full['ip.src.2'] = df_full['ip.src.2'].apply(bin2dec)
    df_full['ip.src.3'] = df_full['ip.src.3'].apply(bin2dec)
    df_full['ip.src.4'] = df_full['ip.src.4'].apply(bin2dec)
    df_full['ip.dst.1'] = df_full['ip.dst.1'].apply(bin2dec)
    df_full['ip.dst.2'] = df_full['ip.dst.2'].apply(bin2dec)
    df_full['ip.dst.3'] = df_full['ip.dst.3'].apply(bin2dec)
    df_full['ip.dst.4'] = df_full['ip.dst.4'].apply(bin2dec)

    df_full['ip.src'] = df_full['ip.src'].astype(str)
    df_full['ip.dst'] = df_full['ip.dst'].astype(str)

    print('df_full.head:')
    print(df_full.head())

    print(f'TEST size before: {len(df_full)}')
    #Replace values with NaN, inf, -inf
    df_full.replace([np.inf, -np.inf], np.nan)
    #print('')
    df_full.replace([np.inf, -np.inf], np.nan)
    ##Remove rows containing NaN
    df_full.dropna(how="any", inplace = True)
    df_full = df_full[df_full.replace([np.inf, -np.inf], np.nan).notnull().all(axis=1)]
    print(f'TEST size after: {len(df_full)}')

    df_full.describe()
    df_full.info()
    print(df_full['label'].value_counts())

    used_features = ['port.src', 'port.dst', 'ip.proto', 'ip.src.1', 'ip.dst.4'][:num_features]

    X = copy.deepcopy(df_full[used_features].astype('int'))
    y = copy.deepcopy(df_full['label'].astype('int'))

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=1000000, shuffle=False)
    # X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.2, stratify=y, random_state=42, shuffle=True)

    print('dataset is loaded')

    return X_train, np.array(y_train), X_test, np.array(y_test), used_features
