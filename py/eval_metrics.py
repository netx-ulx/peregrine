import os
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn import metrics

ts_datetime = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

def eval_kitnet(
        rmse_list, stats_global, peregrine_eval, threshold, det_init_time, det_init_pkt_num,
        det_init_pkt_num_dp, train_skip, fm_grace, ad_grace, attack, sampling, offset, max_ae,
        train_exact_ratio, total_time):
    outdir = f'{Path(__file__).parents[0]}/eval/kitnet'
    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/kitnet'):
        os.makedirs(outdir, exist_ok=True)
    outpath_peregrine = os.path.join(
        outdir, f'{attack}-m-{max_ae}-{sampling}-r-{train_exact_ratio}-o-{offset}-rmse-{ts_datetime}.csv')

    # Collect the processed packets' RMSE, label, and save to a csv.
    df_peregrine = pd.DataFrame(peregrine_eval, columns=[
        'mac_src', 'ip_src', 'ip_dst', 'ip_type', 'src_proto',
        'dst_proto', 'rmse', 'label'])
    df_peregrine.to_csv(outpath_peregrine, chunksize=10000, index=None)

    # Cut all training rows.
    if train_skip is False:
        df_peregrine_cut = df_peregrine.drop(df_peregrine.index[range(fm_grace + ad_grace)])
    else:
        df_peregrine_cut = df_peregrine
    # df_peregrine_cut = df_peregrine

    # Sort by RMSE.
    df_peregrine_cut.sort_values(by='rmse', ascending=False, inplace=True)

    # Split by threshold.
    peregrine_benign = df_peregrine_cut[df_peregrine_cut.rmse < threshold]
    # print(peregrine_benign.shape[0])
    peregrine_alert = df_peregrine_cut[df_peregrine_cut.rmse >= threshold]
    # print(peregrine_alert.shape[0])

    # Calculate statistics.
    TP = peregrine_alert[peregrine_alert.label == 1].shape[0]
    FP = peregrine_alert[peregrine_alert.label == 0].shape[0]
    TN = peregrine_benign[peregrine_benign.label == 0].shape[0]
    FN = peregrine_benign[peregrine_benign.label == 1].shape[0]

    try:
        TPR = TP / (TP + FN)
    except ZeroDivisionError:
        TPR = 0

    try:
        TNR = TN / (TN + FP)
    except ZeroDivisionError:
        TNR = 0

    try:
        FPR = FP / (FP + TN)
    except ZeroDivisionError:
        FPR = 0

    try:
        FNR = FN / (FN + TP)
    except ZeroDivisionError:
        FNR = 0

    try:
        accuracy = (TP + TN) / (TP + FP + FN + TN)
    except ZeroDivisionError:
        accuracy = 0

    try:
        precision = TP / (TP + FP)
    except ZeroDivisionError:
        precision = 0

    try:
        recall = TP / (TP + FN)
    except ZeroDivisionError:
        recall = 0

    try:
        f1_score = 2 * (recall * precision) / (recall + precision)
    except ZeroDivisionError:
        f1_score = 0

    roc_curve_fpr, roc_curve_tpr, roc_curve_thres = metrics.roc_curve(
        df_peregrine_cut.label, df_peregrine_cut.rmse)
    roc_curve_fnr = 1 - roc_curve_tpr

    auc = metrics.roc_auc_score(df_peregrine_cut.label, df_peregrine_cut.rmse)
    eer = roc_curve_fpr[np.nanargmin(np.absolute((roc_curve_fnr - roc_curve_fpr)))]
    eer_sanity = roc_curve_fnr[np.nanargmin(np.absolute((roc_curve_fnr - roc_curve_fpr)))]

    print(f'Time elapsed (total): {total_time}')
    print(f'Time elapsed (trace) until detection: {det_init_time}')
    print(f'Number of attack packets until detection (CP): {det_init_pkt_num}')
    print(f'Number of attack packets until detection (DP): {det_init_pkt_num_dp}')
    print(f'TP: {TP}')
    print(f'TN: {TN}')
    print(f'FP: {FP}')
    print(f'FN: {FN}')
    print(f'TPR: {TPR}')
    print(f'TNR: {TNR}')
    print(f'FPR: {FPR}')
    print(f'FNR: {FNR}')
    print(f'Accuracy: {accuracy}')
    print(f'Precision: {precision}')
    print(f'Recall: {recall}')
    print(f'F1 Score: {f1_score}')
    print(f'AuC: {auc}')
    print(f'EER: {eer}')
    print(f'EER sanity: {eer_sanity}')

    # Write the eval to a txt.
    f = open(f'{outdir}/{attack}-m-{max_ae}-{sampling}-r-{train_exact_ratio}'
             f'-o-{offset}-metrics-{ts_datetime}.txt', 'a+')
    f.write(f'Time elapsed (total): {total_time}\n')
    f.write(f'Time elapsed (trace) until detection: {det_init_time}\n')
    f.write(f'Number of attack packets until detection (CP): {det_init_pkt_num}\n')
    f.write(f'Number of attack packets until detection (DP): {det_init_pkt_num_dp}\n')
    f.write(f'Threshold: {threshold}\n')
    f.write(f'TP: {TP}\n')
    f.write(f'TN: {TN}\n')
    f.write(f'FP: {FP}\n')
    f.write(f'FN: {FN}\n')
    f.write(f'TPR: {TPR}\n')
    f.write(f'TNR: {TNR}\n')
    f.write(f'FPR: {FPR}\n')
    f.write(f'FNR: {FNR}\n')
    f.write(f'Accuracy: {accuracy}\n')
    f.write(f'Precision: {precision}\n')
    f.write(f'Recall: {recall}\n')
    f.write(f'F1 Score: {f1_score}\n')
    f.write(f'AuC: {auc}\n')
    f.write(f'EER: {eer}\n')
    f.write(f'EER sanity: {eer_sanity}\n')
