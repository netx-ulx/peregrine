import os
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn import metrics

ts_datetime = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]


def eval_metrics(rmse_list, cur_stats_global, peregrine_eval, threshold, train_skip, fm_grace,
                 ad_grace, attack, sampling, max_ae, train_exact_ratio, total_time):
    outdir = str(Path(__file__).parents[0]) + '/eval/'
    if not os.path.exists(str(Path(__file__).parents[0]) + '/eval'):
        os.makedirs(outdir, exist_ok=True)
    outpath_peregrine = os.path.join(outdir, attack + '-m-' + str(max_ae) + '-'
                                     + str(sampling) + '-r-' + str(train_exact_ratio)
                                     + '-rmse-' + ts_datetime + '.csv')
    outpath_cur_stats_global = os.path.join(outdir, attack + '-m-' + str(max_ae) + '-'
                                            + str(sampling) + '-r-' + str(train_exact_ratio)
                                            + '-stats-' + ts_datetime + '.csv')

    # Collect the global stats and save to a csv.
    df_cur_stats_global = pd.DataFrame(cur_stats_global)
    df_cur_stats_global.to_csv(outpath_cur_stats_global, index=None)

    # Collect the processed packets' RMSE, label, and save to a csv.
    df_peregrine = pd.DataFrame(peregrine_eval,
                                columns=['mac_src', 'ip_src', 'ip_dst', 'ip_type', 'src_proto',
                                         'dst_proto', 'rmse', 'label'])
    df_peregrine.to_csv(outpath_peregrine, index=None)

    # Cut all training rows.
    if train_skip is False:
        df_peregrine_cut = df_peregrine.drop(df_peregrine.index[range(fm_grace + ad_grace)])
    else:
        df_peregrine_cut = df_peregrine

    # Sort by RMSE.
    df_peregrine_cut.sort_values(by='rmse', ascending=False, inplace=True)

    # Split by threshold.
    peregrine_benign = df_peregrine_cut[df_peregrine_cut.rmse < threshold]
    print(peregrine_benign.shape[0])
    peregrine_alert = df_peregrine_cut[df_peregrine_cut.rmse >= threshold]
    print(peregrine_alert.shape[0])

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

    roc_curve_fpr, roc_curve_tpr, roc_curve_thres = metrics.roc_curve(df_peregrine_cut.label, df_peregrine_cut.rmse)
    roc_curve_fnr = 1 - roc_curve_tpr

    try:
        auc = metrics.roc_auc_score(df_peregrine_cut.label, df_peregrine_cut.rmse)
        eer = roc_curve_fpr[np.nanargmin(np.absolute((roc_curve_fnr - roc_curve_fpr)))]
        eer_sanity = roc_curve_fnr[np.nanargmin(np.absolute((roc_curve_fnr - roc_curve_fpr)))]
    except ValueError:
        auc = "null"
        eer = "null"
        eer_sanity = "null"

    print('TP: ' + str(TP))
    print('TN: ' + str(TN))
    print('FP: ' + str(FP))
    print('FN: ' + str(FN))
    print('TPR: ' + str(TPR))
    print('TNR: ' + str(TNR))
    print('FPR: ' + str(FPR))
    print('FNR: ' + str(FNR))
    print('Accuracy: ' + str(accuracy))
    print('precision: ' + str(precision))
    print('Recall: ' + str(recall))
    print('F1 Score: ' + str(f1_score))
    print('AuC: ' + str(auc))
    print('EER: ' + str(eer))
    print('EER sanity: ' + str(eer_sanity))

    # Write the eval to a txt.
    f = open(outdir + '/' + attack + '-m-' + str(max_ae) + '-' + str(sampling)
             + '-r-' + str(train_exact_ratio) + '-metrics-' + ts_datetime + '.txt', 'a+')
    f.write('Time elapsed: ' + str(total_time) + '\n')
    f.write('Threshold: ' + str(threshold) + '\n')
    f.write('TP: ' + str(TP) + '\n')
    f.write('TN: ' + str(TN) + '\n')
    f.write('FP: ' + str(FP) + '\n')
    f.write('FN: ' + str(FN) + '\n')
    f.write('TPR: ' + str(TPR) + '\n')
    f.write('TNR: ' + str(TNR) + '\n')
    f.write('FPR: ' + str(FPR) + '\n')
    f.write('FNR: ' + str(FNR) + '\n')
    f.write('Accuracy: ' + str(accuracy) + '\n')
    f.write('Precision: ' + str(precision) + '\n')
    f.write('Recall: ' + str(recall) + '\n')
    f.write('F1 Score: ' + str(f1_score) + '\n')
    f.write('AuC: ' + str(auc) + '\n')
    f.write('EER: ' + str(eer) + '\n')
    f.write('EER sanity: ' + str(eer_sanity) + '\n')
    f.close()
