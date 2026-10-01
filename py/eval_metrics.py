from pathlib import Path
from datetime import datetime
from sklearn import metrics
import pandas as pd
import numpy as np
import itertools
import csv
import os

ts_datetime = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

def eval_kitnet(rmse_list, stats_global, peregrine_eval, threshold, det_init_time,
                det_init_pkt_num, det_init_pkt_num_dp, train_skip, fm_grace, ad_grace, dataset,
                attack, sampling, offset, max_ae, five_t, only_ol, train_exact_ratio, total_time):
    only_ol_str = ''
    five_t_str = ''
    if only_ol:
        only_ol_str = 'only-ol-'
    if five_t:
        only_ol_str = 'five-t-'

    outdir = f'{Path(__file__).parents[0]}/eval/kitnet/{dataset}'

    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/kitnet/{dataset}'):
        os.makedirs(outdir, exist_ok=True)
    outpath_peregrine = os.path.join(
        outdir, f'{attack}-m-{max_ae}-{sampling}-r-{train_exact_ratio}-o-{offset}-{only_ol_str}{five_t_str}rmse-{ts_datetime}.csv')

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
             f'-o-{offset}-{only_ol_str}{five_t_str}metrics-{ts_datetime}.txt', 'a+')
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

def eval_kitnet_pca(rmse_list, stats_global, peregrine_eval, threshold, det_init_time,
                    det_init_pkt_num, det_init_pkt_num_dp, fm_grace, ad_grace, dataset,
                    attack, sampling, max_ae, only_ol, total_time):
    only_ol_str = ''
    five_t_str = ''
    if only_ol:
        only_ol_str = 'only-ol-'

    outdir = f'{Path(__file__).parents[0]}/eval/kitnet/{dataset}'

    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/kitnet/{dataset}'):
        os.makedirs(outdir, exist_ok=True)
    outpath_peregrine = os.path.join(
        outdir, f'{attack}-pca-m-{max_ae}-{sampling}-{only_ol_str}rmse-{ts_datetime}.csv')

    # Collect the processed packets' RMSE, label, and save to a csv.
    df_peregrine = pd.DataFrame(peregrine_eval, columns=['rmse', 'label'])
    df_peregrine.to_csv(outpath_peregrine, chunksize=10000, index=None)

    # Cut all training rows.
    df_peregrine_cut = df_peregrine.drop(df_peregrine.index[range(fm_grace + ad_grace)])

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
    f = open(f'{outdir}/{attack}-pca-m-{max_ae}-{sampling}'
             f'-{only_ol_str}metrics-{ts_datetime}.txt', 'a+')
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

def eval_planter_if(trace_hdrs, model_exec_out, switch_exec_out, cur_model, cur_model_size,
                    train_size, dataset, attack, switch_model, total_time):
    outdir = f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'
    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'):
        os.makedirs(outdir, exist_ok=True)
    outpath_model   = os.path.join(
        outdir, f'{attack}-{cur_model}-{cur_model_size}-model-{ts_datetime}.txt')

    if switch_model:
        outpath_switch  = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-switch-{ts_datetime}.txt')

    df_trace        = pd.DataFrame(trace_hdrs, columns=['mac_src', 'ip_src', 'ip_dst', 'ip_type',
                                                        'src_proto', 'dst_proto', 'label'])
    df_trace_exec   = df_trace.drop(df_trace.index[range(train_size)])
    trace_labels    = df_trace_exec['label'].to_list()

    # print(model_exec_out[0])

    model_exec_out_0 = []
    model_exec_out_1 = []

    for i, a in enumerate(model_exec_out):
        model_exec_out_0.append(model_exec_out[i][0])
        model_exec_out_1.append(model_exec_out[i][1])

    model_exec_out_flat_0   = list(itertools.chain(*model_exec_out_0))
    model_exec_out_flat_1   = list(itertools.chain(*model_exec_out_1))

    m_tn, m_fp, m_fn, m_tp  = metrics.confusion_matrix(trace_labels, model_exec_out_flat_0).ravel()
    m_accuracy              = metrics.accuracy_score(trace_labels, model_exec_out_flat_0)
    m_precision             = metrics.precision_score(trace_labels, model_exec_out_flat_0)
    m_recall                = metrics.recall_score(trace_labels, model_exec_out_flat_0)
    m_f1                    = metrics.f1_score(trace_labels, model_exec_out_flat_0)
    m_auc                   = metrics.roc_auc_score(trace_labels, model_exec_out_flat_1)

    try:
        m_tpr = m_tp / (m_tp + m_fn)
    except ZeroDivisionError:
        m_tpr = 0

    try:
        m_tnr = m_tn / (m_tn + m_fp)
    except ZeroDivisionError:
        m_tnr = 0

    try:
        m_fpr = m_fp / (m_fp + m_tn)
    except ZeroDivisionError:
        m_fpr = 0

    try:
        m_fnr = m_fn / (m_fn + m_tp)
    except ZeroDivisionError:
        m_fnr = 0

    # Write the eval to a txt.
    f = open(outpath_model, 'a+')
    f.write(f'Time elapsed (total): {total_time}\n')
    f.write(f'TP: {m_tp}\n')
    f.write(f'TN: {m_tn}\n')
    f.write(f'FP: {m_fp}\n')
    f.write(f'FN: {m_fn}\n')
    f.write(f'TPR: {m_tpr}\n')
    f.write(f'TNR: {m_tnr}\n')
    f.write(f'FPR: {m_fpr}\n')
    f.write(f'FNR: {m_fnr}\n')
    f.write(f'Accuracy: {m_accuracy}\n')
    f.write(f'Precision: {m_precision}\n')
    f.write(f'Recall: {m_recall}\n')
    f.write(f'F1 Score: {m_f1}\n')
    f.write(f'AuC: {m_auc}\n')

    if switch_model:
        s_tn, s_fp, s_fn, s_tp  = metrics.confusion_matrix(trace_labels, switch_exec_out[0]).ravel()
        s_accuracy              = metrics.accuracy_score(trace_labels, switch_exec_out[0])
        s_precision             = metrics.precision_score(trace_labels, switch_exec_out[0])
        s_recall                = metrics.recall_score(trace_labels, switch_exec_out[0])
        s_f1                    = metrics.f1_score(trace_labels, switch_exec_out[0])
        s_auc                   = metrics.roc_auc_score(trace_labels, switch_exec_out[1])

        try:
            s_tpr = s_tp / (s_tp + s_fn)
        except ZeroDivisionError:
            s_tpr = 0

        try:
            s_tnr = s_tn / (s_tn + s_fp)
        except ZeroDivisionError:
            s_tnr = 0

        try:
            s_fpr = s_fp / (s_fp + s_tn)
        except ZeroDivisionError:
            s_fpr = 0

        try:
            s_fnr = s_fn / (s_fn + s_tp)
        except ZeroDivisionError:
            s_fnr = 0

        # Write the eval to a txt.
        f = open(outpath_switch, 'a+')
        f.write(f'Time elapsed (total): {total_time}\n')
        f.write(f'TP: {s_tp}\n')
        f.write(f'TN: {s_tn}\n')
        f.write(f'FP: {s_fp}\n')
        f.write(f'FN: {s_fn}\n')
        f.write(f'TPR: {s_tpr}\n')
        f.write(f'TNR: {s_tnr}\n')
        f.write(f'FPR: {s_fpr}\n')
        f.write(f'FNR: {s_fnr}\n')
        f.write(f'Accuracy: {s_accuracy}\n')
        f.write(f'Precision: {s_precision}\n')
        f.write(f'Recall: {s_recall}\n')
        f.write(f'F1 Score: {s_f1}\n')
        f.write(f'AuC: {s_auc}\n')

def eval_planter_if_pca(trace_hdrs, model_exec_out, switch_exec_out, cur_model, cur_model_size,
                        train_size, dataset, attack, switch_model, pca_params, total_time):
    outdir = f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'
    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'):
        os.makedirs(outdir, exist_ok=True)
    outpath_model   = os.path.join(
        outdir, f'{attack}-{cur_model}-{cur_model_size}-pca-{pca_params}-model-{ts_datetime}.txt')

    if switch_model:
        outpath_switch  = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-pca-{pca_params}-switch-{ts_datetime}.txt')

    df_trace        = pd.DataFrame(trace_hdrs, columns=['label'])
    df_trace_exec   = df_trace.drop(df_trace.index[range(train_size)])
    trace_labels    = df_trace_exec['label'].to_list()

    # print(model_exec_out[0])

    model_exec_out_0 = []
    model_exec_out_1 = []

    for i, a in enumerate(model_exec_out):
        model_exec_out_0.append(model_exec_out[i][0])
        model_exec_out_1.append(model_exec_out[i][1])

    model_exec_out_flat_0   = list(itertools.chain(*model_exec_out_0))
    model_exec_out_flat_1   = list(itertools.chain(*model_exec_out_1))

    m_tn, m_fp, m_fn, m_tp  = metrics.confusion_matrix(trace_labels, model_exec_out_flat_0).ravel()
    m_accuracy              = metrics.accuracy_score(trace_labels, model_exec_out_flat_0)
    m_precision             = metrics.precision_score(trace_labels, model_exec_out_flat_0)
    m_recall                = metrics.recall_score(trace_labels, model_exec_out_flat_0)
    m_f1                    = metrics.f1_score(trace_labels, model_exec_out_flat_0)
    m_auc                   = metrics.roc_auc_score(trace_labels, model_exec_out_flat_1)

    try:
        m_tpr = m_tp / (m_tp + m_fn)
    except ZeroDivisionError:
        m_tpr = 0

    try:
        m_tnr = m_tn / (m_tn + m_fp)
    except ZeroDivisionError:
        m_tnr = 0

    try:
        m_fpr = m_fp / (m_fp + m_tn)
    except ZeroDivisionError:
        m_fpr = 0

    try:
        m_fnr = m_fn / (m_fn + m_tp)
    except ZeroDivisionError:
        m_fnr = 0

    # Write the eval to a txt.
    f = open(outpath_model, 'a+')
    f.write(f'Time elapsed (total): {total_time}\n')
    f.write(f'TP: {m_tp}\n')
    f.write(f'TN: {m_tn}\n')
    f.write(f'FP: {m_fp}\n')
    f.write(f'FN: {m_fn}\n')
    f.write(f'TPR: {m_tpr}\n')
    f.write(f'TNR: {m_tnr}\n')
    f.write(f'FPR: {m_fpr}\n')
    f.write(f'FNR: {m_fnr}\n')
    f.write(f'Accuracy: {m_accuracy}\n')
    f.write(f'Precision: {m_precision}\n')
    f.write(f'Recall: {m_recall}\n')
    f.write(f'F1 Score: {m_f1}\n')
    f.write(f'AuC: {m_auc}\n')

    if switch_model:
        s_tn, s_fp, s_fn, s_tp  = metrics.confusion_matrix(trace_labels, switch_exec_out[0]).ravel()
        s_accuracy              = metrics.accuracy_score(trace_labels, switch_exec_out[0])
        s_precision             = metrics.precision_score(trace_labels, switch_exec_out[0])
        s_recall                = metrics.recall_score(trace_labels, switch_exec_out[0])
        s_f1                    = metrics.f1_score(trace_labels, switch_exec_out[0])
        s_auc                   = metrics.roc_auc_score(trace_labels, switch_exec_out[1])

        try:
            s_tpr = s_tp / (s_tp + s_fn)
        except ZeroDivisionError:
            s_tpr = 0

        try:
            s_tnr = s_tn / (s_tn + s_fp)
        except ZeroDivisionError:
            s_tnr = 0

        try:
            s_fpr = s_fp / (s_fp + s_tn)
        except ZeroDivisionError:
            s_fpr = 0

        try:
            s_fnr = s_fn / (s_fn + s_tp)
        except ZeroDivisionError:
            s_fnr = 0

        # Write the eval to a txt.
        f = open(outpath_switch, 'a+')
        f.write(f'Time elapsed (total): {total_time}\n')
        f.write(f'TP: {s_tp}\n')
        f.write(f'TN: {s_tn}\n')
        f.write(f'FP: {s_fp}\n')
        f.write(f'FN: {s_fn}\n')
        f.write(f'TPR: {s_tpr}\n')
        f.write(f'TNR: {s_tnr}\n')
        f.write(f'FPR: {s_fpr}\n')
        f.write(f'FNR: {s_fnr}\n')
        f.write(f'Accuracy: {s_accuracy}\n')
        f.write(f'Precision: {s_precision}\n')
        f.write(f'Recall: {s_recall}\n')
        f.write(f'F1 Score: {s_f1}\n')
        f.write(f'AuC: {s_auc}\n')

def eval_planter_pca(trace_hdrs, model_exec_out, switch_exec_out, cur_model, cur_model_size,
                     train_size, dataset, attack, switch_model, corr_aggr, total_time):
    outdir = f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'
    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/planter/{dataset}/{cur_model}/metrics'):
        os.makedirs(outdir, exist_ok=True)
    outpath_model       = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-model-feats-{ts_datetime}.csv')
    outpath_labels      = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-labels-{ts_datetime}.csv')
    outpath_corr_aggr   = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-corr-aggr-{ts_datetime}.csv')

    if switch_model:
        outpath_switch  = os.path.join(
            outdir, f'{attack}-{cur_model}-{cur_model_size}-switch-feats-{ts_datetime}.csv')

        with open(outpath_corr_aggr, mode='w', newline='') as f:
            writer = csv.writer(f)
            for i in corr_aggr:
                writer.writerow([i])

    model_exec_out_flat = list(itertools.chain(*model_exec_out))

    pca_columns = []
    for i in range(len(model_exec_out_flat[0])):
        pca_columns.append(f'pca_{i}')

    df_feats_m = pd.DataFrame(model_exec_out_flat, columns=pca_columns)
    df_feats_m.to_csv(outpath_model, index=False)

    df_trace = pd.DataFrame(trace_hdrs, columns=['mac_src', 'ip_src', 'ip_dst', 'ip_type',
                                                 'src_proto', 'dst_proto', 'label'])
    df_trace['label'].to_csv(outpath_labels, index=False)

    if switch_model:
        switch_exec_out_flat = list(itertools.chain(*switch_exec_out))
        df_feats_s = pd.DataFrame(switch_exec_out_flat, columns=['pca_0', 'pca_1'])
        df_feats_s.to_csv(outpath_switch, index=False)
