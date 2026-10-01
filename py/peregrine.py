#!/usr/bin/env python3

from eval_metrics import eval_kitnet, eval_kitnet_pca
from eval_metrics import eval_planter_if, eval_planter_if_pca, eval_planter_pca
from pipeline_kitnet import PipelineKitNET
from pipeline_kitnet_pca import PipelineKitNET_PCA
from pipeline_hv import PipelineHv
from pipeline_planter import PipelinePlanter
import argparse
import time
import yaml

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="peregrine-py")
    argparser.add_argument('-p', '--plugin', type=str, help='Plugin')
    argparser.add_argument('--pca_feats', type=bool, default=False, help='PCA')
    argparser.add_argument('-c', '--conf', type=str, help='Config path')
    args = argparser.parse_args()

    with open(args.conf, "r") as yaml_conf:
        conf = yaml.load(yaml_conf, Loader=yaml.FullLoader)

    time_start = time.time()

    # Call function to run the packet processing pipeline.
    if args.plugin == 'kitnet' and not args.pca_feats:
        pipeline = PipelineKitNET(
                conf['trace'],
                conf['labels'],
                conf['sampl'],
                conf['train_sampl'],
                conf['exec_sampl_offset'],
                conf['fm_grace'],
                conf['ad_grace'],
                conf['max_ae'],
                conf['learning_rate'],
                conf['hidden_ratio'],
                conf['num_features'],
                conf['five_t'],
                conf['only_ol'],
                conf['fm_model'],
                conf['el_model'],
                conf['ol_model'],
                conf['train_stats'],
                conf['dataset'],
                conf['attack'],
                conf['train_exact_ratio'],
                conf['exact_stats'],
                conf['save_stats_global'],
                conf['save_spatial'],
                time_start)
    if args.plugin == 'kitnet' and args.pca_feats:
        pipeline = PipelineKitNET_PCA(
                conf['pca_feats'],
                conf['pca_labels'],
                conf['sampl'],
                conf['fm_grace'],
                conf['ad_grace'],
                conf['max_ae'],
                conf['learning_rate'],
                conf['hidden_ratio'],
                conf['only_ol'],
                conf['dataset'],
                conf['attack'],
                conf['save_stats_global'],
                time_start)
    elif args.plugin == 'hypervision':
        pipeline = PipelineHv(
                conf['trace'],
                conf['attack'],
                conf['hv_dataset'],
                conf['veth'])
    elif args.plugin == 'planter':
        pipeline = PipelinePlanter(
                conf['trace'],
                conf['labels'],
                conf['planter_conf'],
                conf['planter_base_dir'],
                conf['train_size'],
                conf['attack'],
                conf['switch_model'],
                conf['pca'],
                time_start)

    if args.plugin == 'planter' and conf['pca']:
        pipeline.process_pca_feats(conf['pca_feats'], conf['pca_labels'])
    else:
        pipeline.process()

    time_stop   = time.time()
    total_time  = time_stop - time_start

    print('Complete. Time elapsed: ', total_time)

    # Call function to perform eval/csv.
    if args.plugin == 'kitnet' and not args.pca_feats:
        eval_kitnet(
                pipeline.rmse_list,
                pipeline.stats_global,
                pipeline.peregrine_eval,
                pipeline.threshold,
                pipeline.det_init_time,
                pipeline.det_init_pkt_num,
                pipeline.det_init_pkt_num_dp,
                pipeline.train_skip,
                conf['fm_grace'],
                conf['ad_grace'],
                conf['dataset'],
                conf['attack'],
                conf['sampl'],
                conf['exec_sampl_offset'],
                conf['max_ae'],
                conf['five_t'],
                conf['only_ol'],
                conf['train_exact_ratio'],
                total_time)
    elif args.plugin == 'kitnet' and args.pca_feats:
        eval_kitnet_pca(
                pipeline.rmse_list,
                pipeline.stats_global,
                pipeline.peregrine_eval,
                pipeline.threshold,
                pipeline.det_init_time,
                pipeline.det_init_pkt_num,
                pipeline.det_init_pkt_num_dp,
                conf['fm_grace'],
                conf['ad_grace'],
                conf['dataset'],
                conf['attack'],
                conf['sampl'],
                conf['max_ae'],
                conf['only_ol'],
                total_time)
    elif args.plugin == 'planter' and pipeline.cur_model == 'if' and not conf['pca']:
        eval_planter_if(
                pipeline.trace_hdrs,
                pipeline.model_exec_out,
                pipeline.tables_exec_out,
                pipeline.cur_model,
                pipeline.cur_model_size,
                conf['train_size'],
                conf['dataset'],
                conf['attack'],
                conf['switch_model'],
                total_time)
    elif args.plugin == 'planter' and pipeline.cur_model == 'if' and conf['pca']:
        eval_planter_if_pca(
                pipeline.trace_hdrs,
                pipeline.model_exec_out,
                pipeline.tables_exec_out,
                pipeline.cur_model,
                pipeline.cur_model_size,
                conf['train_size'],
                conf['dataset'],
                conf['attack'],
                conf['switch_model'],
                conf['pca_params'],
                total_time)
    elif args.plugin == 'planter' and pipeline.cur_model == 'pca':
        eval_planter_pca(
                pipeline.trace_hdrs,
                pipeline.model_exec_out,
                pipeline.tables_exec_out,
                pipeline.cur_model,
                pipeline.cur_model_size,
                conf['train_size'],
                conf['dataset'],
                conf['attack'],
                conf['switch_model'],
                pipeline.corr_aggr,
                total_time)

    print('Done.')
