#!/usr/bin/env python3

import sys
import logging
import argparse
import time
import yaml
from eval_metrics import eval_kitnet
from pipeline_kitnet import PipelineKitNET

logger = None

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="peregrine-py")
    argparser.add_argument('-p', '--plugin', type=str, help='Plugin')
    argparser.add_argument('-c', '--conf', type=str, help='Config path')
    args = argparser.parse_args()

    with open(args.conf, "r") as yaml_conf:
        conf = yaml.load(yaml_conf, Loader=yaml.FullLoader)

    # configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(args.plugin)

    time_start = time.time()

    # Call function to run the packet processing pipeline.
    if args.plugin == 'kitnet':
        pipeline = PipelineKitNET(
                conf['trace'], conf['labels'], conf['sampl'], conf['train_sampl'],
                conf['exec_sampl_offset'], conf['fm_grace'], conf['ad_grace'], conf['max_ae'],
                conf['fm_model'], conf['el_model'], conf['ol_model'], conf['train_stats'],
                conf['attack'], conf['train_exact_ratio'], conf['exact_stats'],
                conf['save_stats_global'], conf['save_spatial'], time_start)
    pipeline.process()

    time_stop = time.time()
    total_time = time_stop - time_start

    print('Complete. Time elapsed: ', total_time)

    # Call function to perform eval/csv.
    if args.plugin == 'kitnet':
        print('Threshold: ', pipeline.threshold)
        eval_kitnet(pipeline.rmse_list, pipeline.stats_global, pipeline.peregrine_eval,
                    pipeline.threshold, pipeline.det_init_time, pipeline.det_init_pkt_num,
                    pipeline.det_init_pkt_num_dp, pipeline.train_skip, conf['fm_grace'], 
                    conf['ad_grace'], conf['attack'], conf['sampl'], conf['exec_sampl_offset'], 
                    conf['max_ae'], conf['train_exact_ratio'], total_time)

    # exit (bug workaround)
    logger.info("Exiting!")

    # flush logs, stdout, stderr
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()

    # exit (bug workaround)
    # os.kill(os.getpid(), signal.SIGTERM)
