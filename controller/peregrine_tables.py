import logging
import bfrt_grpc.client as gc
from table import Table


class SamplingRate(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(SamplingRate, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('sampling_rate')
        self.logger.info('Setting up sampling_rate table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.sampling_rate')

        # clear and add defaults
        self.clear()

    def add_entry(self, dummy_key, rate):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on sampling_rate table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.sampling_rate_key', dummy_key)])],
           [self.table.make_data(
               [gc.DataTuple('sampling_rate', rate)],
               'SwitchIngress_a.set_sampling_rate')])


class FwdRecirculation_a(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FwdRecirculation_a, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('a_fwd_recirculation')
        self.logger.info('Setting up a_fwd_recirculation table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.fwd_recirculation')

        # clear and add defaults
        self.clear()

    def add_entry(self, ig_port, recirc_toggle, int_port):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on a_fwd_recirculation table...')

        if recirc_toggle:
            self.table.entry_add(
                target,
                [self.table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', ig_port),
                        gc.KeyTuple('ig_md.meta.recirc_toggle', recirc_toggle)])],
                [self.table.make_data(
                    [gc.DataTuple('port', int_port)],
                    'SwitchIngress_a.modify_eg_port')])
        else:
            self.table.entry_add(
                target,
                [self.table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', ig_port),
                        gc.KeyTuple('ig_md.meta.recirc_toggle', recirc_toggle)])],
                [self.table.make_data(
                    [gc.DataTuple('port', int_port)],
                    'SwitchIngress_a.fwd')])


class FwdRecirculation_b(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FwdRecirculation_b, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('b_fwd_recirculation')
        self.logger.info('Setting up b_fwd_recirculation table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.fwd_recirculation')

        # clear and add defaults
        self.clear()

    def add_entry(self, ig_port, eg_port):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on b_fwd_recirculation table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_intr_md.ingress_port', ig_port)])],
           [self.table.make_data(
               [gc.DataTuple('port', eg_port)],
               'SwitchIngress_b.modify_eg_port')])


class MacIpSrcDecayCheck(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(MacIpSrcDecayCheck, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('mac_ip_src_decay_check')
        self.logger.info('Setting up mac_ip_src_decay_check table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_mac_ip_src_a.decay_check')

        # clear and add defaults
        self.clear()

    def add_entry(self, counter, interval):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on mac_ip_src_decay_check table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.decay_cntr', counter)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_mac_ip_src_a.decay_check_' + str(interval))])


class IpSrcDecayCheck(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpSrcDecayCheck, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_src_decay_check')
        self.logger.info('Setting up ip_src_decay_check table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_src_a.decay_check')

        # clear and add defaults
        self.clear()

    def add_entry(self, counter, interval):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_src_decay_check table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.decay_cntr', counter)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_src_a.decay_check_' + str(interval))])


class IpDecayCheck(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpDecayCheck, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_decay_check')
        self.logger.info('Setting up ip_decay_check table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.decay_check')

        # clear and add defaults
        self.clear()

    def add_entry(self, counter, interval):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_decay_check table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.decay_cntr', counter)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.decay_check_' + str(interval))])


class FiveTDecayCheck(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTDecayCheck, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_decay_check')
        self.logger.info('Setting up five_t_decay_check table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.decay_check')

        # clear and add defaults
        self.clear()

    def add_entry(self, counter, interval):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_decay_check table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.decay_cntr', counter)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.decay_check_' + str(interval))])


class MacIpSrcMean(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(MacIpSrcMean, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('mac_ip_src_mean')
        self.logger.info('Setting up mac_ip_src_mean table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_mac_ip_src_b.mean')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on mac_ip_src_mean table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.mac_ip_src_pkt_cnt', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_mac_ip_src_b.rshift_mean_' + str(div))])


class IpSrcMean(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpSrcMean, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_src_mean')
        self.logger.info('Setting up ip_src_mean table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_src_b.mean')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_src_mean table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.ip_src_pkt_cnt', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_src_b.rshift_mean_' + str(div))])


class IpMean0(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpMean0, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_mean_0')
        self.logger.info('Setting up ip_mean_0 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.mean_0')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_mean_0 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.pkt_cnt_0', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.rshift_mean_' + str(div))])


class IpResStructUpdate(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpResStructUpdate, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_res_struct_update')
        self.logger.info('Setting up ip_res_struct_update table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.res_struct_update')

        # clear and add defaults
        self.clear()

    def add_entry(self, flag, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_res_struct_update table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.res_check', flag)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.res_' + div)])


class IpResProd(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpResProd, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_res_prod')
        self.logger.info('Setting up ip_res_prod table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.res_prod')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_res_prod table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.res_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.lshift_res_prod_' + str(div))])


class IpSumResProdGetCarry(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpSumResProdGetCarry, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_sum_res_prod_get_carry')
        self.logger.info('Setting up ip_sum_res_prod_get_carry table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.sum_res_prod_get_carry')

        # clear and add defaults
        self.clear()

    def add_entry(self, power, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_sum_res_prod_get_carry table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.decay_check', power)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.sum_res_prod_get_carry_decay_' + str(div))])


class IpPktCnt1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpPktCnt1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_pkt_cnt_1_access')
        self.logger.info('Setting up ip_pkt_cnt_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.pkt_cnt_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_pkt_cnt_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.pkt_cnt_1_' + div)])


class IpSs1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpSs1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_ss_1_access')
        self.logger.info('Setting up ip_ss_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.ss_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_ss_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.ss_1_' + div)])


class IpMean1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpMean1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_mean_1_access')
        self.logger.info('Setting up ip_mean_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_ip_a.mean_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_mean_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_ip_a.mean_' + div)])


class IpMeanSs0(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpMeanSs0, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_mean_ss_0')
        self.logger.info('Setting up ip_mean_ss_0 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.mean_ss_0')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_mean_ss_0 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.ip_pkt_cnt', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.rshift_mean_ss_0_' + str(div))])


class IpMeanSs1(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpMeanSs1, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_mean_ss_1')
        self.logger.info('Setting up ip_mean_ss_1 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.mean_ss_1')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_mean_ss_1 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.ip_pkt_cnt_1', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.rshift_mean_ss_1_' + str(div))])


class IpVariance0Abs(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpVariance0Abs, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_variance_0_abs')
        self.logger.info('Setting up ip_variance_0_abs table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.variance_0_abs')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_variance_0_abs table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.variance_0', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.variance_0_' + div)])


class IpVariance1Abs(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpVariance1Abs, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_variance_1_abs')
        self.logger.info('Setting up ip_variance_1_abs table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.variance_1_abs')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_variance_1_abs table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.variance_1', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.variance_1_' + div)])


class IpCov(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpCov, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_cov')
        self.logger.info('Setting up ip_cov table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.cov')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_cov table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.ip_pkt_cnt_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.rshift_cov_' + str(div))])


class IpStdDevProd(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpStdDevProd, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_std_dev_prod')
        self.logger.info('Setting up ip_std_dev_prod table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.std_dev_prod')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_std_dev_prod table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.std_dev_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.lshift_std_dev_prod_' + str(div))])


class IpPcc(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(IpPcc, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('ip_pcc')
        self.logger.info('Setting up ip_pcc table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_ip_b.pcc')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on ip_pcc table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_ip.std_dev_prod', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_ip_b.rshift_pcc_' + str(div))])


class FiveTMean0(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTMean0, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_mean_0')
        self.logger.info('Setting up five_t_mean_0 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.mean_0')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_mean_0 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.pkt_cnt_0', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.rshift_mean_' + str(div))])


class FiveTResStructUpdate(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTResStructUpdate, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_res_struct_update')
        self.logger.info('Setting up five_t_res_struct_update table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.res_struct_update')

        # clear and add defaults
        self.clear()

    def add_entry(self, flag, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_res_struct_update table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.res_check', flag)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.res_' + div)])


class FiveTResProd(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTResProd, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_res_prod')
        self.logger.info('Setting up five_t_res_prod table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.res_prod')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_res_prod table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.res_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.lshift_res_prod_' + str(div))])


class FiveTSumResProdGetCarry(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTSumResProdGetCarry, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_sum_res_prod_get_carry')
        self.logger.info('Setting up five_t_sum_res_prod_get_carry table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.sum_res_prod_get_carry')

        # clear and add defaults
        self.clear()

    def add_entry(self, power, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_sum_res_prod_get_carry table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.decay_check', power)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.sum_res_prod_get_carry_decay_' + str(div))])


class FiveTPktCnt1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTPktCnt1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_pkt_cnt_1_access')
        self.logger.info('Setting up five_t_pkt_cnt_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.pkt_cnt_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_pkt_cnt_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.pkt_cnt_1_' + div)])


class FiveTSs1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTSs1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_ss_1_access')
        self.logger.info('Setting up five_t_ss_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.ss_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_ss_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.ss_1_' + div)])


class FiveTMean1Access(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTMean1Access, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_mean_1_access')
        self.logger.info('Setting up five_t_mean_1_access table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_a.stats_five_t_a.mean_1_access')

        # clear and add defaults
        self.clear()

    def add_entry(self, const, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_mean_1_access table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.meta.recirc_toggle', const)])],
           [self.table.make_data([], 'SwitchIngress_a.stats_five_t_a.mean_' + div)])


class FiveTMeanSs0(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTMeanSs0, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_mean_ss_0')
        self.logger.info('Setting up five_t_mean_ss_0 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.mean_ss_0')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_mean_ss_0 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.five_t_pkt_cnt', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.rshift_mean_ss_0_' + str(div))])


class FiveTMeanSs1(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTMeanSs1, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_mean_ss_1')
        self.logger.info('Setting up five_t_mean_ss_1 table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.mean_ss_1')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_mean_ss_1 table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.five_t_pkt_cnt_1', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.rshift_mean_ss_1_' + str(div))])


class FiveTVariance0Abs(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTVariance0Abs, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_variance_0_abs')
        self.logger.info('Setting up five_t_variance_0_abs table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.variance_0_abs')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_variance_0_abs table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.variance_0', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.variance_0_' + div)])


class FiveTVariance1Abs(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTVariance1Abs, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_variance_1_abs')
        self.logger.info('Setting up five_t_variance_1_abs table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.variance_1_abs')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, const, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_variance_1_abs table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.variance_1', const, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.variance_1_' + div)])


class FiveTCov(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTCov, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_cov')
        self.logger.info('Setting up five_t_cov table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.cov')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_cov table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('hdr.peregrine.five_t_pkt_cnt_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.rshift_cov_' + str(div))])


class FiveTStdDevProd(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTStdDevProd, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_std_dev_prod')
        self.logger.info('Setting up five_t_std_dev_prod table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.std_dev_prod')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_std_dev_prod table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.std_dev_1', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.lshift_std_dev_prod_' + str(div))])


class FiveTPcc(Table):

    def __init__(self, client, bfrt_info):
        # set up base class
        super(FiveTPcc, self).__init__(client, bfrt_info)

        self.logger = logging.getLogger('five_t_pcc')
        self.logger.info('Setting up five_t_pcc table...')

        # get this table
        self.table = self.bfrt_info.table_get('SwitchIngress_b.stats_five_t_b.pcc')

        # clear and add defaults
        self.clear()

    def add_entry(self, priority, power, mask, div):
        # target all pipes on device 0
        target = gc.Target(device_id=0)

        self.logger.info('Programming entries on five_t_pcc table...')

        self.table.entry_add(
           target,
           [self.table.make_key(
               [gc.KeyTuple('ig_md.stats_five_t.std_dev_prod', power, mask),
                gc.KeyTuple('$MATCH_PRIORITY', priority)])],
           [self.table.make_data([], 'SwitchIngress_b.stats_five_t_b.rshift_pcc_' + str(div))])
