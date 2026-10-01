from .planter_fork.src.functions.config_modification import reload_config, dump_config
from .planter_fork.src.functions.input_CLI import take_CLI_input
from .planter_fork.src.functions.timer_printer import print_timer
import sys
import importlib.util
import time

# =================== import Planter src ===================

class Planter:
    def __init__(self, conf, base_dir, switch_model):
        self.conf_path      = conf
        self.switch_model   = switch_model

        if conf:
            self.conf = reload_config(self.conf_path)
        else:
            print('No config file found. Exiting.')
            exit()

        # ====================== set machine learning model in config ======================
        question    = 'Which model do you want to plant?'
        default     = 'DT'
        self.conf   = take_CLI_input(self.conf, 'model config', 'model', question, default,
                                     check_dir_existence=True, check_available_options=True,
                                     option_address='/src/models')

        # ====================== set dataset in config ======================
        question    = 'Which dataset do you want to use?'
        default     = 'UNSW_5_tuple'
        self.conf   = take_CLI_input(self.conf, 'data config', 'dataset', question, default,
                                     check_dir_existence=True, check_available_options=True,
                                     option_address='/src/load_data', option_suffix='_dataset.py')

        # =================== set data feature numbers in config ===================
        question    = 'How many input features?'
        default     = 4
        self.conf   = take_CLI_input(self.conf, 'data config', 'number of features', question,
                                     default, numeric=True)

        # prepare the log dict
        self.conf['timer log'] = {}

        # dump the conf file
        dump_config(self.conf, self.conf_path)

        # =================== include model folder and files ===================
        load_data_file = importlib.util.spec_from_file_location(
                "*", base_dir
                        + "/src/load_data/"
                        + self.conf['data config']['dataset']+"_dataset.py")
        load_data_functions = importlib.util.module_from_spec(load_data_file)
        load_data_file.loader.exec_module(load_data_functions)
        global test_X, test_y

        # reload the config file
        self.conf = reload_config(self.conf_path)

        # =================== load data timer ===================
        self.conf['timer log']['load data']            = {}
        self.conf['timer log']['load data']['start']   = time.time()
        # =======================================================

        # dump the planter config
        dump_config(self.conf, self.conf_path)

        model_path = base_dir \
                     + 'src/models/' \
                     + self.conf['model config']['model']
        print('= Add the following path: '+ model_path)
        sys.path.append(model_path)

        model_main = importlib.util.spec_from_file_location(
                "*", model_path+"/table_generator_peregrine.py")
        self.main_functions = importlib.util.module_from_spec(model_main)

        model_main.loader.exec_module(self.main_functions)

        if self.conf['model config']['model'] == 'if':
            self.model_class = self.main_functions.IF(self.conf_path)

        elif self.conf['model config']['model'] == 'pca':
            self.model_class = self.main_functions.PCA_(self.conf_path)
        else:
            print(f'Invalid model selected: {self.conf["model config"]["model"]}.')

    def cur_model(self):
        return self.conf['model config']['model']

    def cur_model_size(self):
        if self.conf['model config']['model'] == 'pca':
            return f'{self.conf["model config"]["model size"]}-dim-{self.conf["model config"]["num components"]}'
        else:
            return self.conf["model config"]["model size"]

    def cur_aggr_pcc(self):
        if self.conf['model config']['model'] == 'pca' and self.switch_model:
            return self.model_class.corr_aggr
        else:
            return False

    def model_train(self, stats_train, switch_model, num_features=80):
        self.model_class.train_model(stats_train, switch_model, num_features)

    def model_exec(self, stats_exec, num_features=80):
        return self.model_class.train_pred(stats_exec, num_features)

    def tables_exec(self, stats_exec):
        return self.model_class.test_tables(stats_exec)

if __name__ == "__main__":
    try:
        Planter()
    except KeyboardInterrupt:
        print('Exiting Planter...')
        print_timer()

