import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import grpc

import logging

from pprint import pprint, pformat

PADDING = 30


class Table(object):

    def __init__(self, client, bfrt_info):
        # get logging, client, and global program info
        self.logger = logging.getLogger('Table')
        self.gc = client
        self.bfrt_info = bfrt_info

        # child clases must set table
        self.table = None

        # lowest possible  priority for ternary match rules
        self.lowest_priority = 1 << 24

    def clear(self):
        """Remove all existing entries in table."""
        if self.table is not None:
            # target all pipes on device 0
            target = gc.Target(device_id=0, pipe_id=0xffff)

            # get all keys in table
            resp = self.table.entry_get(target, [], {"from_hw": False})

            # delete all keys in table
            for _, key in resp:
                if key:
                    self.table.entry_del(target, [key])

        # # try to reinsert default entry if it exists
        # try:
        #     self.table.default_entry_reset(target)
        # except:
        #     pass

    def print_current_state(self):
        print()
        print("====================================================")

        print("Table info:")
        print("  ID   {}".format(self.table.info.id_get()))
        print("  Name {}".format(self.table.info.name_get()))

        actions = self.table.info.action_name_list_get()
        data_fields = self.table.info.data_field_name_list_get()
        key_fields = self.table.info.key_field_name_list_get()
        attributes = self.table.info.attributes_supported_get()

        print("  Actions:")
        for action in actions:
            print("  {}".format(action))

        print("  Data fields:")
        for data_field in data_fields:
            data_field_size = self.table.info.data_field_size_get(data_field)
            data_field_type = self.table.info.data_field_size_get(data_field)

            print("    Name {}".format(data_field))
            print("    Size {} bytes, {} bits".format(data_field_size[0], data_field_size[1]))
            print("    Type {}".format(data_field_type))

        print("  Keys:")
        for key_field in key_fields:
            key_field_size = self.table.info.key_field_size_get(key_field)
            key_field_type = self.table.info.key_field_type_get(key_field)

            print("    Name {}".format(key_field))
            print("    Size {} bytes, {} bits".format(key_field_size[0], key_field_size[1]))
            print("    Type {}".format(key_field_type))

        print("  Attributes:")
        for attribute in attributes:
            print("    Name {}".format(attribute))

        target = gc.Target(device_id=0, pipe_id=0xffff)
        keys = self.table.entry_get(target, [], {"from_hw": False})

        print("Table entries:")
        for data, key in keys:
            print("  -------------------------------------------------")
            for key_field in key.to_dict().keys():
                print("  {} {}".format(key_field.ljust(PADDING), key.to_dict()[key_field]['value']))

            for data_field in data.to_dict().keys():
                if data_field in ['is_default_entry', 'action_name']:
                    continue

                print("  {} {}".format(data_field.ljust(PADDING), data.to_dict()[data_field]))

            print("  {} {}".format("Actions".ljust(PADDING), data.to_dict()['action_name']))

        print("====================================================")
        print()
