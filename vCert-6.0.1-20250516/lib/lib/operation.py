# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import glob
import importlib
import logging
import os
import sys
import yaml

from lib.console import print_header, print_text_error
from lib.environment import Environment
from lib.exceptions import OperationFailed, CommandExecutionError
from lib.host_utils import get_config_file_path
from lib.input import MenuInput

logger = logging.getLogger(__name__)

class ValueSource(object):
    """
    Class for providing operation arguments as part of config file
    """
    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value


class EnvironmentSource(object):
    """
    Class for providing operation argument from environment variable
    """
    def __init__(self, key):
        self.key = key

    def get_value(self):
        """
        Return value from environment
        """
        env = Environment.get_environment()
        return env.get_value(self.key)


class InputSource(object):
    """
    Class for providing operation arguments via user input dialog
    """
    def __init__(self, text, acceptable_inputs, default_input=None, allow_empty_input=True, case_insensitive=False,
                 masked=False):
        """
        InputSource constructor. All arguments will be passed to MenuInput
        """
        self.text = text
        self.acceptable_inputs = acceptable_inputs
        self.default_input = default_input
        self.allow_empty_input = allow_empty_input
        self.case_insensitive = case_insensitive
        self.masked = masked

    def get_value(self):
        """
        Return value obtained from MenuInput execution
        """
        source_input = MenuInput(self.text, self.acceptable_inputs, self.default_input, self.allow_empty_input,
                                 self.case_insensitive, self.masked)
        return source_input.get_input()


class OperationArgument(object):
    """
    Class for defining operation argument
    """
    def __init__(self, name, source):
        self.name = name
        self.source = source


class Operation(object):
    """
    Class for defining operation object
    """
    def __init__(self, title, module_name, method_name, condition_key):
        """
        Operation constructor method

        :param title: text to be displayed when the operation is executed
        :param module_name: module to be load to find the method for this operation
        :param method_name: method to be called for this operation
        :param condition_key: key to be used to evaluate if the operation is disabled
        """
        env = Environment.get_environment()
        sys.path.append(env.get_value('SCRIPT_DIR'))
        self.title = title
        self.module = importlib.import_module(module_name)
        obj = self.module
        for attr_name in method_name.split('.'):
            obj = getattr(obj, attr_name)
        self.method = obj
        self.arguments = []
        self.condition_key = condition_key

    def add_argument(self, name, source):
        self.arguments.append(OperationArgument(name, source))

    def get_argument_values(self):
        """
        Get operation arguments as dict. This method will also reset CURRENT_MENU
        environment with this mapping
        """
        args = dict()
        env = Environment.get_environment()
        env.set_value('CURRENT_MENU', args)
        for arg in self.arguments:
            value = arg.source.get_value()
            args[arg.name] = value
        return args

    def is_disabled(self):
        """
        Check if the operation is disabled
        """
        if self.condition_key:
            return Environment.get_environment().get_value(self.condition_key) is not True
        else:
            return False

    def run(self):
        """
        Execute the operation
        """
        if self.is_disabled():
            print_text_error('Operation is disabled!')
            print()
            return

        if self.title:
            print_header(self.title)
        try:
            return self.method(**self.get_argument_values())
        except CommandExecutionError as e:
            raise OperationFailed(str(e))


    class OperationGroup(object):
        """
        Class for defining operation that aggregate other operations
        """
        def __init__(self, title):
            self.title = title
            self.operations = []

        def add_operation(self, op):
            self.operations.append(op)

        def run(self):
            for op in self.operations:
                op.run()

    @staticmethod
    def load_operation_from_config_obj(config):
        """
        Load operation from loaded config object

        :param config: config file to be loaded
        """
        entry_point = config['entry_point']
        operation = Operation(config.get('title'), entry_point['module'], entry_point['method'],
                              config.get('condition'))
        arguments = config.get('arguments')
        if arguments:
            for arg in config.get('arguments'):
                arg_name = arg['name']
                if arg.get('value') is not None:
                    operation.add_argument(arg_name, ValueSource(arg['value']))
                    continue

                source_config = arg['source']
                if source_config['type'] == 'input':
                    operation.add_argument(
                        arg_name,
                        InputSource(text=source_config['input_text'],
                                    acceptable_inputs=source_config.get('acceptable_inputs'),
                                    default_input=source_config.get('default_input'),
                                    case_insensitive=(source_config.get('case_insensitive') is True),
                                    masked=(source_config.get('masked') is True)))
                elif source_config['type'] == 'environment':
                    operation.add_argument(arg_name, EnvironmentSource(source_config['key']))
        return operation

    @staticmethod
    def load_operation_from_config(config_file):
        """
        Load operation from a yaml config file

        :param config_file: config file to be loaded
        :return: Return Operation or OperationGroup object
        """
        env = Environment.get_environment()
        config_file = get_config_file_path(config_file)
        logger.info("Loading operation from config file {}".format(config_file))
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
            if config['type'] == "operation":
                return Operation.load_operation_from_config_obj(config)

            op_group = Operation.OperationGroup(config.get('title'))
            for operation in config['operations']:
                if operation['type'] == 'single':
                    if operation.get('config'):
                        op = Operation.load_operation_from_config(operation['config'])
                    else:
                        op = Operation.load_operation_from_config_obj(operation)
                    op_group.add_operation(op)
                    continue
                # logger.info("Parsing multiple operations in {}".format(glob.glob(operation['config'])))

                # Only use the SCRIPT_DIR environment setting if the config
                # path isn't absolute.
                opconfig = operation['config']
                if os.path.isabs(opconfig):
                   globPath = opconfig
                else:
                   globPath = os.path.join(env.get_value('SCRIPT_DIR'), opconfig)

                for config_file in sorted(glob.glob(globPath)):
                    op = Operation.load_operation_from_config(config_file)
                    op_group.add_operation(op)
            return op_group
