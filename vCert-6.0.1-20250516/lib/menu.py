# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import glob
import yaml
import logging

from lib.console import print_header, print_text, ColorKey, set_text_color, print_text_error
from lib.environment import Environment
from lib.exceptions import MenuExitException, OperationFailed
from lib.input import MenuInput
from lib.operation import Operation
from lib.text_utils import translate_text
from lib.vecs import get_certificate_aliases, get_store_list
from lib.vmdir import get_identity_sources

logger = logging.getLogger(__name__)

class MenuItem(object):
    """
    Class for holding menu item information
    """
    def __init__(self, text, method, method_args=None, key=None, is_disabled=False,
                 is_hidden=False, is_default=False, use_label_as_key=False):
        """
        Initialize MenuItem object

        :param text: label for the menu item when displayed as part of menu
        :param method: the method to be called if the menu item is executed
        :param method_args: arguments to be supplied to method
        :param key: specify menu key explicitly. If this key not specified,
            the key will be generated using a sequenced number
        :param is_disabled: show menu as disabled menu item
        :param is_default: use this menu item if the input return empty key
        :param use_label_as_key: use the label as the key for default input
        """
        self.text = text
        self.method = method
        self.method_args = method_args
        self.key = key
        self.is_disabled = is_disabled
        self.is_hidden = is_hidden
        self.is_default = is_default
        self.use_label_as_key = use_label_as_key


class Menu(object):
    """
    Class for representing a single menu dialog, providing the method to
    define and show menu list, the handling of accepted inputs and the
    execution of menu item
    """
    def __init__(self):
        self.title = ''
        self.sub_title = ''
        self.items = []
        self.input_text = None
        self.run_once = False

    def set_menu_options(self, title, sub_title=None, run_once=False, input_text=None):
        """
        Set the menu option: menu title and the input text
        """
        self.title = title
        self.sub_title = sub_title
        self.input_text = input_text
        self.run_once = run_once

    def add_menu_item(self, label, method=None, method_args=None, key=None, is_disabled=False,
                      is_hidden=False, is_default=False, use_label_as_key=False):
        """
        Add menu item entry

        :param label: label for the menu item when displayed as part of menu
        :param method: method object to be called if the menu item is executed
        :param method_args: arguments to be supplied to method
        :param key: specify menu key explicitly. If this key not specified,
        the key will be auto-generated using sequence number
        :param is_disabled: show menu as disabled menu item
        :param is_hidden: if True, hidden the menu entry
        :param is_default: use this menu item if the input return empty key
        :param use_label_as_key: use the label as the key for default input
        """
        # validate that the new menu item entry doesn't have conflict with the existing ones
        if key is not None:
            key = key.upper()
        for item in self.items:
            if key is not None and key == item.key:
                raise ValueError("Duplicating menu item key: {}".format(key))
            if is_default and item.is_default:
                raise ValueError('Duplicating default menu item')
        if is_hidden and key is None:
            raise ValueError('Hidden menu item requires explicit key value')
        self.items.append(MenuItem(label, method, method_args, key, is_disabled, is_hidden,
                                   is_default, use_label_as_key))

    def get_all_menu_keys(self):
        """
        Get all menu keys defined or generated for the current menu entries

        :returns all menu keys
        """
        user_keys = []
        for item in self.items:
            if item.key is not None:
                user_keys.append(item.key)
        keys = [str(i) for i in range(1, len(self.items) - len(user_keys) + 1)]
        keys.extend(user_keys)
        return keys

    def get_all_menu_keys_string(self) -> str:
        """
        Get all menu keys as a single string

        The auto-generated keys will be simplified using range expression.
        Example: When get_all_menu_keys() returns ['1', '2', '3', 'E'],
        this method will return '1-3, E'

        :return meny keys in a single-line string
        """
        keys = []
        for item in self.items:
            if item.key is not None:
                keys.append(item.key)
        num_others = len(self.items) - len(keys)
        if num_others == 1:
            keys.insert(0, "1")
        elif num_others > 1:
            keys.insert(0, "{}-{}".format(1, num_others))
        return ", ".join(keys)

    def get_menu_item(self, key):
        """
        Get menu item using key {key}

        :param key: key to be used to search the menu item
        :return: MenuItem object
        """
        key = key.upper()
        item_key = 1
        for item in self.items:
            if item.key is None:
                if key == str(item_key):
                    return item
                else:
                    item_key += 1
            elif item.key == key:
                return item
        return None

    def get_input(self):
        """
        Get user input from console

        :return: key entered by user
        """
        keys = self.get_all_menu_keys()
        # get default key
        default_key = None
        seq = 0
        for item in self.items:
            if not item.key:
                seq += 1
            if item.is_default:
                default_key = item.key if item.key else str(seq)
                default_key_text = item.text if item.use_label_as_key else default_key            
                    
                Environment.get_environment().get_value('CURRENT_MENU')['__DEFAULT__'] = default_key
                break
        # compose default input text if required
        input_text = self.input_text
        if self.input_text is None:
            if default_key is not None:
                input_text = "Select an option [{key}]: ".format(key=default_key_text)
            else:
                input_text = 'Select an option: '

        menu_input = MenuInput(translate_text(input_text), acceptable_inputs=keys, default_input=default_key)
        return menu_input.get_input()

    def show_menu(self):
        """
        Show the menu list
        """
        if self.title:
            print()
            print_header(self.title)
        if self.sub_title:
            print_text(self.sub_title)
        seq = 1
        for item in self.items:
            if item.is_hidden:
                continue
            key = item.key
            if not key:
                key = str(seq)
                seq += 1

            if item.is_disabled:
                set_text_color(ColorKey.YELLOW)
            print_text("{:>2}. {}".format(key, translate_text(item.text)))
            if item.is_disabled:
                set_text_color(ColorKey.NORMAL)

    def run(self):
        """
        Execute the menu: show the menu list, get user input, and execute
        the selected menu item
        """
        Environment.get_environment().set_value('CURRENT_MENU', dict())
        while True:
            self.show_menu()
            print()
            try:
                key = self.get_input()
                item = self.get_menu_item(key)
            except KeyboardInterrupt:
                raise MenuExitException('KeyboardInterrupt exception')
            logger.info('Running menu item: {}'.format(item))
            if item is None:
                raise RuntimeError('Menu item not found')
            elif item.is_disabled:
                print()
                print_text_error('Operation is not available')
                return
            elif item.method == Menu.run_navigation_exit:
                raise MenuExitException('Exit requested')
            elif item.method == Menu.run_navigation_return:
                return
            try:
                if item.method_args is not None:
                    item.method(**item.method_args)
                else:
                    item.method()
            except OperationFailed as e:
                print()
                print_text_error('Operation failed: {}'.format(str(e)))
            except KeyboardInterrupt:
                raise MenuExitException('KeyboardInterrupt exception')

            if self.run_once:
                return

    @staticmethod
    def load_menu_item_from_file(config_file):
        """
        Load menu item definition from yaml config file

        :param config_file: file to be loaded
        :return: menu item type, label, and enable condition string
        """
        env = Environment.get_environment()
        config_file = config_file if config_file.startswith(env.get_value('SCRIPT_DIR')) \
            else "{}/{}".format(env.get_value('SCRIPT_DIR'), config_file)
        with open(config_file, 'r') as file:
            item_config = yaml.safe_load(file)
            label = item_config.get('label')
            condition = item_config.get('condition')
            if label is None:
                label = item_config['title']
            return item_config['type'], label, condition

    @staticmethod
    def load_menu_items_from_files(config_files):
        """
        Load multiple menu item definitions from yaml config files, specified
        using a file pattern (glob)

        :param config_files: file pattern to be loaded.
        :return: list of a tuple of menu item type, label, and condition
        """
        items = []
        env = Environment.get_environment()
        config_files = config_files if config_files.startswith(env.get_value('SCRIPT_DIR')) \
            else "{}/{}".format(env.get_value('SCRIPT_DIR'), config_files)
        for config in sorted(glob.glob(config_files)):
            env = Environment.get_environment()
            config = config if config.startswith(env.get_value('SCRIPT_DIR')) \
                else "{}/{}".format(env.get_value('SCRIPT_DIR'), config)
            with open(config, 'r') as file:
                item_config = yaml.safe_load(file)
                logger.info('Configuration from {} is: {}'.format(config, item_config))
                label = item_config.get('label')
                condition = item_config.get('condition')
                if label is None:
                    label = item_config['title']
                items.append((item_config['type'], label, config, condition))
        return items

    @staticmethod
    def load_menu_from_config(config_file):
        """
        Load a full menu context from config file

        :param config_file: a yaml config file to be loaded
        :return: Menu object created from the config file
        """
        env = Environment.get_environment()
        menu = Menu()
        config_file = config_file if config_file.startswith(env.get_value('SCRIPT_DIR')) \
            else "{}/{}".format(env.get_value('SCRIPT_DIR'), config_file)
        with open(config_file, 'r') as file:
            menu_config = yaml.safe_load(file)
            title = menu_config['title']
            sub_title = menu_config.get('sub_title', '')
            run_once = menu_config.get('run_once', False)
            input_text = None
            if menu_config.get('input'):
                input_text = menu_config['input']['text']
            menu.set_menu_options(title, sub_title, run_once, input_text)

            for item_config in menu_config['items']:
                item_type = item_config['type']
                item_label = item_config.get('label')
                is_default = item_config.get('default') is True
                condition = item_config.get('condition')
                is_disabled = env.get_value(condition) is not True if condition else False
                is_hidden = item_config.get('hidden') is True
                use_label_as_key = item_config.get('use_label_as_key', False)
                key = item_config.get('key')
                if item_type == 'single':
                    submenu_config = item_config['config']
                    submenu_type, submenu_label, submenu_condition = Menu.load_menu_item_from_file(submenu_config)
                    if item_label is None:
                        item_label = submenu_label
                    if not is_disabled:
                        is_disabled = env.get_value(submenu_condition) is not True if submenu_condition else False
                    handler = Menu.run_menu_from_config if submenu_type == 'menu' else Menu.run_operation_from_config
                    menu.add_menu_item(item_label, handler, {'config': submenu_config}, key=key,
                                       is_disabled=is_disabled, is_hidden=is_hidden, is_default=is_default)
                elif item_type == 'multiple':
                    items = Menu.load_menu_items_from_files(item_config['config'])
                    for submenu_type, submenu_label, submenu_config, submenu_condition in items:
                        is_disabled = env.get_value(submenu_condition) is not True if submenu_condition else False
                        handler = Menu.run_menu_from_config \
                            if submenu_type == 'menu' else Menu.run_operation_from_config
                        menu.add_menu_item(submenu_label, handler, {'config': submenu_config},
                                           is_disabled=is_disabled)
                elif item_type == 'navigation:exit':
                    menu.add_menu_item(item_label, Menu.run_navigation_exit, key=key, is_disabled=is_disabled,
                                       is_hidden=is_hidden, is_default=is_default)
                elif item_type == 'navigation:return':
                    menu.add_menu_item(item_label, Menu.run_navigation_return, key=key, is_disabled=is_disabled,
                                       is_hidden=is_hidden, is_default=is_default, use_label_as_key=use_label_as_key)
        return menu

    @staticmethod
    def get_menu_label_and_condition_from_config(config):
        """
        Obtain menu label and condition only from a menu config file

        :param config: config file to be loaded
        :return: tuple of menu item label and condition
        """
        env = Environment.get_environment()
        config = config if config.startswith(env.get_value('SCRIPT_DIR')) \
            else "{}/{}".format(env.get_value('SCRIPT_DIR'), config)
        with open(config, 'r') as file:
            menu_config = yaml.safe_load(file)
            label = menu_config.get('label')
            if label is None:
                label = menu_config['title']

            condition = menu_config.get('condition')
            return label, condition

    @staticmethod
    def run_menu_from_config(config):
        """
        Method to be used by MenuItem that load another menu (submenu)

        :param config: config to be load in the submenu
        """
        menu = Menu.load_menu_from_config(config)
        menu.run()

    @staticmethod
    def run_operation_from_config(config):
        """
        Method to be used by MenuItem that execute operation

        :param config: config to be loaded to run the operation
        """
        operation = Operation.load_operation_from_config(config)
        try:
            operation.run()
        except OperationFailed as e:
            print()
            print_text_error("Operation failed: {}".format(str(e)))


    @staticmethod
    def run_navigation_exit():
        """
        Method to be used by MenuItem that cause application exit
        """
        pass


    @staticmethod
    def run_navigation_return():
        """
        Method to be used by MenuItem that cause return to parent menu
        """
        pass


    @staticmethod
    def set_menu_conditions():
        Menu.set_ldaps_condition()
        Menu.set_machine_ssl_csr_condition()
        Menu.set_backup_store_condition()

    @staticmethod
    def set_ldaps_condition():
        env = Environment.get_environment()
        identity_sources = get_identity_sources(use_machine_account=True)
        value = True if identity_sources else False
        env.set_value('HAS_LDAPS_IDENTITY_SOURCE', value)


    @staticmethod
    def set_machine_ssl_csr_condition():
        env = Environment.get_environment()
        machine_ssl_aliases = get_certificate_aliases('MACHINE_SSL_CERT')
        value = True if '__MACHINE_CSR' in machine_ssl_aliases else False
        env.set_value('HAS_MACHINE_SSL_CSR', value)


    @staticmethod
    def set_backup_store_condition():
        env = Environment.get_environment()
        backup_stores = ['BACKUP_STORE', 'BACKUP_STORE_H5C']
        vecs_stores = get_store_list()
        value = any(store in vecs_stores for store in backup_stores)
        env.set_value('HAS_BACKUP_STORE', value)