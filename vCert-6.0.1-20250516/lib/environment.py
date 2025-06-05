# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import yaml
from pathlib import Path


class DefaultDict(dict):

    def __missing__(self, key):
        return ''


class Environment(object):

    shared_environment = None

    def __init__(self):
        self.cache = DefaultDict()
        self.load_default()
        self.restricted_keys = dict()

    def get_value(self, key):
        value = self.cache.get(key)
        if value is None and key in self.restricted_keys.keys():
            for k, v in self.restricted_keys[key]():
                self.cache[k] = v
                if k == key:
                    value = v
        return value

    def set_value(self, key, value):
        if key in self.restricted_keys.keys():
            raise KeyError('Cannot update environment using restricted key')
        self.cache[key] = value

    def invalidate_value(self, key):
        self.cache[key] = None

    def get_map(self):
        return self.cache

    def add_restricted_key(self, key, populate_method):
        """
        Set {key} as restricted variable. The existing value is invalidated.

        :param key: environment key
        :param populate_method: method to be called to populate the values
        """
        if key in self.restricted_keys:
            raise KeyError('Duplicating restricted key')
        self.restricted_keys[key] = populate_method
        self.cache[key] = None

    def load_from_file(self, env_file):
        """
        Load environment variables from config file
        :param env_file: config file
        """
        self.cache = DefaultDict()
        self.restricted_keys = dict()
        with open(env_file, 'r') as file:
            config = yaml.safe_load(file)
            env_map = config['environments']
            for key in env_map.keys():
                self.set_value(key, env_map[key])

    def load_default(self):
        """
        Load environment variables from default config file 'config/env.yaml'
        """
        base_dir = str(Path(__file__).resolve().parent.parent)
        default_env_file = Path(base_dir, 'config/env.yaml')
        if Path.exists(default_env_file):
            self.load_from_file(str(default_env_file))

    @staticmethod
    def get_environment():
        if Environment.shared_environment is None:
            Environment.shared_environment = Environment()
        return Environment.shared_environment
