# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import base64
import json
import glob
import os
import subprocess
from collections.abc import Mapping
from datetime import datetime

from lib.environment import Environment
from lib.exceptions import ReplayEntryNotFound, CommandExecutionError

replay_context = None


class ReplayEntry(object):
    """
    Class for representing execution result entry
    """

    def __init__(self, category, command_args, input_string, tag):
        """
        ReplayEntry constructor

        :param category: category of result (e.g. 'command', 'ldap')
        :param command_args: command and the parameters
        :param input_string:  Input text to be supplied as stdin
        """
        self.category = category
        self.command_args = command_args
        self.input_string = input_string if input_string is not None else ''
        self.used_count = 0
        self.key = self.generate_key(category, command_args, input_string, tag)
        self.results = []

    def add_result(self, timestamp, return_code, stdout, stderr):
        """
        Add command result entry

        :param timestamp: the timestamp of command execution
        :param return_code: command's return code
        :param stdout:  The command output from stdout
        :param stderr:  The command output from stderr
        """
        # always add result in sorted
        added = False
        value = (timestamp, return_code, stdout, stderr)
        for index, (ts, _, _, _) in enumerate(self.results):
            if ts > timestamp:
                self.results.insert(index, value)
                added = True
                break
        if not added:
            self.results.append(value)

    @staticmethod
    def generate_key(category, command_args, input_string, tag):
        """
        Generate key based on category, command_args, and input_string.
        The key is not guaranteed to be unique but should be good enough for
        debugging and testing purpose. This key will be used to retrieve
        the previous command result for replay

        :param category: the category, 'command', 'ldap'
        :param command_args:  command arguments
        :param input_string: input string
        :param tag: additional tag to differentiate the same commands in a different condition
        :return: generated key
        """
        for idx, arg in enumerate(command_args):
            if not isinstance(arg, str):
                command_args[idx] = str(arg)
        if input_string == subprocess.DEVNULL:
            input_string = '__/dev/null__'
        return "{}||{}||{}||{}".format(category, ">>".join(command_args), input_string, tag)


class ReplayContext(object):
    """
    The class holding context object for capturing or replaying command result
    """

    categories = ['command', 'ldap', 'other']

    def __init__(self, replay_dir, is_replaying=True, is_capturing=False):
        """
        ReplayContext constructor

        :param replay_dir: base directory for storing or retrieving command result
        :param is_capturing: True when capturing, otherwise it's in replay mode
        """
        self.replay_dir = replay_dir
        self.replay_entries = None
        self.is_replaying = is_replaying
        self.is_capturing = is_capturing
        self.tag = None

    def get_replay_entry(self, key) -> ReplayEntry:
        """
        Get replay entry based on the key

        :param key: key to be used to retrieve the command result
        """
        if self.replay_entries is None:
            self.load_all_replays()
        return self.replay_entries.get(key)

    def store_result(self, category, command_args, command_input, return_code, stdout, stderr):
        """
        Store the command result

        The file will be stored in <replay-dir>/<hostname>/replay_<category>_<1st command_args>_<timestamp>.json
        """
        command = command_args[0].split('/')[-1]
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S_%f')
        file_name = "{}/replay_{}_{}_{}.json".format(self.replay_dir, category,
                                                     command, timestamp)
        with open(file_name, 'w') as file:
            content = {
                "command_args": ReplayContext.encode_bytes(command_args),
                "input": command_input if command_input != subprocess.DEVNULL else '__/dev/null__',
                "tag": self.tag,
                "timestamp": timestamp,
                "return_code": return_code,
                "stdout": self.encode_bytes(stdout),
                "stderr": self.encode_bytes(stderr)
            }
            try:
                file.write(json.dumps(content, indent=4))
            except TypeError as te:
                raise CommandExecutionError("Unserializable object: {}".format(content))

        if self.is_replaying:
            self.add_replay_entry(category, command_args, command_input, self.tag, timestamp,
                                  return_code, stdout, stderr)

    def set_tag(self, tag):
        self.tag = tag

    def load_all_replays(self):
        """
        Load all replay entries
        """
        self.replay_entries = {}
        for category in ReplayContext.categories:
            for file in sorted(glob.glob("{}/replay_{}_*.json".format(self.replay_dir, category))):
                with open(file, 'r') as f:
                    replay = json.load(f)
                    command_args = ReplayContext.decode_bytes(replay['command_args'])
                    command_input = replay['input']
                    stdout = ReplayContext.decode_bytes(replay['stdout'])
                    stderr = ReplayContext.decode_bytes(replay['stderr'])
                    self.add_replay_entry(category, command_args, command_input, replay['tag'], replay['timestamp'],
                                          replay['return_code'], stdout, stderr)

    def add_replay_entry(self, category, command_args, command_input, tag, timestamp,
                         return_code, stdout, stderr):
        """
        Add replay entry
        """
        key = ReplayEntry.generate_key(category, command_args, command_input, tag)
        entry = self.get_replay_entry(key)
        if entry is None:
            entry = ReplayEntry(category, command_args, command_input, tag)
            self.replay_entries[key] = entry
        entry.add_result(timestamp, return_code, stdout, stderr)

    def reset_context(self):
        for entry in self.replay_entries:
            entry.used_count = 0

    def get_execution_result(self, category, command_args, command_input) -> (int, str, str):
        """
        Get the previous execution result based on {category}, {command_args}, and {command_input}
        """
        key = ReplayEntry.generate_key(category, command_args, command_input, self.tag)
        entry = self.get_replay_entry(key)
        if entry is None:
            if self.is_capturing:
                return None
            else:
                raise ReplayEntryNotFound("Replay entry not found for key {}".format(key))
        result = entry.results[entry.used_count]
        entry.used_count = (entry.used_count + 1) % len(entry.results)
        return result[1:]

    @staticmethod
    def get_replay_context(reload=False):
        """
        Static method to get ReplayContext instance from other modules

        :param reload: if True, it will dispose the previous object and create a new instance
        """
        global replay_context
        env = Environment.get_environment()
        is_remote = env.get_value('VCERT_REMOTE_EXEC') is True
        is_replay = env.get_value('VCERT_REMOTE_EXEC_REPLAY') is True
        is_capture = env.get_value('VCERT_REMOTE_EXEC_CAPTURE') is True
        if reload:
            replay_context = None
        if is_remote and (is_replay or is_capture) and replay_context is None:
            remote_hostname = env.get_value('VCERT_REMOTE_HOSTNAME')
            replay_dir = "{}/{}".format(env.get_value('VCERT_REMOTE_EXEC_REPLAY_DIR'),
                                        remote_hostname)
            if not os.path.exists(replay_dir):
                os.makedirs(replay_dir)
            replay_context = ReplayContext(replay_dir, is_replay, is_capture)
        return replay_context

    @staticmethod
    def encode_bytes(obj):
        if isinstance(obj, bytes):
            return "__base64__({})".format(base64.b64encode(obj).decode('utf-8'))
        if isinstance(obj, list):
            for idx, value in enumerate(obj):
                obj[idx] = ReplayContext.encode_bytes(value)
        elif isinstance(obj, dict):
            for key in obj.keys():
                obj[key] = ReplayContext.encode_bytes(obj[key])
        elif isinstance(obj, Mapping):
            new_obj = dict()
            for key in obj.keys():
                new_obj[key] = ReplayContext.encode_bytes(obj[key])
            obj = new_obj
        return obj

    @staticmethod
    def decode_bytes(obj):
        if isinstance(obj, str) and obj.startswith('__base64__(') and obj.endswith(')'):
            return base64.b64decode(obj[11:-1])
        if isinstance(obj, list):
            for idx, value in enumerate(obj):
                obj[idx] = ReplayContext.decode_bytes(value)
        elif isinstance(obj, dict):
            for key in obj.keys():
                obj[key] = ReplayContext.decode_bytes(obj[key])
        return obj
