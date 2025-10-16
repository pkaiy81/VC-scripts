# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import subprocess

from lib.environment import Environment
from lib.exceptions import CommandExecutionError, CommandExecutionTimeout
from lib.execution_replay import ReplayContext


class CommandRunner(object):
    """
    A utility class to execute external command and obtain the output
    This class also provide a mechanism for rerouting the execution on
    remote machine via SSH session, capturing the execution result and
    replaying it back for development and testing purpose.
    """

    def __init__(self, *command_args, **options):
        """
        CommandRunner constructor

        :param command_args: the command and its arguments
        :param options: Supports the following optional parameters:
            - expected_return_code: if specified, CommandRunner will check the command
                return value and will raise CommandExecutionError it doesn't match
            - command_input: Text to be supplied to stdin when executing the command
            - binary_output: indicating that the command is expected to return binary output
        """
        self.command_args = command_args
        self.options = options
        self.timeout = None
        self.replay_context = None

        if options.get('expected_return_code') is not None:
            self.expected_return_code = options['expected_return_code']
        else:
            self.expected_return_code = None
        if options.get('command_input') is not None:
            self.command_input = options['command_input']
        else:
            self.command_input = None
        if options.get('binary_output') is not None:
            self.binary_output = options['binary_output'] is True
        else:
            self.binary_output = False
        if options.get('timeout') is not None:
            self.timeout = options['timeout']

        self.remote_hostname = None
        self.remote_username = None
        self.is_remote = False
        self.setup_remote_exec()


    def setup_remote_exec(self):
        """
        Setup the remote execution, capture/replay mechanism if the required
        keys are set in the environment
        """
        env = Environment.get_environment()
        if env.get_value('VCERT_REMOTE_EXEC'):
            self.set_remote(env.get_value('VCERT_REMOTE_HOSTNAME'),
                            env.get_value('VCERT_REMOTE_USERNAME'))
            if env.get_value('VCERT_REMOTE_EXEC_REPLAY') is True \
                    or env.get_value('VCERT_REMOTE_EXEC_CAPTURE') is True:
                self.replay_context = ReplayContext.get_replay_context()

    def set_remote(self, hostname, username='root'):
        self.is_remote = True
        self.remote_hostname = hostname
        self.remote_username = username if not username else 'root'


    def set_input(self, command_input):
        self.command_input = command_input


    def run(self):
        """
        Run the command, redirect to run_remote if remote execution is set
        """
        if self.is_remote:
            return self.run_remote(self.command_args, self.command_input, self.timeout,
                                   self.expected_return_code, self.binary_output)
        else:
            return self.run_local(self.command_args, self.command_input, self.timeout,
                                  self.expected_return_code, self.binary_output)

    def run_and_get_output(self):
        """
        Run the command and get the standard output only
        """
        _, stdout, _ = self.run()
        return stdout


    @staticmethod
    def run_local(command_args, command_input, timeout, expected_return_code, binary_output) -> (int, str, str):
        """
        Run the command locally

        :param command_args: external command and the arguments
        :param command_input: Text to be supplied as stdin
        :param timeout: Timeout value for waiting the external command to
            return. It will raise CommandExecutionTimeout when this happen
        :param expected_return_code: The expected return code. If it's
            specified and it doesn't match to the actual return code,
            CommandExecutionError will be raised
        :param binary_output: need to handle binary output instead of text
        :return: a tuple of (return code, stdout output, stderr output)
        """
        try:
            if binary_output:
                ret = subprocess.run(command_args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout)
            elif command_input == subprocess.DEVNULL:
                ret = subprocess.run(command_args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
            else:
                ret = subprocess.run(command_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     input=command_input, universal_newlines=True, timeout=timeout)
            if expected_return_code is not None:
                if ret.returncode != expected_return_code:
                    raise CommandExecutionError("External command '{}' returned {}, error message: {}".format(
                        " ".join(command_args), ret.returncode, ret.stderr))
            return ret.returncode, ret.stdout, ret.stderr
        except subprocess.TimeoutExpired:
            raise CommandExecutionTimeout("External command '{}' timed out".format(" ".join(command_args)))

    def run_remote(self, command_args, command_input, timeout, expected_return_code, binary_output):
        """
        Run the command on remote machine, or perform capture/replay when
        set in the environment variables

        It will append the required ssh command arguments 'ssh', '-l', '<user>', '<hostname>'
        The capture and replay mechanism will use the remote setting for storing
        and retrieve the command result.

        Refer to run_local for the parameter description
        """
        env = Environment.get_environment()
        remote_hostname = env.get_value('VCERT_REMOTE_HOSTNAME')
        remote_username = env.get_value('VCERT_REMOTE_USERNAME')
        local_hostname = env.get_value('LOCAL_HOSTNAME')

        if self.replay_context and self.replay_context.is_replaying:
            result = self.replay_context.get_execution_result('command', command_args, command_input)
            if result is not None:
                if expected_return_code is not None:
                    return_code, _, _ = result
                    if return_code != expected_return_code:
                        raise CommandExecutionError("External command '{}' returned {}".format(
                            " ".join(command_args), return_code))
                return result

        if local_hostname and remote_hostname.lower() == local_hostname.lower():
            # run locally
            final_args = command_args
        else:
            final_args = ['ssh', '-l', remote_username, remote_hostname]
            final_args.extend(command_args)
            CommandRunner.add_quotation_escape(final_args)
        return_code, stdout, stderr = CommandRunner.run_local(final_args, command_input, timeout,
                                                              None, binary_output)
        if self.replay_context and self.replay_context.is_capturing:
            self.replay_context.store_result('command', command_args, command_input, return_code, stdout, stderr)
        if expected_return_code is not None and expected_return_code != return_code:
            raise CommandExecutionError("External command '{}' returned {}".format(
                " ".join(command_args), return_code))
        return return_code, stdout, stderr

    @staticmethod
    def add_quotation_escape(args):
        for index, arg in enumerate(args):
            if ' ' in arg or '"' in arg or '\'' in arg or '\\' in arg:
                args[index] = "\"{}\"".format(arg.replace('"', '\\"'))
