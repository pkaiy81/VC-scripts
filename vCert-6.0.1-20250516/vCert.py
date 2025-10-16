#!/usr/bin/env python3

# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import argparse
import datetime
import logging
import logging.config
import os
import pathlib
import sys
import yaml

from lib.console import init_env_colormap, print_text, print_text_error
from lib.constants import VCERT_NAME, VCERT_VERSION, VCERT_DESC, VCERT_PROGRAM, WARNING_TEXT, TOP_DIR
from lib.environment import Environment
from lib.exceptions import MenuExitException
from lib.menu import Menu, MenuInput
from lib.host_utils import init_env_host, VcVersion, get_vc_version, make_directory, remove_directory
from lib.services import check_services_status
from lib.vmdir import init_env_identity_source, init_env_cac
from operation.common import verify_sso_credential, populate_sso_credential


def init_logging():
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(tools_dir, 'config/logging.yaml')
    with open(config_file, 'r') as stream:
        config = yaml.load(stream, Loader=yaml.FullLoader)
    log_dir = pathlib.Path(config['handlers']['file']['filename']).parent
    try:
        os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        # this may necessary for remote execution on a restricted environment
        tmp_dir = pathlib.Path('/tmp')
        new_log_dir = tmp_dir.joinpath(log_dir.relative_to('/'))
        os.makedirs(new_log_dir, exist_ok=True)
        log_file = pathlib.Path(config['handlers']['file']['filename']).name
        new_log_file = pathlib.Path(new_log_dir, log_file)
        config['handlers']['file']['filename'] = str(new_log_file)

    logging.config.dictConfig(config)


def init_environment(args):
    """
    Initialize environment variables
    :param args: Command line arguments
    """
    env = Environment.get_environment()
    if args.environment is not None:
        env.load_from_file(args.environment)

    env.set_value('VCERT_NAME', VCERT_NAME)
    env.set_value('VCERT_VERSION', VCERT_VERSION)
    env.set_value('VCERT_DESC', VCERT_DESC)
    init_env_host()
    init_env_colormap()
    init_env_identity_source()
    init_env_cac()

    check_vc_version()

    check_services_status()

    if args.password is not None:
        if args.user is None:
            # args.user = 'administrator@vsphere.local'
            args.user = "administrator@{}".format(env.get_value('SSO_DOMAIN'))
        if not verify_sso_credential(args.user, args.password):
            print("Error: failed to authenticate user {}".format(args.user))
            exit(1)
        env.set_value('SSO_USERNAME', args.user)
        env.set_value('SSO_PASSWORD', args.password)

    if env.get_value('SSO_USERNAME') is None:
        env.add_restricted_key('SSO_USERNAME', populate_sso_credential)
        env.add_restricted_key('SSO_PASSWORD', populate_sso_credential)


def get_timestamp():
    return datetime.datetime.utcnow().strftime('%Y%m%d')


def init_working_directory():
    # working directory
    timestamp = get_timestamp()
    work_dir = "{}/{}".format(TOP_DIR, timestamp)
    if not make_directory(work_dir):
        work_dir = "{}/{}".format(str(pathlib.Path('.').resolve()), timestamp)
    request_dir = "{}/requests".format(work_dir)
    backup_dir = "{}/backup".format(work_dir)
    temp_dir = "{}/temp".format(work_dir)
    script_dir = os.path.dirname(os.path.realpath(__file__))
    for dir in [request_dir, backup_dir, temp_dir]:
        make_directory(dir)

    env = Environment.get_environment()
    env.set_value('WORK_DIR', work_dir)
    env.set_value('BACKUP_DIR', backup_dir)
    env.set_value('REQUEST_DIR', request_dir)
    env.set_value('TEMP_DIR', temp_dir)
    env.set_value('SCRIPT_DIR', script_dir)


def cleanup_working_directory():
    """
    Cleanup working directory. Remove directory only if there is no remaining contents
    except for temporary directory
    """
    env = Environment.get_environment()
    remove_directory(env.get_value('BACKUP_DIR'))
    remove_directory(env.get_value('REQUEST_DIR'))
    remove_directory(env.get_value('TEMP_DIR'), remove_all=True)
    remove_directory(env.get_value('WORK_DIR'))


def parse_arguments():
    parser = argparse.ArgumentParser(prog=VCERT_PROGRAM, description=VCERT_DESC)
    parser.add_argument('--version', action='version', version=VCERT_VERSION)
    parser.add_argument('--env', required=False, dest='environment',
                        help='Config file for environment variables')
    parser.add_argument('--run', required=False, dest='operation',
                        help='Run specific operation directly instead of showing menu')
    parser.add_argument('--user', required=False, dest='user',
                        help='Specify an SSO administrator account')
    parser.add_argument('--password', required=False, dest='password',
                        help='Password for the specified SSO administrator account')
    return parser.parse_args(sys.argv[1:])


def check_vc_version():
    """
    Check VC version. If the vCenter version is not supported, error message will be displayed
    and the program exit immediately
    """
    vc_version = get_vc_version()
    if vc_version == VcVersion.Invalid:
        vc_version_full = Environment.get_environment().get_value('VC_VERSION')
        print_text_error("Error: Unsupported vCenter version: {}.\n"
                         "{} only supports versions {} to {}\n"
                         .format(
                             vc_version_full,
                             VCERT_DESC,
                             VcVersion.min(),
                             VcVersion.max()
                         )
                        )
        sys.exit(1)


def show_warning_message():
    """
    Show warning message before using the vCert. For development purpose, this message can be
    suppressed using environment setting
    """
    env = Environment.get_environment()
    suppress_warning_message = env.get_value('VCERT_SUPPRESS_WARNING_MESSAGE') is True
    if suppress_warning_message:
        return
    print_text(WARNING_TEXT, end='')
    menu_input = MenuInput('', acceptable_inputs=['Y', 'N'], default_input='N')
    if menu_input.get_input() == 'N':
        sys.exit(0)


def run_operation(op_config):
    try:
        Menu.run_operation_from_config(op_config)
    except MenuExitException:
        pass


def run_menu():
    menu = Menu.load_menu_from_config('config/menu_main.yaml')
    try:
        menu.run()
    except MenuExitException:
        pass


if __name__ == '__main__':
    init_logging()
    args = parse_arguments()
    init_environment(args)
    init_working_directory()
    Menu.set_menu_conditions()
    try:
        if args.operation:
            run_operation(args.operation)
        else:
            show_warning_message()
            run_menu()
    finally:
        cleanup_working_directory()
