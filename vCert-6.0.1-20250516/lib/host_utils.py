# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import ipaddress
import glob
import logging
import os
import pathlib
import re
import shutil
import socket
import xml.etree.ElementTree as ET
from enum import Enum

from lib.constants import RHTTPPROXY_CONFIG_FILE_PATH, STS_SERVER_CONFIG_FILE_PATH
from lib.environment import Environment
from lib.execution_replay import ReplayContext
from lib.command_runner import CommandRunner
from lib.text_utils import TextFilter

VMAFD_CLI = '/usr/lib/vmware-vmafd/bin/vmafd-cli'
LWREGSHELL_CLI = '/opt/likewise/bin/lwregshell'
SERVICE_CONTROL_CLI = '/usr/bin/service-control'
TEE_CMD = '/usr/bin/tee'
FILE_CMD = '/usr/bin/file'
CHMOD_CMD = '/bin/chmod'


logger = logging.getLogger(__name__)


class NodeType(Enum):
    EMBEDDED = 'embedded'
    # unsupported node types
    INFRASTRUCTURE = 'infrastructure'
    MANAGEMENT = 'management'


class VcVersion(Enum):
    V7_0 = '7.0'
    V8_0 = '8.0'
    # unsupported versions
    V6_5 = '6.5'
    V6_7 = '6.7'


def init_env_host():
    """
    Obtain basic information from VC server
    """
    vpxd_info = CommandRunner('vpxd', '-v').run_and_get_output().strip().split(' ')
    vc_version_long = vpxd_info[2]
    vc_version = '.'.join(vc_version_long.split('.')[:-1])
    vc_build = vpxd_info[3].split('-')[1]
    node_type = get_file_contents('/etc/vmware/deployment.node.type').strip()
    hostname = CommandRunner('hostname', '-f').run_and_get_output().strip()
    pnid = CommandRunner(VMAFD_CLI, 'get-pnid', '--server-name', 'localhost').run_and_get_output().strip()
    machine_id = CommandRunner(VMAFD_CLI, 'get-machine-id', '--server-name', 'localhost').run_and_get_output().strip()
    ifconfig_output = CommandRunner('/usr/sbin/ifconfig', 'eth0').run_and_get_output()
    ip_address = TextFilter(ifconfig_output).head(2).tail(1).get_text().strip().split('  ')[0].replace(':', ' ').split(' ')[-1]
    sso_domain = CommandRunner(VMAFD_CLI, 'get-domain-name', '--server-name', 'localhost').run_and_get_output().strip()
    sso_site = CommandRunner(VMAFD_CLI, 'get-site-name', '--server-name', 'localhost').run_and_get_output().strip()
    sso_domain_dn = "dc={}".format(",dc=".join(sso_domain.split('.')))
    vmdir_account_dn, vmdir_account_password = get_vmdir_machine_account()
    local_hostname = socket.getfqdn()
    smart_card_filter_file = get_smart_card_filter_file(vc_version, vc_build)

    env = Environment.get_environment()
    env.set_value('VC_VERSION', vc_version)
    env.set_value('VC_VERSION_LONG', vc_version_long)
    env.set_value('VC_BUILD', vc_build)
    env.set_value('NODE_TYPE', node_type)
    env.set_value('HOSTNAME', hostname)
    env.set_value('LOCAL_HOSTNAME', local_hostname)
    env.set_value('PNID', pnid)
    env.set_value('MACHINE_ID', machine_id)
    env.set_value('IP_ADDRESS', ip_address)
    env.set_value('SSO_DOMAIN', sso_domain)
    env.set_value('SSO_SITE', sso_site)
    env.set_value('SSO_DOMAIN_DN', sso_domain_dn)
    env.set_value('VMDIR_MACHINE_ACCOUNT_DN', vmdir_account_dn)
    env.set_value('VMDIR_MACHINE_ACCOUNT_PASSWORD', vmdir_account_password)
    env.set_value('SMART_CARD_FILTER_FILE', smart_card_filter_file)
    init_env_solution_users()


def get_vmdir_machine_account():
    """
    Get machine account from likewise
    :return: a tupple of ( account_dn, account_password)
    """
    output = CommandRunner(LWREGSHELL_CLI, 'list_values',
                           r'[HKEY_THIS_MACHINE\services\vmdir]').run_and_get_output()

    account_dn = TextFilter(output).contain('"dcAccountDN"').cut('REG_SZ', [1]).get_text().strip()[1:-1]\
        .replace('\\"', r'"').replace('\\\\', '\\')
    account_password = TextFilter(output).contain('dcAccountPassword').cut('REG_SZ', [1]).get_text().strip()[1:-1]\
        .replace('\\"', r'"').replace('\\\\', '\\')
    return account_dn, account_password


def is_file_exists(file):
    """
    Wrapper for checking file existence.
    This wrapper is required to redirect operation when VCERT_REMOTE_EXEC is True

    :param file: file path to be checked
    :return: True if file is exist
    """
    if not is_remote_exec():
        return os.path.exists(file)

    return_code, _, _  = CommandRunner('/bin/ls', file, expected_return_code=None).run()
    return return_code == 0


def make_directory(path):
    """
    Wrapper for making directory.
    This wrapper is required to redirect operation when VCERT_REMOTE_EXEC is True

    :param path: directory path to be created
    :return: True if the operation success, otherwise False
    """
    if is_remote_exec():
        command_runner = CommandRunner('/bin/mkdir', '-p', path, expected_return_code=None)
        return_code, _, _ = command_runner.run()
        return return_code == 0

    try:
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def remove_directory(path, remove_all=False):
    """
    Wrapper for removing directory
    This wrapper is required to redirect operation when VCERT_REMOTE_EXEC is True
    :param path: Directory path to remove
    :param remove_all: if True, this method will remove the directory contents before trying to
        remove the directory
    :return: True if the operation success, otherwise False
    """
    if is_remote_exec():
        if remove_all:
            command_runner = CommandRunner('/bin/rmdir', '-r', path, expected_return_code=None)
        else:
            command_runner = CommandRunner('/bin/rmdir', path, expected_return_code=None)
        return_code, _, _ = command_runner.run()
        return return_code == 0

    try:
        if remove_all:
            shutil.rmtree(path)
        else:
            pathlib.Path(path).rmdir()
    except Exception:
        return False


def get_file_contents(file):
    """
    Wrapper for reading file contents.
    This wrapper is required to redirect operation when VCERT_REMOTE_EXEC is True

    :param file: File path to load
    :return:  File contents
    """
    if not is_remote_exec():
        with open(file, 'r') as f:
            return f.read()

    command_runner = CommandRunner('/bin/cat', file, expected_return_code=0)
    _, stdout, _ = command_runner.run()
    return stdout


def get_hostname():
    """
    Wrapper obtaining remote hostname
    This wrapper is required to redirect operation when VCERT_REMOTE_EXEC is True

    :return: return VCERT_REMOTE_HOSTNAME value if VCERT_REMOTE_EXEC is True,
        otherwise return 'localhost'
    """
    if is_remote_exec():
        hostname = Environment.get_environment().get_value('VCERT_REMOTE_HOSTNAME')
    else:
        hostname = 'localhost'
    return hostname


def is_remote_exec():
    """
    Check if remote execution is set
    :return: True if remote execution is set, otherwise False
    """
    return Environment.get_environment().get_value('VCERT_REMOTE_EXEC') is True


def get_node_type():
    """
    Get the  VC node type.
    The value is obtained from environment variable NODE_TYPE

    :return: the VC node type as NodeType enum
    """
    node_type = Environment.get_environment().get_value('NODE_TYPE')
    if node_type == NodeType.EMBEDDED:
        return NodeType.EMBEDDED
    elif node_type == NodeType.INFRASTRUCTURE:
        return NodeType.INFRASTRUCTURE
    elif node_type == NodeType.MANAGEMENT:
        return NodeType.MANAGEMENT
    return None


def get_vc_version():
    """
    Get the VC version. The value is obtained from environment variable VC_VERSION

    :return: VC version as VcVersion enum
    """
    vc_version = Environment.get_environment().get_value('VC_VERSION')
    if vc_version.startswith(VcVersion.V7_0.value):
        return VcVersion.V7_0
    elif vc_version.startswith(VcVersion.V8_0.value):
        return VcVersion.V8_0
    elif vc_version.startswith(VcVersion.V6_7.value):
        return VcVersion.V6_7
    elif vc_version.startswith(VcVersion.V6_5.value):
        return VcVersion.V6_5
    return None


def init_env_solution_users():
    """
    Initialize set of solution users to be checked, saved the list into environment
    variable 'SOLUTION_USERS'
    """
    env = Environment.get_environment()
    vc_version = env.get_value('VC_VERSION')
    solution_users = ['machine', 'vsphere-webclient']
    if get_node_type() != NodeType.INFRASTRUCTURE:
        solution_users.extend(['vpxd', 'vpxd-extension'])
        if re.match(r'^[78]', vc_version):
            solution_users.extend(['hvc', 'wcp'])
    env.set_value('SOLUTION_USERS', solution_users)


def is_valid_ip_address(hostname_or_ip):
    try:
        ipaddress.ip_address(hostname_or_ip)
        return True
    except ValueError:
        return False


def get_ip_address(hostname_or_ip):
    if is_valid_ip_address(hostname_or_ip):
        return hostname_or_ip
    else:
        return socket_gethostbyname(hostname_or_ip)


def socket_gethostbyname(hostname):
    category = 'other'
    command_args = ['socket', 'gethostbyname', 'hostname', hostname]
    context = ReplayContext.get_replay_context()
    if context and context.is_replaying:
        result = context.get_execution_result(category, command_args, None)
        if result is not None:
            _, ip_address, _ = result
            return ip_address

    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip_address = ''
    if context and context.is_capturing:
        context.store_result(category, command_args, None, 0, ip_address, None)

    return ip_address


def is_service_running(service_name):
    """
    Check if VMware service {service_name} is running
    :param service_name: Service to be checked
    :return:  True if the service is running, otherwise False
    """
    return_code, stdout, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--status', service_name).run()
    return return_code == 0 and TextFilter(stdout).start_with('Stopped:').get_count() == 0


def get_vmon_service_profile():
    """
    Get vmon service profile
    """
    vmon_service_profile = get_file_contents('/storage/vmware-vmon/defaultStartProfile')
    return ['--vmon-profile', 'HAActive'] if 'HACore' in vmon_service_profile else ['--all']


def list_vmware_services():
    """
    Get a list of services present in the VC
    :param:
    :return: List of services 
    """
    output = CommandRunner(SERVICE_CONTROL_CLI, '--list-services').run_and_get_output().strip()
    services = TextFilter(output).cut(fields=[0]).get_lines()
    return services


def start_vmware_services(service=None):
    """
    Start VMware services
    :param service: to be started. If it's None, all service will be restarted
    :return: True if service(s) are started successfully. Otherwise, False
    """
    if service is None:
        service_profile = get_vmon_service_profile()
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--start', *service_profile).run()
    else:
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--start', service).run()

    if ret_code != 0:
        logger.error("Failed to start VMware services: {}".format(stderr))
        return False
    return True


def stop_vmware_services(service=None):
    """
    Stop VMware service
    :param service: to be stopped. If it's None, all service will be stopped
    :return: True if service(s) are started successfully. Otherwise, False
    """
    if service is None:
        service_profile = get_vmon_service_profile()
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--stop', *service_profile).run()
    else:
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--stop', service).run()

    if ret_code != 0:
        logger.error("Failed to stop VMware services: {}".format(stderr))
        return False
    return True


def save_text_to_file(text, filename):
    """
    A wrapper to write {text} to file {filename}
    :param filename:  the output filename
    :param text:  file contents
    """
    if is_remote_exec():
        CommandRunner(TEE_CMD, filename, command_input=text, expected_return_code=0).run()
        return

    with open(filename, 'w') as file:
        file.write(text)


def append_text_to_file(text, filename, start_new_line=True):
    """
    A wrapper to append {text} to file {filename}
    :param text:  text to append
    :param file:  the existing filename
    :param start_new_line:  start appending data on a new line
    """
    if is_remote_exec():
        CommandRunner(TEE_CMD, '-a', filename, command_input=text, expected_return_code=0).run()
        return
    
    with open(filename, 'a') as file:
        if start_new_line:
            file.write("\n{}".format(text))
        else:
            file.write(text)

def find_files(pattern):
    """
    Wrapper for glob.glob({pattern}) method
    :param pattern: glob patter for matching
    """

    if is_remote_exec():
        output = CommandRunner('/usr/bin/sh', '-c', "eval ls -1 '{}'".format(pattern)).run_and_get_output()
        return output.splitlines()

    return glob.glob(pattern)


def get_file_type(filename):
    """
    Get file type returned by /usr/bin/file command
    """
    output = CommandRunner(FILE_CMD, filename,
                expected_return_code =0).run_and_get_output()
    return TextFilter(output).cut(delimiter=':', fields=[1]).get_text().strip()


def set_file_mode(file_path, mode):
    """
    A wrapper for setting file mode on {filename}
    :param file_path: File path to be modified
    :param mode: permission value, the exact permission value to be passed to os.chmod()
    """
    if is_remote_exec():
        mode_string = "{:04o}".format(mode)
        CommandRunner(CHMOD_CMD, mode_string, file_path, expected_return_code=0).run()
    else:
        os.chmod(file_path, mode)


def get_smart_card_filter_file(vc_version, vc_build):
    filter_file = ''
    # After 7.0 U3i the location of the Smart Card filter file is hard-coded in the STS server config
    if vc_version == '7.0' and int(vc_build) >= 20845200 or vc_version == '8.0':
        config = ET.parse(STS_SERVER_CONFIG_FILE_PATH)
        root = config.getroot()
        for connector in root.iter('Connector'):
            if connector.attrib['port'] == '${bio-ssl-clientauth.https.port}':
                filter_file = connector.find('SSLHostConfig').attrib['truststoreFile']
        pass
    # Before 7.0 U3i the location of the Smart Card filter file is defined in the reverse proxy config
    else:
        config = ET.parse(RHTTPPROXY_CONFIG_FILE_PATH)
        root = config.getroot()
        client_ca_list_file = root.find('clientCAListFile')
        if client_ca_list_file is not None:
            filter_file = client_ca_list_file.text
            filter_file = '/etc/vmware-rhttpproxy/{}'.format(filter_file) if filter_file.startswith('/') is False else filter_file
    return filter_file