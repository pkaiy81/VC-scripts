# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import ipaddress
import glob
import logging
import os
import pathlib
import re
import shutil
import socket
import sys
import xml.etree.ElementTree as ET
from enum import Enum

from lib.console import print_text_warning
from lib.constants import RHTTPPROXY_CONFIG_FILE_PATH, STS_SERVER_CONFIG_FILE_PATH, STS_SERVER_CONFIG_PROPERTY_FILE_PATH
from lib.environment import Environment
from lib.execution_replay import ReplayContext
from lib.command_runner import CommandRunner
from lib.java_utils import load_property_file
from lib.text_utils import TextFilter

VMAFD_CLI = '/usr/lib/vmware-vmafd/bin/vmafd-cli'
LWREGSHELL_CLI = '/opt/likewise/bin/lwregshell'
TEE_CMD = '/usr/bin/tee'
FILE_CMD = '/usr/bin/file'
CHMOD_CMD = '/bin/chmod'


logger = logging.getLogger(__name__)


class VcVersion(Enum):
    """
    Define the recognized versions of VC.
    """
    # We assume the needed version values are only major and minor releases,
    # and not patches for example. This allows us to represent the versions as
    # floating point numbers for relative comparison. For code specific to
    # patch releases, the tool resorts to build numbers, which are checked as
    # needed.
    #
    # Also, the order of enum definitions must be kept in increasing order,
    # including minor releases.
    Invalid = None
    V7 = '7'
    V8 = '8'
    V9 = '9'

    @classmethod
    def min(cls):
        """Minimum supported vCenter version"""
        return min([float(v) for v in cls if v.value is not None])

    @classmethod
    def max(cls):
        """Maximum supported vCenter version"""
        return max([float(v) for v in cls if v.value is not None])

    @property
    def major(self):
        """Return the major release number for the release."""
        if self.value is None:
            return None
        # Floats that are actually integers always end with ".0" as a string.
        return str(float(self)).split('.')[0]

    @property
    def minor(self):
        """Return the minor release number for the release."""
        if self.value is None:
            return None
        # Floats that are actually integers always end with ".0" as a string.
        return str(float(self)).split('.')[1]

    def _validate(self, other):
        if not isinstance(other, VcVersion):
            raise ValueError(other)

    def __float__(self):
        # If there is no value (for the Invalid entry) then return float NaN
        # so all comparison operations return False. (However, we provide
        # special direct comparison overrides for != and == so that comparisons
        # with VcVersion.Invalid work as expected.)
        return float('nan') if self.value is None else float(self.value)

    def __lt__(self, other):
        self._validate(other)
        return float(self) < float(other)

    def __le__(self, other):
        self._validate(other)
        return float(self) <= float(other)

    def __eq__(self, other):
        self._validate(other)
        return self.value == other.value

    def __ne__(self, other):
        self._validate(other)
        return self.value != other.value

    def __gt__(self, other):
        self._validate(other)
        return float(self) > float(other)

    def __ge__(self, other):
        self._validate(other)
        return float(self) >= float(other)


def init_env_host():
    """
    Obtain basic information from VC server
    """
    vpxd_info = CommandRunner('vpxd', '-v').run_and_get_output().strip().split(' ')
    vc_version_long = vpxd_info[2]
    vc_version = '.'.join(vc_version_long.split('.')[:-1])
    vc_build = vpxd_info[3].split('-')[1]
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

    env = Environment.get_environment()
    env.set_value('VC_VERSION', vc_version)
    env.set_value('VC_VERSION_LONG', vc_version_long)
    env.set_value('VC_BUILD', vc_build)
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

    smart_card_filter_file = get_smart_card_filter_file()
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


def get_config_file_path(config_file):
    env = Environment.get_environment()
    if os.path.isabs(config_file):
        if is_file_exists(config_file):
            return config_file
        else:
            print_text_warning("Unable to find configuration file '{}'".format(config_file))
            print_text_warning('Script cannot continue. Exiting...')
            sys.exit(1)
    else:
        vcert_relative_config_path = "{}/{}".format(env.get_value('SCRIPT_DIR'), config_file)
        cwd_relative_config_path = "{}/{}".format(os.getcwd(), config_file)
        if is_file_exists(vcert_relative_config_path):
            return vcert_relative_config_path
        elif is_file_exists(cwd_relative_config_path):
            return cwd_relative_config_path
        else:
            print_text_warning("Configuration file does not exist in the vCert script directory ({}),".format(vcert_relative_config_path))
            print_text_warning("nor in the current working directory ({}).".format(cwd_relative_config_path))
            print_text_warning('Script cannot continue. Exiting...')
            sys.exit(1)


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


def get_vc_version():
    """
    Get the VC version. The value is obtained from environment variable VC_VERSION

    :return: VC version as VcVersion enum
    """
    vc_version = Environment.get_environment().get_value('VC_VERSION')
    # Versions in VcVersion are kept in increasing order. Thus we search the
    # versions in reverse order to bulletproof the code against versions that
    # are represented just as a major release versus ones that are represented
    # as major.minor.
    for definedVcVersion in reversed(VcVersion):
       if (    definedVcVersion.value is not None
           and vc_version.startswith(definedVcVersion.value)):
          return definedVcVersion
    return VcVersion.Invalid


def init_env_solution_users():
    """
    Initialize set of solution users to be checked, saved the list into environment
    variable 'SOLUTION_USERS'
    """
    solutionUserDB = {
    #   Solution User        Version Constraint (None means all)
    #   -------------------  -----------------------------------
        'machine':           None,
        'vsphere-webclient': None,
        'vpxd':              None,
        'vpxd-extension':    None,
        'hvc':               None,
        'wcp':               [VcVersion.V7, VcVersion.V8],
        'wcpsvc':            [VcVersion.V9],
    }

    env = Environment.get_environment()
    vc_version = get_vc_version()

    solution_users = []
    for solutionUser, versionConstraint in solutionUserDB.items():
        if versionConstraint and not vc_version in versionConstraint:
           continue
        solution_users.append(solutionUser)

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


def get_smart_card_filter_file():
    def revproxy_get_file():
        # Before 7.0 U3i the location of the Smart Card filter file is defined
        # in the reverse proxy config.
        config = ET.parse(RHTTPPROXY_CONFIG_FILE_PATH)
        root = config.getroot()
        client_ca_list_file = root.find('clientCAListFile')
        if client_ca_list_file is None:
            filter_file = ''
        else:
            filter_file = client_ca_list_file.text
            filter_file = '/etc/vmware-rhttpproxy/{}'.format(filter_file) if filter_file.startswith('/') is False else filter_file
        return filter_file

    def xml_config_get_file():
        # After 7.0 U3i the location of the Smart Card filter file is
        # hard-coded in the STS server config which is an XML file.
        config = ET.parse(STS_SERVER_CONFIG_FILE_PATH)
        root = config.getroot()
        for connector in root.iter('Connector'):
            if connector.attrib['port'] == '${bio-ssl-clientauth.https.port}':
                return connector.find('SSLHostConfig').attrib['truststoreFile']
        return '' # Not found

    def prop_config_get_file():
        # Starting with 9.0 the Smart Card filter file is in the STS server
        # configuration file which is a Java property file.
        config = load_property_file(STS_SERVER_CONFIG_PROPERTY_FILE_PATH)
        return config.get('vmidentity.server.connector.ssl.client.auth.truststore.file', '')

    # In the following DB, search stops on first match.
    # Order of entries in the DB must be from most specific to least specific
    # (for example an entry with a version specifying a build must be before
    # the same version with no build).
    smartCardConfigDB = [
    #   Version        Build     Retrieval Function
    #   -------------  --------  ---------------------
        (VcVersion.V7, 20845200, xml_config_get_file),
        (VcVersion.V7, None,     revproxy_get_file),
        (VcVersion.V8, None,     xml_config_get_file),
        (VcVersion.V9, None,     prop_config_get_file),
    ]

    env = Environment.get_environment()
    vc_version = get_vc_version()
    vc_build = int(env.get_value('VC_BUILD'))

    # Resolve the retrieval function. We break on first match.
    get_file = None
    for versionConstraint, buildConstraint, func in smartCardConfigDB:
        if vc_version != versionConstraint:
            continue
        if buildConstraint and vc_build < buildConstraint:
            continue

        # Found a match.
        get_file = func
        break

    # If found, execute the retrieval function; otherwise return an empty
    # string.
    return get_file() if get_file else ''
