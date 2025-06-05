# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import stat

from lib.command_runner import CommandRunner
from lib.console import (
    print_task, print_task_status, print_task_status_warning, print_header, ColorKey, print_text
)
from lib.constants import STS_SERVER_CONFIG_FILE_PATH
from lib.environment import Environment
from lib.exceptions import OperationFailed, CommandExecutionError
from lib.host_utils import set_file_mode, save_text_to_file
from lib.ldap_utils import LdapException
from lib.menu import MenuInput
from lib.vecs import get_certificate, get_key, delete_store, create_store, grant_vecs_permission
from lib.vmdir import perform_ldap_modify
from operation.check_configuration import check_sts_certificate_configuration, check_sts_connectionstring_configuration
from operation.restart_service import restart_vmware_services

logger = logging.getLogger(__name__)

def manage_sts_configuration():
    print_header('Checking STS Server Configuration')
    need_to_update_configuration, sts_config = check_sts_certificate_configuration()
    if not need_to_update_configuration:
        print_text('\nThe STS server is using the {}MACHINE_SSL_CERT{} VECS store.\n'.format(ColorKey.GREEN, ColorKey.NORMAL))
    else:
        manage_sts_certificate_configuration(sts_config)

    need_to_update_connectionstrings, connectionstring_dn = check_sts_connectionstring_configuration()
    if not need_to_update_connectionstrings:
        manage_sts_connectionstrings(connectionstring_dn)
        

def manage_sts_certificate_configuration(sts_config):
    env = Environment.get_environment()
    vc_version = env.get_value('VC_VERSION')
    vc_build = env.get_value('VC_BUILD')
    localhost_connector_store = sts_config['localhost_connector_store']
    localhost_certificate_store = sts_config['localhost_certificate_store']
    clientauth_connector_store = sts_config['clientauth_connector_store']
    clientauth_certificate_store = sts_config['clientauth_certificate_store']
    vecs_stores_to_replace = sts_config['vecs_stores_to_replace']
    print_text('\nThe STS server is using the following VECS stores:')
    print_text('Server > Service > Connector (localhost port): {}{}{}'.format(ColorKey.YELLOW, localhost_connector_store, ColorKey.NORMAL))
    print_text('Server > Service > Connector (localhost port) > SSLHostConfig > Certificate: {}{}{}'.format(ColorKey.YELLOW, localhost_certificate_store, ColorKey.NORMAL))
    if vc_version == '8.0' or (vc_version == '7.0' and int(vc_build) >= 20845200):
        print_text('Server > Service > Connector (client auth port): {}{}{}'.format(ColorKey.YELLOW, clientauth_connector_store, ColorKey.NORMAL))
        print_text('Server > Service > Connector (client auth port) > SSLHostConfig > Certificate: {}{}{}'.format(ColorKey.YELLOW, clientauth_certificate_store, ColorKey.NORMAL))
    
    user_input = MenuInput('\nUpdate STS server configuration to use the {}MACHINE_SSL_CERT{} store? [N]: '.format(ColorKey.GREEN, ColorKey.NORMAL),
                               acceptable_inputs=['Y', 'N'], default_input='N')
    if user_input.get_input() == 'N':
        print()
        return
    backup_dir = env.get_value('BACKUP_DIR')
    print_header('Updating STS server configuration')
    print_text('Backing up configuration')
    sts_config_backup = '{}/sts-server.xml'.format(backup_dir)
    try:
        CommandRunner('cp', STS_SERVER_CONFIG_FILE_PATH, sts_config_backup).run_and_get_output()
        set_file_mode(sts_config_backup, stat.S_IRUSR | stat.S_IWUSR)
    except CommandExecutionError:
        print_task_status_warning('FAILED')
        error_message = 'Unable to backup STS server configuration'
        logger.error(error_message)
        raise OperationFailed(error_message)
        
    for store in vecs_stores_to_replace:
        print_task('Store {}: Backing up certificate'.format(store))
        sts_backup_cert = get_certificate(store, '__MACHINE_CERT')
        save_text_to_file(sts_backup_cert, '{}/sts-{}.crt'.format(backup_dir, store))
        print_task_status('OK')

        print_task('Store {}: Backing up key'.format(store))
        sts_backup_key = get_key(store, '__MACHINE_CERT')
        save_text_to_file(sts_backup_key, '{}/sts-{}.key'.format(backup_dir, store))
        print_task_status('OK')

        print_task('Changing STS server configuration')
        try:
            CommandRunner('sed', '-i', 's/{}/MACHINE_SSL_CERT/g'.format(store), STS_SERVER_CONFIG_FILE_PATH).run()
        except:
            print_task_status_warning('FAILED')
            error_message = 'Unable to change STS server configuration'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')

        if store == 'STS_INTERNAL_SSL_CERT':
            print_task('Remove legacy STS VECS store')
            delete_store('STS_INTERNAL_SSL_CERT')
            print_task_status('OK')
    restart_vmware_services('vmware-stsd')


def manage_sts_connectionstrings(search_dn):
    user_input = MenuInput('\nUpdate STS ConnectionStrings value to {}ldap://localhost:389{}? [N]: '.format(ColorKey.GREEN, ColorKey.NORMAL),
                               acceptable_inputs=['Y', 'N'], default_input='N')
    if user_input.get_input() == 'N':
        print()
        return
    print_header('Update STS ConnectionStrings')
    print_task('Change vmwSTSConnectionStrings value')
    try:
        perform_ldap_modify(search_dn, 'vmwSTSConnectionStrings', 'ldap://localhost:389')
        print_task_status('OK')
    except LdapException:
        error_message = "Failed updating vmwSTSConnectionStrings to 'ldap://localhost:389'"
        logger.error(error_message)
        raise OperationFailed(error_message)