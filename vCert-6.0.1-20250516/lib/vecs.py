# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import json

from lib.console import (
    print_task, print_task_status, print_header, ColorKey, print_text
)
from lib.environment import Environment
from lib.command_runner import CommandRunner
from lib.host_utils import VcVersion, get_vc_version, is_file_exists
from lib.menu import MenuInput
from lib.text_utils import TextFilter
from lib.exceptions import (OperationFailed, CommandExecutionError)



VECS_CLI = '/usr/lib/vmware-vmafd/bin/vecs-cli'
logger = logging.getLogger(__name__)


def get_all_certificates(store):
    """
    Get certificates and aliases from 'vecs-cli entry list' output

    :param store: Certificate store
    :return:  tuple of certificate list and alias list
    """
    args = [VECS_CLI, 'entry', 'list', '--store', store]
    client = CommandRunner(*args, expected_return_code=0)
    return_code, stdout, stderr = client.run()
    certs_pem = TextFilter(stdout).match_block(
        r'.*\s+-----BEGIN CERTIFICATE-----|.*\s+-----BEGIN X509 CRL-----',
        '-----END CERTIFICATE-----|-----END X509 CRL-----', concatenate=True)\
        .remove('Certificate :\t').get_lines()
    aliases = TextFilter(stdout).start_with('Alias').remove_white_spaces().cut(':', [1]).get_lines()
    return certs_pem, aliases


def get_all_ca_certificates():
    """
    Get all trusted root CA certificates from VECS
    """
    return get_all_certificates('TRUSTED_ROOTS')


def get_certificate_aliases(store):
    """
    Get aliases from VECS via 'vecs-cli entry list' command output

    :param store: Certificate store
    :return: list of aliases
    """
    args = [VECS_CLI, 'entry', 'list', '--store', store]
    client = CommandRunner(*args, expected_return_code=0)
    return_code, stdout, stderr = client.run()
    return TextFilter(stdout).start_with('Alias').remove_white_spaces().cut(':', [1]).get_lines()


def get_store_list():
    """
    Get store list in VECS via 'vecs-cli store list' command output
    :return: list of certificate stores in VECS
    """
    args = [VECS_CLI, 'store', 'list']
    client = CommandRunner(*args, expected_return_code=0)
    return_code, stdout, stderr = client.run()
    return stdout.splitlines()


def get_expected_stores_to_check():
   stores = ['MACHINE_SSL_CERT', 'TRUSTED_ROOTS', 'TRUSTED_ROOT_CRLS', 'machine', 'vsphere-webclient',
              'vpxd', 'vpxd-extension', 'SMS', 'APPLMGMT_PASSWORD', 'data-encipherment', 'hvc', 'wcp']
   return stores


def get_missing_stores():
    current_stores = get_store_list()
    expected_stores = get_expected_stores_to_check()
    missing_stores = []
    for store in expected_stores:
        if store not in current_stores:
            missing_stores.append(store)
    
    return missing_stores


def get_certificate(store, alias):
    """
    Get a specific certificate from VECS via 'vecs-cli entry getcert' command output

    :param store: Certificate store in VECS
    :param alias: Certificate alias
    :return: Certificate in PEM format
    """
    args = [VECS_CLI, 'entry', 'getcert', '--store', store, '--alias', alias]
    client = CommandRunner(*args, expected_return_code=0)
    return_code, stdout, stderr = client.run()
    return stdout


def get_key(store, alias):
    """
    Get a specific key entry from VECS via 'vecs-cli entry getkey' command output

    :param store: Certificate store in VECS
    :param alias: certificate alias
    :return: key in PEM format
    """
    args = [VECS_CLI, 'entry', 'getkey', '--store', store, '--alias', alias]
    command = CommandRunner(*args, expected_return_code=0)
    return_code, stdout, stderr = command.run()
    return stdout


def add_entry(store, alias, cert_file, key_file=None):
    """
    Add new entry into VECS

    :param store: the store name
    :param alias: alias for the new entry
    :param cert_file:  certificate file (PEM)
    :param key_file:  key file (PEM)
    """
    args = [VECS_CLI, 'entry', 'create', '--store', store, '--alias', alias, '--cert', cert_file]
    if key_file:
        args.extend(['--key', key_file])
    CommandRunner(*args, expected_return_code=0).run()


def delete_entry(store, alias):
    """
    Delete certificate/key entry from VECS
    :param store: store name
    :param alias:  certificate/key alias
    """
    args = [VECS_CLI, 'entry', 'delete', '--store', store, '--alias', alias, '-y']
    client = CommandRunner(*args, expected_return_code=0).run()


def get_current_vecs_store_permissions():
    current_vecs_permissions = dict()
    stores = get_expected_stores_to_check()
    for store in stores:
        owner, read_users, write_users = get_vecs_store_permission(store)
        current_vecs_permissions[store] = {'owner' : owner,
                                           'read'  : read_users,
                                           'write' : write_users}
        
    return current_vecs_permissions


def get_template_vecs_store_permissions(template_file):
    desired_vecs_permissions = dict()
    if is_file_exists(template_file):
        try:
            template_file_handler = open(template_file)
            template_data = json.load(template_file_handler)
            template_file_handler.close()
        except Exception as e:
            error_message = 'Unable to open template file: {}'.format(str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)

        for store, permissions in template_data.items():
            desired_vecs_permissions[store] = dict()
            desired_vecs_permissions[store]['owner'] = permissions['owner']
            desired_vecs_permissions[store]['read'] = permissions['read']
            desired_vecs_permissions[store]['write'] = permissions['write']
        
    return desired_vecs_permissions


def get_vecs_store_permission(store):
    """
    Get VECS store permissions

    :param store: VECS store
    :return: tuple (owner, list of users with read permission, list of users with write permissions)
    """
    args = [VECS_CLI, 'store', 'get-permissions', '--name', store]
    client = CommandRunner(*args, expected_return_code=0)
    _, stdout, _ = client.run()
    owner = TextFilter(stdout).start_with('OWNER').cut(':', [1]).get_text().strip()
    read_users = TextFilter(stdout).match('.*read$').cut('\t', [0]).get_lines()
    write_users = TextFilter(stdout).match('.*write$').cut('\t', [0]).get_lines()
    return owner, read_users, write_users


def force_refresh():
    """
    Force VECS refresh from VMDir
    """
    CommandRunner(VECS_CLI, 'force-refresh', expected_return_code=0).run()


def grant_vecs_permission(store, user, perm):
    args = [VECS_CLI, 'store', 'permission', '--name', store, '--user', user, '--grant', perm]
    try:
        CommandRunner(*args, expected_return_code=0).run()
    except CommandExecutionError:
        error_message = 'Unable to assign {} permission to user {} on store {}'.format(perm, user, store)
        logger.error(error_message)
        raise OperationFailed(error_message)
 

def create_store(store):
    """
    Create store in VECS via 'vecs-cli store create' command
    """
    args = [VECS_CLI, 'store', 'create', '--name', store]
    try:
        CommandRunner(*args, expected_return_code=0).run()
    except CommandExecutionError:
        error_message = "Unable to create VECS store {}".format(store)
        logger.error(error_message)
        raise OperationFailed(error_message)


def delete_store(store):
    """
    Create store in VECS via 'vecs-cli store create' command
    """
    args = [VECS_CLI, 'store', 'delete', '--name', store, '-y']
    try:
        CommandRunner(*args, expected_return_code=0).run()
    except CommandExecutionError:
        error_message = "Unable to delete VECS store {}".format(store)
        logger.error(error_message)
        raise OperationFailed(error_message)


def create_vecs_store_template(template_file):
    print_header('Create VECS Store Template')
    print_task('Creating template file')
    template = get_current_vecs_store_permissions()   
    try:
        with open(template_file, 'w') as outfile:
            json.dump(template, outfile)
        print_task_status('OK')
    except Exception as e:
        error_message = 'Unable to write template file: {}'.format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)
    

def manage_missing_vecs_stores(missing_stores):
    prompt = MenuInput('Some VECS stores are missing, recreate them? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N')
    print()
    if prompt.get_input() == 'Y':
        print_header('Recreate VECS Store')
        for store in missing_stores:
            print_task(store)
            create_store(store)
            print_task_status('OK')


def manage_missing_vecs_permissions(missing_permissions):
    prompt = MenuInput('Some VECS stores are missing expected permissions, reassign them? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N')
    print()
    if prompt.get_input() == 'Y':
        print_header('Reassign VECS Store Permissions')
        if missing_permissions['read']:
            print_text('Reassigning READ permissions:')
            for store, missing_read_users in missing_permissions['read'].items():
                print_text('   Store {}:'.format(store))
                for user in missing_read_users:
                    print_task('      {}'.format(user))
                    grant_vecs_permission(store, user, 'read')
                    print_task_status('OK')

        if missing_permissions['write']:
            print_text('Reassigning WRITE permissions:')
            for store, missing_write_users in missing_permissions['write'].items():
                print_text('   Store {}:'.format(store))
                for user in missing_write_users:
                    print_task('      {}'.format(user))
                    grant_vecs_permission(store, user, 'write')
                    print_task_status('OK')