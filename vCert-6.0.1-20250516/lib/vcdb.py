# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

from lib.command_runner import CommandRunner
from lib.text_utils import TextFilter

PSQL_CLI = '/usr/bin/psql'


def get_extension_thumbprints(extensions):
    """
    Get extension thumbprints from VCDB
    :param extensions: list of extensions to fetch
    :return:  list of tuple (extension name, thumbprint)
    """
    query = "SELECT ext_id, thumbprint FROM vpx_ext WHERE ext_id IN ('{}') ORDER BY ext_id" \
        .format('\', \''.join(extensions))
    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    extensions = TextFilter(output).contain('|').cut(delimiter='|', fields=[0]).remove_white_spaces().get_lines()
    thumbprints = TextFilter(output).contain('|').cut(delimiter='|', fields=[1]).remove_white_spaces().get_lines()
    result = dict()
    for index, extension in enumerate(extensions):
        result[extension] = thumbprints[index]
    return result


def get_extension_thumbprint(extension):
    """
    Get thumbprint for a specific extension
    :param extension: extension name
    :return: extension thumbprint
    """
    query = "SELECT thumbprint FROM vpx_ext WHERE ext_id = '{}'".format(extension)
    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    thumbprint = TextFilter(output).head(1).get_text().strip()
    return thumbprint


def update_extension_thumbprint(extension, thumbprint):
    query = "UPDATE vpx_ext SET thumbprint = '{}' WHERE ext_id = '{}'".format(thumbprint, extension)
    ret_code, _, _ = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres', '-c',
                                   query, '-t').run()
    return ret_code == 0


def get_certificate_management_mode():
    """
    Get certificate management node
    """
    query = 'SELECT value FROM vpx_parameter WHERE name=\'vpxd.certmgmt.mode\''
    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).head(1).get_text().strip()


def get_number_of_hosts():
    """
    Get the number of hosts
    """
    query = 'SELECT COUNT(id) FROM vpx_host WHERE enabled=1'
    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).head(1).get_text().strip()


def get_hosts():
    """
    Get the hosts
    """
    query = 'SELECT id, dns_name, ip_address FROM vpx_host WHERE enabled=1 ORDER BY dns_name ASC, ip_address ASC'

    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres', '-c', query, '-t').run_and_get_output()
    return TextFilter(output).get_text().strip().splitlines()


def get_host_and_cluster_id():
    """
        Get the hosts id and cluster id it belongs too
        """
    query = '''SELECT ent.id, ent.parent_id FROM vpx_entity as ent LEFT JOIN vpx_object_type AS obj ON 
    ent.type_id = obj.id WHERE obj.name = 'HOST' '''

    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).get_text().strip().splitlines()


def get_clusters():
    query = '''SELECT ent.id, ent.name FROM vpx_entity as ent LEFT JOIN vpx_object_type AS obj 
    ON ent.type_id = obj.id WHERE obj.name = 'CLUSTER_COMPUTE_RESOURCE' '''

    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).get_text().strip().splitlines()


def get_ssl_thumbprint_from_vcdb(access_string):
    """
    Get the expected_ssl_thumbprint and host_ssl_thumbprint
    """
    query = 'SELECT expected_ssl_thumbprint,host_ssl_thumbprint FROM vpx_host where  ' \
            'dns_name = \'{0}\' or ip_address = \'{0}\' '.format(access_string)

    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).get_text().strip().splitlines()


def get_vmca_configuration_from_vcdb():
    """
    Get the vpxd.certmgmt.mode and vpxd.certmgmt.cn.* values from the database
    """
    query = "SELECT name,value FROM vpx_parameter WHERE name='vpxd.certmgmt.mode' OR name LIKE 'vpxd.certmgmt.certs.cn.%' ORDER BY name"

    output = CommandRunner(PSQL_CLI, '-d', 'VCDB', '-U', 'postgres',
                           '-c', query, '-t').run_and_get_output()
    return TextFilter(output).get_text().strip().splitlines()