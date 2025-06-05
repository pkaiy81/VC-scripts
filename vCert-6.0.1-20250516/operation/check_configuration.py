# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import xml.etree.ElementTree as ET

from lib.console import (
    print_task, print_task_status, print_task_status_error,
    print_task_status_warning, print_header, ColorKey, print_text
)
from lib.constants import STS_SERVER_CONFIG_FILE_PATH
from lib.environment import Environment
from lib.exceptions import OperationFailed
from lib.host_utils import is_file_exists
from lib.input import MenuInput
from lib.vcdb import get_vmca_configuration_from_vcdb
from lib.vecs import (create_vecs_store_template, get_current_vecs_store_permissions, get_template_vecs_store_permissions, 
                     get_missing_stores, manage_missing_vecs_stores, manage_missing_vecs_permissions
)                     
from lib.vmdir import get_sso_domain_nodes, perform_ldap_search
from operation.check_certificate import CertificateStatus, add_certificate_status

logger = logging.getLogger(__name__)

def check_sts_configuration():
    print_header('Checking STS Server Configuration')
    check_sts_certificate_configuration()
    check_sts_connectionstring_configuration()


def check_sts_certificate_configuration():
    vecs_stores_to_replace = set()
    update_sts_config = False
    env = Environment.get_environment()
    vc_version = env.get_value('VC_VERSION')
    vc_build = env.get_value('VC_BUILD')
    
    print_task('Checking VECS store configuration')
   
    config = ET.parse(STS_SERVER_CONFIG_FILE_PATH)
    root = config.getroot()
    clientauth_connector_store = ''
    clientauth_certificate_store = ''

    for connector in root.iter('Connector'):
        if connector.attrib['port'] == '${bio-ssl-localhost.https.port}':
            localhost_connector_store = connector.attrib['store']
            localhost_certificate_store = connector.find('SSLHostConfig').find('Certificate').attrib['certificateKeystoreFile']
        elif connector.attrib['port'] == '${bio-ssl-clientauth.https.port}':
            clientauth_connector_store = connector.attrib['store']
            clientauth_certificate_store = connector.find('SSLHostConfig').find('Certificate').attrib['certificateKeystoreFile']
    logger.info('Checking STS configuration on vCenter {} build {}'.format(vc_version, vc_build))
    logger.info('Localhost connector store: {}'.format(localhost_connector_store))
    logger.info('Localhost certificate store: {}'.format(localhost_certificate_store))
    logger.info('ClientAuth connector store: {}'.format(clientauth_connector_store))
    logger.info('ClientAuth certificate store: {}'.format(clientauth_certificate_store))
    if vc_version == '8.0' or (vc_version == '7.0' and int(vc_build) >= 20845200):
        if localhost_connector_store == 'MACHINE_SSL_CERT' and \
           localhost_certificate_store == 'MACHINE_SSL_CERT' and \
           clientauth_connector_store == 'MACHINE_SSL_CERT' and \
           clientauth_certificate_store == 'MACHINE_SSL_CERT':
            pass
        else:
            update_sts_config = True
            if localhost_connector_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(localhost_connector_store)
            if localhost_certificate_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(localhost_certificate_store)
            if clientauth_connector_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(clientauth_connector_store)
            if clientauth_certificate_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(clientauth_certificate_store)            
    else:
        if localhost_connector_store == 'MACHINE_SSL_CERT' and \
           localhost_certificate_store == 'MACHINE_SSL_CERT':
            pass
        else:
            update_sts_config = True
            if localhost_connector_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(localhost_connector_store)
            if localhost_certificate_store != 'MACHINE_SSL_CERT':
                vecs_stores_to_replace.add(localhost_certificate_store)

    sts_config = {'localhost_connector_store' : localhost_connector_store, 
                  'localhost_certificate_store' : localhost_certificate_store,
                  'clientauth_connector_store' : clientauth_connector_store,
                  'clientauth_certificate_store' : clientauth_certificate_store,
                  'vecs_stores_to_replace' : vecs_stores_to_replace}
    if update_sts_config:
        add_certificate_status(CertificateStatus.CERT_STATUS_STS_VECS_CONFIG)
        print_task_status_warning('LEGACY')
    else:
        print_task_status('OK')
    return update_sts_config, sts_config


def check_sts_connectionstring_configuration():
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    sso_domain = Environment.get_environment().get_value('SSO_DOMAIN')
    print_task('Checking STS ConnectionStrings')
    search_dn = 'cn={},cn=IdentityProviders,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(sso_domain, sso_domain, domain_dn)
    search_filter = '(objectclass=vmwSTSIdentityStore)'
    search_attributes = ['vmwSTSConnectionStrings']
    result = perform_ldap_search(search_dn, search_filter, search_attributes)
    if result:
        sts_connection_strings = result[0]['vmwSTSConnectionStrings']
        if len(get_sso_domain_nodes()) > 1 and sts_connection_strings != 'ldap://localhost:389':
            add_certificate_status(CertificateStatus.CERT_STATUS_STS_CONNECTION_STRINGS)
            print_task_status_warning('MISCONFIG')
            return False, search_dn
        else:
            print_task_status('OK')
            return True, search_dn
    else:
        print_task_status_error('FAILED')
        error_message = 'Unable to get the vmwSTSConnectionStrings attribute from VMware Directory'
        raise OperationFailed(error_message)
    

def check_vmca_configuration_vcdb():
    settings =get_vmca_configuration_from_vcdb()
    for setting in settings:
        setting_parts = setting.split('|') 
        setting_name = setting_parts[0].strip()
        setting_value = setting_parts[1].strip()
        if not setting_value:
            add_certificate_status(CertificateStatus.CERT_STATUS_VMCA_EMPTY_CONFIG)
            print_text("{:<48}{}'EMPTY'{}".format(setting_name, ColorKey.YELLOW, ColorKey.NORMAL))
        elif setting_name == 'vpxd.certmgmt.mode' and 'setting_value' == 'thumbprint':
            add_certificate_status(CertificateStatus.CERT_STATUS_VMCA_MODE)
            print_text("{:<48}{}'{}'{}".format(setting_name, ColorKey.YELLOW, setting_value, ColorKey.NORMAL))
        else:
            print_text("{:<48}{}'{}'{}".format(setting_name, ColorKey.GREEN, setting_value, ColorKey.NORMAL))


def check_vecs_store_permissions(check_only=True):
    env = Environment.get_environment()
    vc_version = env.get_value('VC_VERSION_LONG')
    vc_build = env.get_value('VC_BUILD')
    vecs_permissions_template = '{}/config/vecs_permissions/vcsa-{}-{}.json'.format(env.get_value('SCRIPT_DIR'), vc_version, vc_build)
    if is_file_exists(vecs_permissions_template):
        print_text('Checking status and permissions for VECS stores:')
        current_permissions = get_current_vecs_store_permissions()
        template_permissions = get_template_vecs_store_permissions(vecs_permissions_template)
        missing_stores = get_missing_stores()
        missing_permissions = {'read'  : {},
                               'write' : {}}
        
        for store, permissions in template_permissions.items():
            print_task('   {}'.format(store))
            
            for expected_read_permission in permissions['read']:
                if expected_read_permission not in current_permissions[store]['read']:
                    if store not in missing_permissions['read']:
                        missing_permissions['read'][store] = []
                    missing_permissions['read'][store].append(expected_read_permission)
            
            for expected_write_permission in permissions['write']:                
                if expected_write_permission not in current_permissions[store]['write']:
                    if store not in missing_permissions['write']:
                        missing_permissions['write'][store] = []
                    missing_permissions['write'][store].append(expected_write_permission)
            
            if store in missing_stores:
                print_task_status_warning('MISSING')
                add_certificate_status(CertificateStatus.CERT_STATUS_STORE_MISSING)
            elif store in missing_permissions['read'] or store in missing_permissions['write']:
                print_task_status_warning('PERMISSIONS')
                add_certificate_status(CertificateStatus.CERT_STATUS_STORE_PERMISSIONS)
            else:
                print_task_status('OK')

        if check_only:
            return
        
        if missing_stores:
            manage_missing_vecs_stores(missing_stores)
                
        if missing_permissions['read'] or missing_permissions['write']:
            manage_missing_vecs_permissions(missing_permissions)
    else:
        print_text('{}VECS store template for {}-{} not found.{}'.format(ColorKey.YELLOW, vc_version, vc_build, ColorKey.NORMAL))
        
        if check_only:
            return
        
        prompt = MenuInput('Create VECS store template? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N')
        print()
        if prompt.get_input() == 'Y':
            create_vecs_store_template(vecs_permissions_template)


