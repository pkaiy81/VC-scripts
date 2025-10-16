# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import xml.etree.ElementTree as ET

from lib.console import (
    print_task, print_task_status, print_task_status_error,
    print_task_status_warning, print_header, ColorKey, print_text
)
from lib.constants import STS_SERVER_CONFIG_FILE_PATH, STS_SERVER_CONFIG_PROPERTY_FILE_PATH
from lib.environment import Environment
from lib.exceptions import OperationFailed
from lib.host_utils import VcVersion, get_vc_version, is_file_exists
from lib.input import MenuInput
from lib.java_utils import load_property_file
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
    env = Environment.get_environment()
    vc_version = get_vc_version()
    vc_build = int(env.get_value('VC_BUILD'))

    print_task('Checking VECS store configuration')

    # List of (versionConstraint, buildConstraint, key) tuples that identify
    # what VECS stores are valid for the provided vCenter version.
    versionConfigDB = [
    #   Version        Build     VECS Key
    #   -------------  -----     ----------------------------
        (VcVersion.V7, None,     'localhost_connector_store'),
        (VcVersion.V8, None,     'localhost_connector_store'),
        (VcVersion.V9, None,     'localhost_connector_store'),

        (VcVersion.V7, None,     'localhost_certificate_store'),
        (VcVersion.V8, None,     'localhost_certificate_store'),
        # Beginning with 9.0 there is just one certificate store.
        (VcVersion.V9, None,     'certificate_store'),

        (VcVersion.V7, 20845200, 'clientauth_connector_store'),
        (VcVersion.V8, None,     'clientauth_connector_store'),
        (VcVersion.V9, None,     'clientauth_connector_store'),

        (VcVersion.V7, 20845200, 'clientauth_certificate_store'),
        (VcVersion.V8, None,     'clientauth_certificate_store'),
    ]

    # Initialize the STS configuration based on the VC version constraints.
    sts_config = {}
    for versionConstraint, buildConstraint, key in versionConfigDB:
        if vc_version != versionConstraint:
            continue
        if buildConstraint and vc_build < buildConstraint:
            continue
        sts_config[key] = ''

    # Obtain the STS configuration from vCenter.
    if vc_version >= VcVersion.V9:
        # Note: All entries in the versionConfigDB that match 9.0 must have an
        # entry in the keyMap.
        keyMap = {
          'vmidentity.server.connector.ssl.localhost.certificate.keystore.file': 'localhost_connector_store',
          'vmidentity.server.connector.ssl.store': 'certificate_store',
          'vmidentity.server.connector.ssl.client.auth.certificate.keystore.file': 'clientauth_connector_store',
        }

        config = load_property_file(STS_SERVER_CONFIG_PROPERTY_FILE_PATH)

        for key, value in config.items():
            if key in keyMap:
                sts_config[keyMap[key]] = value
    else:
        config = ET.parse(STS_SERVER_CONFIG_FILE_PATH)
        root = config.getroot()

        conn_cfg = {}
        for connector in root.iter('Connector'):
            if connector.attrib['port'] == '${bio-ssl-localhost.https.port}':
                conn_cfg['localhost_connector_store'] = connector.attrib['store']
                conn_cfg['localhost_certificate_store'] = connector.find('SSLHostConfig').find('Certificate').attrib['certificateKeystoreFile']
            elif connector.attrib['port'] == '${bio-ssl-clientauth.https.port}':
                conn_cfg['clientauth_connector_store'] = connector.attrib['store']
                conn_cfg['clientauth_certificate_store'] = connector.find('SSLHostConfig').find('Certificate').attrib['certificateKeystoreFile']

        for key, value in conn_cfg.items():
            if key in sts_config:
                sts_config[key] = value
            else:
                # This should never happen. It means somehow a key is in the
                # STS server config file that doesn't belong for the given VC
                # version, as indicated by versionConfigDB.
                logger.warning('Unexpected STS server config key: %s' % key)

    logger.info('Checking STS configuration on vCenter {} build {}'.format(vc_version, vc_build))

    vecs_stores_to_replace = set()
    update_sts_config = False
    for key, value in sts_config.items():
        description = key.replace('_', ' ').capitalize()
        logger.info('{}: {}'.format(description, value))

        if value != 'MACHINE_SSL_CERT':
            update_sts_config = True
            vecs_stores_to_replace.add(value)
        sts_config[key] = value

    sts_config['vecs_stores_to_replace'] = vecs_stores_to_replace

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
        if len(get_sso_domain_nodes()) == 1:
            print_task_status('OK')
            return True, search_dn
        sts_connection_strings = result[0]['vmwSTSConnectionStrings']
        if len(sts_connection_strings) > 1:
            add_certificate_status(CertificateStatus.CERT_STATUS_STS_CONNECTION_STRINGS_NUMBER)
            print_task_status_warning('MISCONFIG')
            return False, search_dn
        if sts_connection_strings[0] != 'ldap://localhost:389':
            add_certificate_status(CertificateStatus.CERT_STATUS_STS_CONNECTION_STRINGS_HOSTNAME)
            print_task_status_warning('MISCONFIG')
            return False, search_dn

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


