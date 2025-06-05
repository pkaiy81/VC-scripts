# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import ldap3 as ldap
import logging

from lib import vecs
from lib import vmdir
from lib.certificate_utils import get_certificate_fingerprint, get_x509_certificate
from lib.console import print_text_error
from lib.constants import VMCAM_CERT_FILE_PATH
from lib.environment import Environment
from lib.exceptions import CommandExecutionError
from lib.host_utils import VcVersion, get_file_contents, get_vc_version, get_hostname
from lib.input import MenuInput
from lib.ldap_utils import Ldap, LdapException, get_user_dn

logger = logging.getLogger(__name__)


def prevalidate_credential(**_):
    """
    Enforce that SSO credentials are properly populated
    """
    env = Environment.get_environment()
    _ = env.get_value('SSO_USERNAME')
    _ = env.get_value('SSO_PASSWORD')

    vmdir.init_env_identity_source()
    vmdir.init_env_cac()


def verify_sso_credential(sso_username, sso_password):
    """
    Verify the SSO credential via LDAP authentication

    :param sso_username: Single Sign-On user name
    :param sso_password:  Single Sign-on password
    :return: True if the credential can be verified, otherwise False
    """
    hostname = get_hostname()
    user_dn = get_user_dn(sso_username)
    connection = None
    try:
        connection = Ldap.open_ldap_connection(node=hostname, user_dn=user_dn,
                                               password=sso_password)
        if Ldap.ldap_search(connection, "cn=schemacontext", "(objectClass=*)",
                            ldap.BASE, ["cn"]):
            logger.info("Password verified successfully for user %s", user_dn)
            return True
    except LdapException:
        pass
    finally:
        if connection:
            Ldap.close_ldap_connection(connection)

    logger.error("Password verification failed for user %s on host %s", user_dn, hostname)
    return False


def populate_sso_credential():
    """
    Callback method to populate SSO_USERNAME and SSO_PASSWORD environment variables

    :return: dict containing both verified SSO_USERNAME and SSO_PASSWORD values
    :raise CommandExecutionError: if the credential verification failed
    """
    env = Environment.get_environment()
    default_input = 'administrator@{}'.format(env.get_value('SSO_DOMAIN'))
    counter_username = counter_password = 0
    sso_username = None
    print()
    while counter_username < 3 and counter_password < 3:
        if sso_username:
            default_input = sso_username
        menu_input = MenuInput('Please enter a Single Sign-On administrator account [{}]: '.format(default_input),
                               default_input=default_input, case_insensitive=False)
        sso_username = menu_input.get_input()
        if not check_sso_credential(sso_username):
            sso_username = None
            counter_username += 1
            continue
        menu_input = MenuInput('Please provide the password for {}: '.format(sso_username),
                               masked=True,
                               case_insensitive=False)
        sso_password = menu_input.get_input()
        if not verify_sso_credential(sso_username, sso_password):
            counter_password += 1
            continue
        print()
        return [('SSO_USERNAME', sso_username), ('SSO_PASSWORD', sso_password)]
    raise CommandExecutionError('Invalid SSO credential')


def check_sso_credential(sso_username, sso_password=None):
    """
    Check and verify the SSO credentials. It will validate that the SSO domain matches to
    values obtained from VC. If password is provided, it will try to verify the credential
    by performing LDAP authentication

    :param sso_username:  SSO user name
    :param sso_password:  SSO user password
    :return: True if the validation passed, otherwise False
    """
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    user_name = None
    user_sso_domain = None
    if '@' in sso_username:
        user_name, user_sso_domain = tuple(sso_username.split('@', 2))
    if user_sso_domain != sso_domain:
        print_text_error('Invalid domain, please provide an account in the SSO domain [{}].'.format(sso_domain))
        return False
    elif not user_name:
        print_text_error('Invalid user name')
        return False
    if sso_password is None:
        return True
    return verify_sso_credential(sso_username, sso_password)


def get_vcenter_extensions():
    """
    Get list of vCenter extension
    """
    vcenter_extensions = [
        'com.vmware.vsan.health', 'com.vmware.vcIntegrity', 'com.vmware.rbd', 'com.vmware.imagebuilder',
        'com.vmware.vmcam', 'com.vmware.vim.eam'
    ]

    if get_vc_version() == VcVersion.V8_0:
        vc_build = Environment.get_environment().get_value('VC_BUILD')
        if int(vc_build) >= 22385739:
            vcenter_extensions = ['com.vmware.vsan.health', 'com.vmware.vcIntegrity', 'com.vmware.imagebuilder',
                                  'com.vmware.vmcam', 'com.vmware.vim.eam']
        vcenter_extensions.append('com.vmware.vlcm.client')

    return vcenter_extensions


def get_vcenter_extension_expected_thumbprints(vcenter_extensions):
    """
    Get expected vcenter extension's thumbprint
    :param vcenter_extensions: list of vcenter extension
    :return: dict { vc_extension: (thumbprint, cert_type) }
    """
    pem_cert = vecs.get_certificate('vpxd-extension', 'vpxd-extension')
    vpxd_ext_thumbprint = get_certificate_fingerprint(get_x509_certificate(pem_cert))

    pem_cert = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')
    machine_ssl_thumbprint = get_certificate_fingerprint(get_x509_certificate(pem_cert))

    pem_cert = get_file_contents(VMCAM_CERT_FILE_PATH)
    vmcam_thumbprint = get_certificate_fingerprint(get_x509_certificate(pem_cert))

    result = dict()
    for extension in vcenter_extensions:
        if extension == 'com.vmware.vmcam':
            expected_thumbprint = vmcam_thumbprint
            expected_cert_type = 'Authentication Proxy'
        elif extension == 'com.vmware.vsan.health':
            expected_thumbprint = machine_ssl_thumbprint
            expected_cert_type = 'Machine SSL'
        else:
            expected_thumbprint = vpxd_ext_thumbprint
            expected_cert_type = 'vpxd-extension'
        result[extension] = (expected_thumbprint, expected_cert_type)
    return result
