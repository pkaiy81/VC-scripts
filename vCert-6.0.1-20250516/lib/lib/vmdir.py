# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import ldap3 as ldap
import logging
import re
from lib import certificate_utils as certutil
from lib.environment import Environment
from lib.certificate_utils import build_pem_certificate
from lib.command_runner import CommandRunner
from lib.console import print_task, print_text_error
from lib.host_utils import VcVersion, get_hostname, get_vc_version
from lib.ldap_utils import Ldap, LdapException, get_user_dn
from lib.text_utils import TextFilter
from lib.console import (print_task_status)
from lib.exceptions import OperationFailed, CommandExecutionError


DIR_CLI = '/usr/lib/vmware-vmafd/bin/dir-cli'
VDCADMINTOOL = '/usr/lib/vmware-vmdir/bin/vdcadmintool'
cache_ca_keyids = None
cache_ca_certificate_map = dict()

logger = logging.getLogger(__name__)


def get_ldap_connection(use_machine_account=False):
    env = Environment.get_environment()
    if use_machine_account:
        user_dn = env.get_value('VMDIR_MACHINE_ACCOUNT_DN')
        user_password = env.get_value('VMDIR_MACHINE_ACCOUNT_PASSWORD')
    else:
        sso_username = env.get_value('SSO_USERNAME')
        user_password = env.get_value('SSO_PASSWORD')
        user_dn = get_user_dn(sso_username)
    hostname = get_hostname()

    return Ldap.open_ldap_connection(node=hostname, user_dn=user_dn, password=user_password)


def close_ldap_connection(ldap_connection):
    Ldap.close_ldap_connection(ldap_connection)


def perform_ldap_search(search_base, search_filter, search_attributes, search_scope=ldap.SUBTREE,
                        use_machine_account=False, throw_exception=False):
    """
    Utility method to perform LDAP search

    :param search_base: LDAP search base DN
    :param search_filter:  LDAP search filter
    :param search_attributes:  LDAP search attribute
    :param search_scope: LDAP search scope (default: ldap.SUBTREE)
    :param use_machine_account:  Flag to use VMDir machine account instead of SSO user account
    :param throw_exception: When LDAP search fails, throw exception instead of empty result
    :return:  list of matching object, as dict with keys from search_attributes paramerter
    """
    results = []
    connection = None
    try:
        connection = get_ldap_connection(use_machine_account)
        if not Ldap.ldap_search(connection, search_base, search_filter, search_scope, search_attributes):
            logger.error("Unable to perform LDAP search base_dn={}, filter={}" \
                         .format(search_base, search_filter))
            if throw_exception:
                raise LdapException(connection.result['result'], connection.result['description'])
            else:
                return results
        if connection.result:
            for entry in connection.response:
                attributes = entry['attributes']
                if 'dn' in search_attributes and not attributes['dn']:
                    attributes['dn'] = entry['dn'].replace(', cn=', ',cn=')
                results.append(attributes)
    finally:
        if connection:
            close_ldap_connection(connection)

    return results


def perform_ldap_add(service_dn, object_class, attributes, use_machine_account=False):
    """
    A wrapper for LDAP modify operation
    """
    connection = None
    try:
        connection = get_ldap_connection(use_machine_account)
        if not Ldap.ldap_add(connection, service_dn, object_class, attributes):
            logger.error("Unable to add LDAP entry dn={}, attributes={}".format(service_dn, str(attributes)))
            raise LdapException(connection.result['result'], connection.result['description'])
    finally:
        if connection:
            close_ldap_connection(connection)


def perform_ldap_modify(service_dn, attribute, value, operation=ldap.MODIFY_REPLACE,
                        use_machine_account=False):
    """
    A wrapper for LDAP modify operation
    """
    connection = None
    try:
        connection = get_ldap_connection(use_machine_account)
        if not Ldap.ldap_modify(connection, service_dn, attribute, operation, value):
            logger.error("Unable to modify LDAP entry dn={}, attribute={}".format(service_dn, attribute))
            raise LdapException(connection.result['result'], connection.result['description'])
    finally:
        if connection:
            close_ldap_connection(connection)


def perform_ldap_delete(service_dn, use_machine_account=False):
    """
    A wrapper for LDAP delete operation
    """
    connection = None
    try:
        connection = get_ldap_connection(use_machine_account)
        if not Ldap.ldap_delete(connection, service_dn):
            logger.error("Unable to delete LDAP entry dn={}".format(service_dn))
            raise LdapException(connection.result['result'], connection.result['description'])
    finally:
        if connection:
            close_ldap_connection(connection)


def get_solution_users():
    """
    Get solution users list from VMDir via LDAP

    :return: list of solution users
    """
    env = Environment.get_environment()
    machine_id = env.get_value('MACHINE_ID')
    domain_dn = env.get_value('SSO_DOMAIN_DN')

    postfix = "-{}".format(machine_id)
    search_base = "cn=ServicePrincipals,{}".format(domain_dn)
    search_filter = "(&(objectClass=vmwServicePrincipal)(cn=*{}))".format(postfix)
    search_attributes = ['cn']
    results = perform_ldap_search(search_base, search_filter, search_attributes)
    return [entry['cn'].replace(postfix, '') for entry in results]


def get_sts_tenant_certificates(include_tenant_credential=True,
                                include_certificate_chain=True):
    """
    Get STS tenant user certificates
    :return: dict(cn: certificate list)
    """
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')

    base_dn = "cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}".format(sso_domain, domain_dn)
    if include_certificate_chain and include_tenant_credential:
        ldap_filter = \
          '(|(objectClass=vmwSTSTenantCredential)(&(objectclass=vmwSTSTenantTrustedCertificateChain)(cn=TrustedCertChain*)))'
    elif include_tenant_credential:
        ldap_filter = '(objectClass=vmwSTSTenantCredential)'
    elif include_certificate_chain:
        ldap_filter = '(&(objectclass=vmwSTSTenantTrustedCertificateChain)(cn=TrustedCertChain*))'
    else:
        return None

    ldap_attributes = ['cn', 'userCertificate']
    results = perform_ldap_search(base_dn, ldap_filter, ldap_attributes)

    tenant_certs = dict()
    for entry in results:
        tenant_certs[entry['cn']] = [build_pem_certificate(cert) for cert in entry['userCertificate']]

    return tenant_certs


def get_solution_user_certificate(solution_user):
    """
    Get solution user certificate from VMDir via LDAP

    :param solution_user: solution user
    :return: Solution user certificate in PEM format
    """
    env = Environment.get_environment()
    machine_id = env.get_value('MACHINE_ID')
    domain_dn = env.get_value('SSO_DOMAIN_DN')

    base_dn = "cn={}-{},cn=ServicePrincipals,{}".format(solution_user, machine_id, domain_dn)
    ldap_filter = '(objectClass=vmwServicePrincipal)'
    ldap_attributes = ['userCertificate']
    results = perform_ldap_search(base_dn, ldap_filter, ldap_attributes, search_scope=ldap.BASE)
    certs = []
    for entry in results:
        for cert in entry['userCertificate']:
            # only expect single certificate
            certs.append(build_pem_certificate(cert))
    return '\n'.join(certs)


def get_all_ca_subject_keyids(use_cache=False):
    """
    Get list of subject keyId of trusted CA certificates via 'dir-cli trustedcert list' output
    The result will be cached

    :param use_cache: If True, the previous cached result will be used (default: True)
    :return: list of subject keyIds of trusted CA certificates
    """
    global cache_ca_keyids
    if use_cache and cache_ca_keyids is not None:
        return cache_ca_keyids

    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    args = [DIR_CLI, 'trustedcert', 'list', '--login', sso_username, '--password', sso_password]
    ret, stdout, _ = CommandRunner(*args).run()
    cache_ca_keyids = TextFilter(stdout).start_with('CN(id):').cut(':', [1]).remove_white_spaces().get_lines()
    return cache_ca_keyids


def get_ca_certificate(subject_keyid, use_cache=True):
    """
    Get CA certificate in VMDir via 'dir-cli trustedcert get' command output

    :param subject_keyid: the certificate' subject keyId
    :param use_cache: if True, the previous cached result will be used instead
    :return: trusted CA certificate in PEM format
    """
    global cache_ca_certificate_map
    if not subject_keyid:
        return None
    if use_cache:
        cert_cache = cache_ca_certificate_map.get(subject_keyid)
        if cert_cache:
            return cert_cache

    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    args = [DIR_CLI, 'trustedcert', 'get', '--login', sso_username, '--password', sso_password,
            '--id', subject_keyid, '--outcert', '/dev/stdout']
    ret, stdout, _ = CommandRunner(*args).run()
    lines = TextFilter(stdout).match_block('-----BEGIN CERTIFICATE-----',
                                           '-----END CERTIFICATE-----').get_lines()
    pem_cert = '\n'.join(lines)
    cache_ca_certificate_map[subject_keyid] = pem_cert
    return pem_cert


def get_all_ca_certificates():
    """
    Get all trusted CA certificates in VMDir via dir-cli command)

    :return: list of CA certificates in PEM format
    """
    subject_keyids = get_all_ca_subject_keyids(False)
    certs = []
    for subject_keyid in subject_keyids:
        pem_cert = get_ca_certificate(subject_keyid)
        certs.append(pem_cert)
    return certs, subject_keyids


def get_service_principals():
    """
    Get service principal list from VMDir via dir-cli

    :return: list of service principals
    """
    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    args = [DIR_CLI, 'service', 'list', '--login', sso_username, '--password', sso_password]
    ret, stdout, _ = CommandRunner(*args).run()
    return TextFilter(stdout).cut(fields=[1]).get_lines()


def init_env_identity_source():
    env = Environment.get_environment()
    if env.get_map().get('SSO_USERNAME') is None or \
            env.get_value('EXTERNAL_IDENTITY_SOURCE_CONFIGURED') is not None:
        return

    logger.info('Checking identity source settings')
    identity_sources = get_identity_sources()
    source_types = [item['type'] for item in identity_sources]
    logger.info("Identity sources: {}".format(source_types))

    env.set_value('EXTERNAL_IDENTITY_SOURCE_CONFIGURED', len(source_types) > 0)


def get_identity_sources(use_machine_account=False):
    """
    Get the identity sources settings

    return: list of configured identity source represented in the following dict object:
    {
        "type": one of ('AD over LDAP', 'ADFS', 'OpenLDAP')
        "domain_name": domain name
        "certificates": CA certificate for this identity source
    }
    """
    logger.info('Obtaining identity source settings')
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    search_list = [
        ('AD over LDAP', 'IdentityProviders', 'IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING'),
        ('ADFS', 'VCIdentityProviders', 'IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING'),
        ('OpenLDAP', 'IdentityProviders', 'IDENTITY_STORE_TYPE_LDAP')
    ]

    identity_sources = []
    connection = None
    try:
        connection = get_ldap_connection(use_machine_account=use_machine_account)
        ldap_attributes = ['vmwSTSDomainName', 'userCertificate']
        for type_name, provider_cn, provider_type in search_list:
            base_dn = "cn={},cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}"\
                .format(provider_cn, sso_domain, domain_dn)
            ldap_filter = "(vmwSTSProviderType={})".format(provider_type)
            if not Ldap.ldap_search(connection, base_dn, ldap_filter, ldap.SUBTREE, ldap_attributes):
                # this search may return noSuchObject due to an invalid base_dn
                if connection.result['result'] == 32:
                    continue
                logger.error('Unable to perform LDAP search for the identity source setting')
                raise LdapException(connection.result['result'], connection.result['description'])
            if not connection.result:
                continue
            for entry in connection.response:
                attributes = entry['attributes']
                result = dict()
                result['type'] = type_name
                result['domain_name'] = attributes['vmwSTSDomainName']
                certs = []
                for cert in attributes['userCertificate']:
                    # only expect single certificate
                    certs.append(build_pem_certificate(cert))
                result['certificates'] = certs
                identity_sources.append(result)
                logger.info("Identity source: type={}, domain={}".format(type_name, result['domain_name']))
    finally:
        if connection:
            close_ldap_connection(connection)

    return identity_sources


def get_sso_domain_nodes():
    logger.info('Obtaining SSO domain nodes')
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    base_dn_list = ["ou=Domain Controllers,{}".format(domain_dn), "ou=Computers,{}".format(domain_dn)]
    ldap_filter = '(objectClass=computer)'
    ldap_attributes = ['cn']
    nodes = []
    for base_dn in base_dn_list:
        results = perform_ldap_search(base_dn, ldap_filter, ldap_attributes)
        for entry in results:
            node = entry['cn']
            if node not in nodes:
                nodes.append(node)
                logger.info("Found node: {}".format(node))

    return nodes


def get_all_lookup_service_endpoints(search_base=None):
    """
    Get all endpoint entries
    :return:
    """
    logger.info('Obtaining all endpoints')
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    if search_base is None:
        search_base = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    search_filter = '(|(objectclass=vmwLKUPServiceEndpoint)(objectClass=vmwLKUPEndpointRegistration))'
    search_attributes = ['dn', 'objectClass', 'vmwLKUPURI', 'vmwLKUPEndpointSslTrust', 'vmwLKUPSslTrustAnchor']
    return perform_ldap_search(search_base, search_filter, search_attributes)


def get_node_trust_anchors(fqdn_or_ip):
    """
    Get SSL trust anchors by filtering the endpoint URI using {fqdn_or_ip}
    :param fqdn_or_ip:
    :return:
    """
    logger.info("Obtaining node trust anchors: fqdn_or_ip: {}".format(fqdn_or_ip))
    trust_anchors = []
    pattern = "^https://{0}:.*|^https://{0}/.*".format(fqdn_or_ip)
    endpoints = get_all_lookup_service_endpoints()
    for endpoint in endpoints:
        if not re.match(pattern, endpoint['vmwLKUPURI']):
            continue
        for cert in sum([endpoint['vmwLKUPEndpointSslTrust'], endpoint['vmwLKUPSslTrustAnchor']], []):
            pem_cert = certutil.build_pem_certificate(cert)
            if pem_cert and pem_cert not in trust_anchors:
                trust_anchors.append(pem_cert)
    logger.info('Trust anchors found for {}: {}'.format(fqdn_or_ip, trust_anchors))
    return trust_anchors


def get_endpoint_service_type(service_id):
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    search_base = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    search_filter = "(cn={})".format(service_id)
    search_attributes = ['vmwLKUPType']
    result = perform_ldap_search(search_base, search_filter, search_attributes)
    if result:
        return result[0]['vmwLKUPType']

    search_filter = '(objectClass=vmwLKUPService)'
    search_attributes = ['dn', 'vmwLKUPServiceType']
    result = perform_ldap_search(search_base, search_filter, search_attributes)
    for entry in result:
        if service_id in entry['dn']:
            # remove prefix 'urn:'
            return entry['vmwLKUPServiceType'][4:]
    return ''


def get_registered_vcenters():
    """
    Get registered VCenters
    :return: list of tuple (deployment_node_id, node_dn)
    """
    logger.info('Obtaining list of registered vCenters')
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    base_dn = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    ldap_filter = '(vmwLKUPType=vcenterserver)'
    ldap_attributes = ['vmwLKUPDeploymentNodeId', 'dn']
    results = perform_ldap_search(base_dn, ldap_filter, ldap_attributes)
    return [(entry['vmwLKUPDeploymentNodeId'], entry['dn']) for entry in results]


def get_endpoint_registrations(base_dn):
    ldap_filter = '(objectClass=vmwLKUPEndpointRegistration)'
    ldap_attributes = ['vmwLKUPURI']
    results = perform_ldap_search(base_dn, ldap_filter, ldap_attributes)
    return [entry['vmwLKUPURI'] for entry in results]


def init_env_cac():
    env = Environment.get_environment()
    # if env.get_map().get('SSO_USERNAME') is None or \
    #        env.get_value('CAC_CONFIGURED') is not None:
    #    return
    if env.get_value('CAC_CONFIGURED') is not None:
        return

    vc_version = get_vc_version()
    if vc_version >= VcVersion.V9:
        logger.info('SmartCards are not supported since version {}'.format(VcVersion.V9.value))
        env.set_value('CAC_CONFIGURED', False)
        return

    logger.info('Checking SmartCard Authentication settings')
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    search_base = "cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}".format(sso_domain, domain_dn)
    search_filter = '(objectclass=vmwSTSTenant)'
    search_attributes = ['vmwSTSAuthnTypes']
    results = perform_ldap_search(search_base, search_filter, search_attributes, use_machine_account=True)
    is_cac_configured = False
    logger.info('LDAP search results: {}'.format(results))
    for entry in results:
        if entry['vmwSTSAuthnTypes'] == 4 or 4 in entry['vmwSTSAuthnTypes']:
            is_cac_configured = True
    env.set_value('CAC_CONFIGURED', is_cac_configured)


def get_smart_card_issuing_ca_certs():
    logger.info('Obtaining SmartCard issuing CA certificates')
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    search_base = \
        "cn=DefaultClientCertCAStore,cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,"\
        "cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}".format(sso_domain, domain_dn)
    search_filter = '(objectClass=vmwSTSTenantTrustedCertificateChain)'
    search_attributes = ['userCertificate']

    result = perform_ldap_search(search_base, search_filter, search_attributes, use_machine_account=True)
    certs = []
    for entry in result:
        certs.extend(build_pem_certificate(cert) for cert in entry['userCertificate'])

    return certs


def get_all_sso_sites():
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    search_base = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    search_filter = '(objectClass=*)'
    search_attributes = ['cn']
    result = perform_ldap_search(search_base, search_filter, search_attributes, search_scope=ldap.LEVEL)
    return [entry['cn'] for entry in result]


def unpublish_trusted_certificate(cert_file):
    """
    Unpublish certificate in VMDir
    :param cert_file: Certificate file to unpublish
    """
    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    CommandRunner(DIR_CLI, 'trustedcert', 'unpublish', '--login', sso_username, '--password',
                  sso_password, '--cert', cert_file, expected_return_code=0).run()


def publish_trusted_certificate(cert_file, is_chain=False):
    """
    Publish certificate in VMDir
    :param cert_file: Certificate file to unpublish
    :param is_chain: Publish all certificate in chain
    """
    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    args = [DIR_CLI, 'trustedcert', 'publish', '--login', sso_username, '--password', sso_password,
            '--cert', cert_file]
    if is_chain:
        args.append('--chain')
    CommandRunner(*args, expected_return_code=0).run()


def remove_ca_certificate_from_ldap(subject_keyid):
    domain_dn = Environment.get_environment().get_value('SSO_DOMAIN_DN')
    cert_dn = "cn={},cn=Certificate-Authorities,cn=Configuration,{}".format(subject_keyid, domain_dn)
    perform_ldap_delete(cert_dn)


def get_sddc_manager():
    # SDDC_MANAGER=$($LDAP_SEARCH -LLL -h $PSC_LOCATION -b
    # "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN"
    # -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password '(objectclass=vmwSTSTenant)'
    # vmwSTSLogonBanner | tr -d '\n' | awk -F'::' '{print $NF}' | tr -d ' ' | base64 -d 2>/dev/null | grep 'SDDC Manager' | awk -F '[()]' '{print $2}' | grep -v '^$')
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    search_base = "cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}".format(sso_domain, domain_dn)
    search_filter = '(objectClass=vmwSTSTenant)'
    search_attributes = ['vmwSTSLogonBanner']
    result = perform_ldap_search(search_base, search_filter, search_attributes, search_scope=ldap.LEVEL)
    return [entry['cn'] for entry in result]


def update_solution_user_certificate_in_vmdir(soluser, cert_file):
    env = Environment.get_environment()
    sso_username = env.get_value('SSO_USERNAME')
    sso_password = env.get_value('SSO_PASSWORD')
    machine_id = env.get_value('MACHINE_ID')
    args = [DIR_CLI, 'service', 'update', '--name', f"{soluser}-{machine_id}", '--cert',
            cert_file,  '--login', sso_username, '--password', sso_password]
    try:
        CommandRunner(*args, expected_return_code=0).run_and_get_output()
    except CommandExecutionError:
        error_message = f"Unable to update {soluser}-{machine_id} solution user certificate in VMDir"
        logger.error(error_message)
        raise OperationFailed(error_message)


# ------------------------------
# Replace a Solution User certificate in VMDir
# ------------------------------
def replace_service_principal_certificates(soluser, cert_file):
    print_task(f"   {soluser}")
    update_solution_user_certificate_in_vmdir(soluser, cert_file)
    print_task_status("OK")


def verify_service_principals():
    print_task('Verifying Service Principal entries exist')
    service_principals = get_service_principals()
    if service_principals:
        env = Environment.get_environment()
        machine_id = env.get_value('MACHINE_ID')
        solution_users = env.get_value('SOLUTION_USERS')
        missing_service_principals = []
        for solution_user in solution_users:
            service_principal = "{}-{}".format(solution_user, machine_id)
            if service_principal not in service_principals:
                missing_service_principals.append(service_principal)

        if missing_service_principals:
            print_text_error('ERROR')
            print_text_error("\n------------------------!!! Attention !!!------------------------ ")
            print_text_error('The following Service Principal entries are missing:')
            for sp in missing_service_principals:
                print_text_error(" - {}".format(sp))

            print_text_error('\nPlease refer to the following Knowledge Base article')
            print_text_error('on using the lsdoctor utility to recreate the missing')
            print_text_error('Solution User/Service Principal entries:')
            print_text_error('https://knowledge.broadcom.com/external/article/320837/using-the-lsdoctor-tool.html')
        else:
            print_task_status("OK")
    else:
        print_text_error('Could not get list of Service Principal entries from VMware Directory')


def get_vmdir_state():
    state_output = CommandRunner(VDCADMINTOOL, command_input='6', expected_return_code=0).run_and_get_output()
    logger.info('VMware Directory state: {}'.format(state_output))
    service_state = TextFilter(state_output).contain('VmDir State').cut('-', [1]).get_text().strip()
    return service_state
