# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import datetime
import glob
import ldap3 as ldap
import logging
import OpenSSL
import os
import pathlib
import re
import stat

from lib import vcdb
from lib import vecs
from lib import vmdir

from lib.exceptions import OperationFailed, CommandExecutionError, MenuExitException
from lib.certificate_utils import (
    generate_vmca_signed_certificate, detect_and_convert_to_pem, get_key_modulus_from_pem_text,
    get_x509_certificate, get_certificate_fingerprint, build_certification_path,
    get_certificate_fetcher_from_list, get_subject_and_issuer_dn, split_certificates_from_pem,
    get_certificate_expiry_in_days, is_x509_expired, get_subject_alternative_names, get_subject_keyid,
    generate_csr, is_ca_certificate, get_serial_number, load_pem_certificate_file_in_der,
    load_pem_key_file_in_pkcs8_der, get_certificate_start_date, get_certificate_end_date,
    get_certificate_from_host, is_self_signed_certificate, get_subject_hash, CERTOOL_CLI, OPENSSL_CLI
)
from lib.command_runner import CommandRunner
from lib.console import (
    print_header, print_text_error, print_task, print_task_status, print_task_status_warning,
    print_task_status_error, print_text, print_text_warning, ColorKey, set_text_color
)
from lib.constants import (TOP_DIR, AUTH_PROXY_CERT_FILE_PATH, RBD_CERT_FILE_PATH, VMCA_CERT_FILE_PATH, READ, WRITE
)
from lib.environment import Environment
from lib.host_utils import (
    is_valid_ip_address, is_file_exists, get_file_contents, save_text_to_file, append_text_to_file,
    find_files, set_file_mode, make_directory, get_vc_version, VcVersion
)
from lib.ldap_utils import LdapException
from lib.menu import Menu, MenuInput
from lib.services import is_service_running, start_vmware_services, stop_vmware_services
from lib.text_utils import TextFilter
from operation.check_certificate import (
    check_signature_algorithm, get_vcenter_extensions, get_vcenter_extension_expected_thumbprints,
    check_rogue_ca, check_vcenter_extension_thumbprints
)
from operation.generate_report import get_ssl_trust_anchors, get_service_ids_and_uri_by_certificate
from operation.restart_service import restart_vmware_services
from operation.view_certificate import (
    print_certification_path, get_certificate_info_brief, view_ca_certificates_in_vmdir, view_ca_certificates_in_vecs,
    view_sms_certificates_in_vecs, view_ldaps_identity_source_certificates, view_smart_card_certificates
)

VMON_CLI = '/usr/sbin/vmon-cli'
logger = logging.getLogger(__name__)
cert_usage_map = {
    'machine-ssl': 'Machine SSL',
    'soluser': 'Solution User',
    'sso-sts': 'STS Signing',
    'vmca': 'VMCA',
    'auth-proxy': 'Authentication Proxy',
    'rbd': 'Auto Deploy CA',
    'vmdir': 'VMware Directory',
    'ESXi': 'ESXi'
}


def set_default_csr_input():
    env = Environment.get_environment()
    env.set_value('VMCA_CN_DEFAULT', 'CA')
    env.set_value('CSR_COUNTRY_DEFAULT', 'US')
    env.set_value('CSR_ORG_DEFAULT', 'VMware')
    env.set_value('CSR_ORG_UNIT_DEFAULT', 'VMware Engineering')
    env.set_value('CSR_STATE_DEFAULT', 'California')
    env.set_value('CSR_LOCALITY_DEFAULT', 'Palo Alto')
    env.set_value('CSR_ADDITIONAL_DNS', [])


def get_csr_info(cert_usage=None):
    env = Environment.get_environment()
    if env.get_value('CSR_COUNTRY'):
        return {
            'country': env.get_value('CSR_COUNTRY'),
            'org': env.get_value('CSR_ORG'),
            'org_unit': env.get_value('CSR_ORG_UNIT'),
            'state': env.get_value('CSR_STATE'),
            'locality': env.get_value('CSR_LOCALITY'),
            'ip': env.get_value('CSR_IP'),
            'email': env.get_value('CSR_EMAIL'),
            'dns': env.get_value('CSR_ADDITIONAL_DNS')
        }

    if cert_usage is None:
        print_header('Certificate Signing Request Information')
    else:
        print_header("Certificate Signing Request Information [{}]".format(get_cert_usage_value(cert_usage)))

    set_default_csr_input()
    country_default = env.get_value('CSR_COUNTRY_DEFAULT')
    country = MenuInput('Enter the country code [{CSR_COUNTRY_DEFAULT}]: ',
                        default_input=country_default).get_input()
    while not re.match('^[A-Z][A-Z]$', country):
        print_text_error('Please enter the two-character country code')
        country = MenuInput('Enter the country code [{CSR_COUNTRY_DEFAULT}]: ',
                            default_input=country_default, case_insensitive=False).get_input()
    env.set_value('CSR_COUNTRY', country)

    org_default = env.get_value('CSR_ORG_DEFAULT')
    org = MenuInput('Enter the Organization name [{CSR_ORG_DEFAULT}]: ',
                    default_input=org_default, case_insensitive=False).get_input()
    env.set_value('CSR_ORG', org)

    org_unit_default = env.get_value('CSR_ORG_UNIT_DEFAULT')
    org_unit = MenuInput('Enter the Organizational Unit name [{CSR_ORG_UNIT_DEFAULT}]: ',
                         default_input=org_unit_default, case_insensitive=False).get_input()
    env.set_value('CSR_ORG_UNIT', org_unit)

    state_default = env.get_value('CSR_STATE_DEFAULT')
    state = MenuInput('Enter the state [{CSR_STATE_DEFAULT}]: ',
                      default_input=state_default, case_insensitive=False).get_input()
    env.set_value('CSR_STATE', state)

    locality_default = env.get_value('CSR_LOCALITY_DEFAULT')
    locality = MenuInput('Enter the locality (city) name [{CSR_LOCALITY_DEFAULT}]: ',
                         default_input=locality_default, case_insensitive=False).get_input()

    env.set_value('CSR_LOCALITY', locality)

    ip_address = MenuInput('Enter the IP address (optional): ', allow_empty_input=True).get_input()
    while ip_address and not is_valid_ip_address(ip_address):
        print_text_error('Invalid IP address, enter valid IP address: ', end='')
        ip_address = MenuInput('').get_input()
    if ip_address:
        env.set_value('CSR_IP', ip_address)

    email = MenuInput('Enter an email address (optional): ', case_insensitive=False,
                      allow_empty_input=True).get_input()
    if email:
        env.set_value('CSR_EMAIL', email)

    dns_input = MenuInput('Enter any additional hostnames for SAN entries (comma separated value): ',
                          case_insensitive=False, allow_empty_input=True).get_input().strip()
    if dns_input:
        dns_entries = dns_input.replace(' ', '').split(',')
        env.set_value('CSR_ADDITIONAL_DNS', dns_entries)
    else:
        dns_entries = []

    return {
        'country': country,
        'org': org,
        'org_unit': org_unit,
        'state': state,
        'locality': locality,
        'ip': ip_address,
        'email': email,
        'dns': dns_entries
    }


def clear_csr_info():
    env = Environment.get_environment()
    env.set_value('CSR_COUNTRY', None)
    env.set_value('CSR_ORG', None)
    env.set_value('CSR_ORG_UNIT', None)
    env.set_value('CSR_STATE', None)
    env.set_value('CSR_LOCALITY', None)
    env.set_value('CSR_IP', None)
    env.set_value('CSR_EMAIL', None)
    env.set_value('CSR_ADDITIONAL_DNS', [])


def replace_machine_ssl_certificate(cert_file, key_file):
    """
    Entry point for managing Machine SSL certificate
    """
    cert_usage = 'machine-ssl'
    backup_vecs_cert_key(cert_usage)

    update_vecs(cert_usage, cert_file, key_file)
    if 'STS_INTERNAL_SSL_CERT' in vecs.get_store_list():
        update_vecs('legacy-lookup-service', cert_file, key_file)
    return cert_file


def check_vpostgres_service():
    if not is_service_running('vmware-vpostgres'):
        print_text_error("The vPostgres service is stopped!\n"
                         "Please ensure this service is running before replacing the Machine SSL certificate.\n"
                         "Hint: Check the number of CRL entries in VECS")
        raise OperationFailed('vmware-vpostgres is not running')


def replace_machine_ssl_certificate_with_vmca_signed():
    """
    Entry point for replacing machine SSL certificate using VMCA signed certificate
    """
    env = Environment.get_environment()
    output_dir = env.get_value('TEMP_DIR')
    pnid = env.get_value('PNID')

    csr_info = get_csr_info()
    print_header('Replace Machine SSL Certificate')
    generate_certool_config(output_dir, 'machine-ssl', csr_info, pnid)

    print_task('Regenerate Machine SSL certificate')
    config = "{}/machine-ssl.cfg".format(output_dir)
    generate_vmca_signed_certificate(config, output_dir, 'machine-ssl')
    print_task_status('OK')

    cert_file = "{}/machine-ssl.crt".format(output_dir)
    key_file = "{}/machine-ssl.key".format(output_dir)

    replace_machine_ssl_certificate(cert_file, key_file)
    return cert_file


def manage_machine_ssl_certificate_with_vmca_signed():
    cert_file = replace_machine_ssl_certificate_with_vmca_signed()
    # update the rest settings
    update_ssl_trust_anchors(cert_file)
    update_vc_ext_thumbprints()
    update_auto_deploy_db()

    # restart services
    restart_vmware_services()
    clear_csr_info()


def get_default_certificate_cn(cert_usage):
    env = Environment.get_environment()
    if cert_usage == 'sso-sts':
        return 'ssoserverSign'
    else:
        hostname = env.get_value('HOSTNAME')
        return hostname


def generate_csr_and_private_key(cert_usage, custom_openssl_config=False, is_CA=False):
    """
    Entry point for CSR generation
    :param cert_usage: Certificate usage
    :param custom_openssl_config: True if a custom OpenSSL config is used
    :param is_CA: True if CSR and key is for a Certificate Authority
    """
    env = Environment.get_environment()
    request_dir = env.get_value('REQUEST_DIR')
    timestamp = get_timestamp()
    csr_file = "{}/{}-{}.csr".format(request_dir, cert_usage, timestamp)
    key_file = "{}/{}-{}.key".format(request_dir, cert_usage, timestamp)
    if custom_openssl_config:
        logger.info('User has chosen to generate the Machine SSL private key and CSR from a custom OpenSSL '
                    'configuration file')
        user_input = MenuInput('Enter path to custom OpenSSL configuration file: ', allow_empty_input=False,
                               case_insensitive=False)
        print()
        while True:
            config_file = user_input.get_input()
            if not is_file_exists(config_file):
                print_text_error('Error: file not found')
                continue
            break
    else:
        logger.info('User has chosen to generate the Machine SSL private key and CSR')
        hostname = env.get_value('HOSTNAME')
        config_file = "{}/{}-{}.cfg".format(request_dir, cert_usage, timestamp)

        csr_info = get_csr_info(cert_usage)
        default_cert_cn = get_default_certificate_cn(cert_usage)
        user_input = MenuInput("Enter a value for the {}CommonName{} of the certificate [{}]: "
                               .format(ColorKey.CYAN, ColorKey.NORMAL, default_cert_cn),
                               default_input=default_cert_cn, case_insensitive=False)
        cert_cn = user_input.get_input()
        san_entries = get_san_entries(cert_usage, csr_info, hostname)
        generate_openssl_config(config_file, csr_info, cert_cn, san_entries, is_CA)

    try:
        generate_csr(config_file, csr_file, key_file)
        # OpenSSL 1.0 on VC 7.x doesn't set the file permission correctly
        set_file_mode(key_file, stat.S_IRUSR | stat.S_IWUSR)
    except CommandExecutionError as e:
        error_message = "Unable to generate Certificate Signing Request and Private Key: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)

    print()
    print_text("Certificate Signing Request generated at {}{}{}".format(ColorKey.CYAN, csr_file, ColorKey.NORMAL))
    print_text("Private Key generated at {}{}{}".format(ColorKey.CYAN, key_file, ColorKey.NORMAL))


def get_san_entries(cert_usage, csr_info, hostname):
    hostname_short = hostname.split('.')[0]
    acceptable_inputs = ['Y', 'N']
    user_input = MenuInput("Include host short name {}{}{} as a Subject Alternative Name entry? [n]: "
                           .format('{COLORS[CYAN]}', hostname_short, '{COLORS[NORMAL]}'),
                           acceptable_inputs=acceptable_inputs, default_input='N')
    san_entries = [hostname]
    for entry in csr_info['dns']:
        if entry.lower() != hostname.lower():
            san_entries.append(entry)
    if (cert_usage != 'ESXi' or not re.match('^[0-9].*', hostname_short))\
            and user_input.get_input() == 'Y':
        san_entries.append(hostname_short)
    env = Environment.get_environment()
    pnid = env.get_value('PNID')
    if cert_usage != 'ESXi' and hostname.lower() != pnid.lower() and pnid not in san_entries:
        san_entries.append(pnid)

    print_text("The following items will be added as Subject Alternative Name entries on the {} "
               "Certificate Signing Request:".format(get_cert_usage_value(cert_usage)))
    print_text('{COLORS[CYAN]}')
    for entry in san_entries:
        print(entry)
    if csr_info['ip']:
        print(csr_info['ip'])
    if csr_info['email']:
        print(csr_info['email'])
    print_text('{COLORS[NORMAL]}')

    additional_san_entries =\
        MenuInput('If you want any additional items added as Subject Alternative Name entries, enter them '
                  'as a comma-separated list (optional): ', allow_empty_input=True,
                  case_insensitive=False).get_input().strip()
    if additional_san_entries:
        san_entries.extend(additional_san_entries.replace(' ', '').split(','))
    return san_entries


def get_cert_usage_value(cert_usage):
    if cert_usage not in cert_usage_map.keys():
        cert_usage_value = cert_usage
    else:
        cert_usage_value = cert_usage_map[cert_usage]
    return cert_usage_value


def generate_openssl_config(cfg_file, csr_info, cert_cn, san_entries, is_CA=False):
    """
    Generate OpenSSL config for CSR generation
    """
    config = [
        '[req]',
        'prompt = no',
        'default_bits = 3096',
        'distinguished_name = req_distinguished_name',
        'req_extensions = v3_req',
        '',
        '[ req_distinguished_name ]',
        "C = {}".format(csr_info['country']),
        "ST = {}".format(csr_info['state']),
        "L = {}".format(csr_info['locality']),
        "O = {}".format(csr_info['org']),
        "OU = {}".format(csr_info['org_unit']),
        "CN = {}".format(cert_cn),
        '',
        '[ v3_req ]'
    ]
    if san_entries is None:
        san_entries = csr_info['dns']
    final_entries = []
    for entry in san_entries:
        if is_valid_ip_address(entry):
            final_entries.append("IP:{}".format(entry))
        else:
            final_entries.append("DNS:{}".format(entry))
    if csr_info['ip']:
        final_entries.append("IP:{}".format(csr_info['ip']))
    if csr_info['email']:
        final_entries.append("email:{}".format(csr_info['email']))
    config.append("subjectAltName = {}".format(', '.join(final_entries)))
    if is_CA:
        config.append('basicConstraints = critical, CA:TRUE')
    save_text_to_file('\n'.join(config), cfg_file)


def import_custom_ca_signed_machine_ssl_certificate():
    """
    Entry point for importing custom CA signed certificate
    """
    logger.info('User has chosen to import a CA-signed Machine SSL certificate and key')
    check_vpostgres_service()
    cert_pem_file, key_pem_file, ca_pem_file, cert_pem, ca_pem = get_custom_ca_signed_certificate_files('machine-ssl')
    publish_ca_signing_certificate(ca_pem_file)
    replace_machine_ssl_certificate(cert_pem_file, key_pem_file)

    # update the rest settings
    update_ssl_trust_anchors(cert_pem_file)
    update_vc_ext_thumbprints()
    update_auto_deploy_db()

    # restart services
    restart_vmware_services()


def manage_solution_user_certificate_with_custom_ca_signed():
    import_custom_ca_signed_certificate_of_soluser()
    update_vc_ext_thumbprints()
    # restart services
    restart_vmware_services()
    clear_csr_info()


def import_custom_ca_signed_certificate_of_soluser():
    """
    Entry point for importing custom CA signed certificate for solution user
    """
    env = Environment.get_environment()
    solution_users = env.get_value('SOLUTION_USERS')
    logger.info('User has chosen to import a CA-signed Solution User certificates and keys')
    soluser_cert_key = {}
    for soluser in solution_users:
        cert_pem_file, key_pem_file, ca_pem_file, cert_pem, ca_pem = get_custom_ca_signed_certificate_files(soluser, True)
        soluser_cert_key[soluser] = {}
        soluser_cert_key[soluser]["cert_pem"] = cert_pem_file
        soluser_cert_key[soluser]["key_pem"] = key_pem_file
        soluser_cert_key[soluser]["ca_pem"] = ca_pem_file
        soluser_cert_key[soluser]["cert_pem_content"] = cert_pem
        soluser_cert_key[soluser]["ca_pem_content"] = ca_pem
        print('')
    print_header('Replace Solution User Certificates')
    vmdir.verify_service_principals()
    print('Verify certificates and keys:')
    for soluser in solution_users:
        print_task("   {}".format(get_cert_usage_value(soluser)))
        cert_pem_file = soluser_cert_key[soluser]["cert_pem"]
        key_pem_file = soluser_cert_key[soluser]["key_pem"]
        ca_pem_file = soluser_cert_key[soluser]["ca_pem"]
        cert_pem = soluser_cert_key[soluser]["cert_pem_content"]
        ca_pem = soluser_cert_key[soluser]["ca_pem_content"]
        verify_certificate_and_key(cert_pem_file, key_pem_file, ca_pem_file, soluser, True)
    verify_certification_path(cert_pem, ca_pem)
    print_task('Publish CA signing certificates')
    for soluser in solution_users:
        publish_ca_signing_certificate(soluser_cert_key[soluser]["ca_pem"], True)
    print_task_status('OK')


    print('\nBackup certificate and private key:')
    for soluser in solution_users:
        backup_vecs_cert_key(soluser)

    print('\nUpdating certificates and keys in VECS:')
    for soluser in solution_users:
        cert_file = soluser_cert_key[soluser]["cert_pem"]
        key_file = soluser_cert_key[soluser]["key_pem"]
        update_vecs(soluser, cert_file, key_file)

    if is_file_exists('/storage/vsan-health/vpxd-extension.cert') and is_file_exists('/storage/vsan-health/vpxd-extension.key'):
        print('\nUpdating vpxd-extension certificate for vSAN Health')
        try:
            CommandRunner('cp', soluser_cert_key['vpxd-extension']['cert_pem'], '/storage/vsan-health/vpxd-extension.cert').run()
            CommandRunner('cp', soluser_cert_key['vpxd-extension']['cert_key'], '/storage/vsan-health/vpxd-extension.key').run()
        except CommandExecutionError as e:
            error_message = "Unable to update vpxd-extension cert and key for vSAN Health: {}".format(str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)

    print('\nUpdating solution user certificates in VMware Directory:')
    for soluser in solution_users:
        cert_file = soluser_cert_key[soluser]["cert_pem"]
        vmdir.replace_service_principal_certificates(soluser, cert_file)


def get_custom_ca_signed_certificate_files(cert_usage, is_sol_user=False):
    """
    this method obtains a CA-signed certificate from user input, converts it to PEM certificates as necessary, and validates the certificate.
    """
    cert_usage_text = get_cert_usage_value(cert_usage)
    menu_input = MenuInput("Provide path to the CA-signed {}{}{} certificate: "
                           .format(ColorKey.CYAN, cert_usage_text, ColorKey.NORMAL),
                           allow_empty_input=False, case_insensitive=False)
    cert_file = ''
    while not cert_file:
        cert_file = menu_input.get_input()
        if not is_file_exists(cert_file):
            print_text_error("Error: file not found: {}\n".format(cert_file))
            cert_file = ''

    env = Environment.get_environment()
    output_dir = env.get_value('TEMP_DIR')
    cert_pem_file = "{}/{}-ca-signed.crt".format(output_dir, cert_usage)
    key_pem_file = "{}/{}-ca-signed.key".format(output_dir, cert_usage)
    ca_pem_file = "{}/{}-ca-chain.pem".format(output_dir, cert_usage)
    cert_pem, key_pem = detect_and_convert_to_pem(cert_file, allow_input=True)
    save_text_to_file(cert_pem, cert_pem_file)

    logger.info("Provided new {} certificate: {}".format(cert_usage_text, cert_file))
    logger.info(cert_pem)
    logger.info("New {} certificate details: ".format(cert_usage_text))
    logger.info(get_certificate_info_brief(cert_pem))

    cert_x509 = get_x509_certificate(cert_pem)
    if not check_signature_algorithm(cert_x509):
        error_message = 'Certificate is using an unsupported signature algorithm'
        print_text_error("Error: {}".format(error_message))
        raise OperationFailed(error_message)
    if is_x509_expired(cert_x509):
        error_message = 'Certificate is expired'
        print_text_error("Error: {}".format(error_message))
        raise OperationFailed(error_message)

    if not key_pem:
        cert_modulus = get_key_modulus_from_pem_text(cert_pem)
        key_pem = find_matched_private_key(cert_modulus, cert_file)
    if not key_pem:
        raise OperationFailed('Failed to obtain key file')
    save_text_to_file(key_pem, key_pem_file)
    set_file_mode(key_pem_file, stat.S_IRUSR | stat.S_IWUSR)

    # validate certificate chaining
    ca_pem, ca_certs_pem, cert_pem_updated = obtain_ca_chain(cert_pem)
    if cert_pem_updated is not None:
        cert_pem = cert_pem_updated
        save_text_to_file(cert_pem, cert_pem_file)
    save_text_to_file(ca_certs_pem, ca_pem_file)

    if not is_sol_user:
        print_header('Certificate Verification')
        if cert_usage != 'vmca':
            verify_certificate_and_key(cert_pem_file, key_pem_file, ca_pem_file, cert_usage)
            verify_certification_path(cert_pem, ca_pem)
        else:
            verify_certificate_and_key(cert_pem_file, key_pem_file, ca_pem_file, cert_usage)
            print_task('Verifying CA certificate')
            if not is_ca_certificate(cert_x509):
                not_ca_cert_error_message = 'The provided certificate {} is not a CA certificate.'.format(cert_pem_file)
                logger.error(not_ca_cert_error_message)
                print_task_status_error('NOT CA')
                raise OperationFailed(not_ca_cert_error_message)
            complete_ca_pem = cert_pem_updated + '\n' + ca_pem
            cert_pem_file = "{}/{}-complete-chain.pem".format(output_dir, cert_usage)
            save_text_to_file(complete_ca_pem, cert_pem_file)
            print_task_status('OK')
    if cert_usage == 'machine-ssl':
        verify_pnid_in_san(cert_pem)
    return cert_pem_file, key_pem_file, ca_pem_file, cert_pem, ca_pem


def verify_certificate_and_key(cert_pem_file, key_pem_file, ca_pem_file,
                               cert_usage, is_sol_user=False):
    """
    Verify that certificate and key match
    """
    if not is_sol_user:
        print_task('Verifying certificate and key')

    logger.info("Using {} cert: {}".format(get_cert_usage_value(cert_usage),cert_pem_file))
    logger.info("Using Private Key: {}".format(key_pem_file))
    logger.info("Using trusted root chain: {}".format(ca_pem_file))
    cert_pem = get_file_contents(cert_pem_file)
    key_pem = get_file_contents(key_pem_file)
    cert_modulus = get_key_modulus_from_pem_text(cert_pem)
    key_modulus = get_key_modulus_from_pem_text(key_pem)
    logger.info("Modulus of {}: {}".format(cert_pem_file, cert_modulus))
    logger.info("Modulus of {}: {}".format(key_pem_file, key_modulus))
    if cert_modulus != key_modulus:
        print_task_status_warning('ERROR')
        error_message = "The private key {} does not correspond to the certificate {}"\
            .format(key_pem_file, cert_pem_file)
        logger.error(error_message)
        raise OperationFailed(error_message)
    print_task_status('OK')


def obtain_ca_chain(cert_pem):
    """
    Get the root CA certificate, get from user if necessary. If the cert_pem includes root CA,
    then move this certificates to root_ca
    """
    ca_subject_keyids = vmdir.get_all_ca_subject_keyids()
    ca_chain = ''
    while True:
        updated_pem = "{}\n{}".format(cert_pem, ca_chain)
        _, fetcher = get_certificate_fetcher_from_list(split_certificates_from_pem(updated_pem))
        cert_path = build_certification_path(updated_pem, ca_subject_keyids, vmdir.get_ca_certificate)
        if cert_path[0]['is_selfsigned']:
            break

        print_text_error('Failed to build the certification path')
        print_certification_path(cert_path)

        subject_keyid = cert_path[0]['subject_keyid']
        cert = fetcher(subject_keyid)
        if not cert:
            cert = vmdir.get_ca_certificate(subject_keyid)
        cert_x509 = get_x509_certificate(cert)
        _, issuer_dn = get_subject_and_issuer_dn(cert_x509)
        print_text('Please ensure that the following certificate (and its issuers, if any) are '
                   'included in the signing CA chain:')
        print_text("   Subject: {}".format(issuer_dn))
        print_text('\n')
        while True:
            root_ca_file = MenuInput('Provide path to the Certificate Authority chain: ',
                                     allow_empty_input=False, case_insensitive=False).get_input()
            if not is_file_exists(root_ca_file):
                print_text_error('Error: file not found')
                continue
            ca_chain, _ = detect_and_convert_to_pem(input_cert=root_ca_file, allow_input=False)
            break

    ca_chain_certs = []
    for cert_info in reversed(cert_path):
        cert = fetcher(cert_info['subject_keyid'])
        if not cert:
            cert = vmdir.get_ca_certificate(cert_info['subject_keyid'])
        ca_chain_certs.append(cert)

    certs_pem = ca_chain_certs[:-1]
    ca_root = ca_chain_certs[-1]
    ca_certs = ca_chain_certs[1:] if len(ca_chain_certs) > 1 else [ca_root]
    return ca_root, '\n'.join(ca_certs), '\n'.join(certs_pem)


def verify_certification_path(cert_pem, ca_pem):
    """
    Check that all certificates in certpath are valid
    """
    print_task('Verifying root chain')
    certs = split_certificates_from_pem(cert_pem)
    certs.extend(split_certificates_from_pem(ca_pem))
    subject_keyids, fetcher = get_certificate_fetcher_from_list(certs)
    cert_path = build_certification_path(cert_pem, subject_keyids, fetcher)
    if not cert_path[0]['is_selfsigned']:
        print_task_status_warning('FAILED')
        error_message = "No root CA found in the certification path"
        logger.error(error_message)
        raise OperationFailed(error_message)

    expired_certs = []
    for cert_info in cert_path[:-1]:
        cert = fetcher(cert_info['subject_keyid'])
        cert_x509 = get_x509_certificate(cert)
        if is_x509_expired(cert_x509):
            subject_dn, _ = get_subject_and_issuer_dn(cert_x509)
            expired_certs.append(subject_dn)
    if expired_certs:
        print_task_status_warning('FAILED')
        error_message_list = ['The following provided CA certificates are expired:']
        error_message_list.extend(expired_certs)
        error_message_list.append('')
        error_message_list.append('Installation of the certificates cannot continue')
        error_message = '\n'.join(error_message_list)
        logger.error(error_message)
        raise OperationFailed(error_message)
    is_rogue, rogue_ca = check_rogue_ca("\n".join(certs))
    if is_rogue:
        print_task_status_warning('FAILED')
        error_message = "Certificate is invalid because the CA '{}' extends beyond the path length restrictions of a parent CA".format(rogue_ca)
        logger.error(error_message)
        raise OperationFailed(error_message)
    print_task_status('OK')


def verify_pnid_in_san(cert_pem):
    """
    Ensure that PNID is included in the Subject Alternative Names
    """
    print_task('Verify PNID included in SAN')
    pnid_lower = Environment.get_environment().get_value('PNID').lower()
    cert_x509 = get_x509_certificate(cert_pem)
    san_lower = get_subject_alternative_names(cert_x509).lower()
    found = "dns:{}".format(pnid_lower) in san_lower or "ip address:{}".format(pnid_lower) in san_lower
    if not found:
        print_task_status_warning('FAILED')
        error_message = 'The Primary Network Identifier (PNID) is not included in the Subject '\
                        'Alternative Name field'
        logger.error(error_message)
        raise OperationFailed(error_message)
    print_task_status('OK')


def publish_ca_signing_certificate(ca_pem_file, is_sol_user=False):
    """
    Publish CA certificates in VMDir. If a certificate with the same id is found in VMDir,
    the previous certificate will be unpublished first.
    :param ca_pem_file: CA certificate chain in PEM format
    :param is_sol_user: Adding is_sol_user param to skip print and log of statements
    to avoid printing those statements for each soluser
    """
    if not is_sol_user:
        print_task('Publish CA signing certificates')
    ca_pem = get_file_contents(ca_pem_file)
    certs = split_certificates_from_pem(ca_pem)
    subject_keyids = vmdir.get_all_ca_subject_keyids(use_cache=False)
    temp_dir = Environment.get_environment().get_value('TEMP_DIR')
    try:
        # unpublish the certificates as necessary
        for cert in certs:
            cert_x509 = get_x509_certificate(cert)
            skid = get_subject_keyid(cert_x509, remove_colons=True)
            if skid in subject_keyids:
                prev_cert = vmdir.get_ca_certificate(skid)
                old_ca_file = "{}/ca-certificate-old-{}.crt".format(temp_dir, skid)
                save_text_to_file(prev_cert, old_ca_file)
                vmdir.unpublish_trusted_certificate(old_ca_file)
        vmdir.publish_trusted_certificate(ca_pem_file, is_chain=True)
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        logger.error(str(e))
        raise OperationFailed(str(e))
    if not is_sol_user:
        print_task_status('OK')


def find_matched_private_key(cert_modulus, cert_file):
    """
    Find private key that matches to current certificate
    """
    logger.info("Looking for private key with modulus {}".format(cert_modulus))
    key_file = str(pathlib.Path(cert_file).with_suffix('.key'))
    files = [key_file] if is_file_exists(key_file) else []
    files.extend(find_files("{}/*/requests/*.key".format(TOP_DIR)))
    for file in files:
        _, key_pem = detect_and_convert_to_pem(file, allow_input=True)
        if key_pem:
            modulus = get_key_modulus_from_pem_text(key_pem)
            if modulus == cert_modulus:
                logger.info("Found private key at {}".format(file))
                return key_pem

    if '__MACHINE_CSR' in vecs.get_certificate_aliases('MACHINE_SSL_CERT'):
        machine_csr = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CSR')
        modulus = get_key_modulus_from_pem_text(machine_csr)
        if modulus == cert_modulus:
            logger.info('Found private key in the __MACHINE_CSR entry in VECS')
            return machine_csr

    key_input = MenuInput("Provide path to the {}{}{} private key: "
                          .format('{COLORS[CYAN]}', cert_file, '{COLORS[NORMAL]}',),
                          allow_empty_input=False, case_insensitive=False)
    retry = 0
    key_pem = None
    while retry < 3 and key_pem is None:
        key_file = key_input.get_input()
        if not is_file_exists(key_file):
            print_text_error('Error: file not found')
        else:
            _, key_pem = detect_and_convert_to_pem(key_file)
        retry += 1

    return key_pem


def generate_certool_config(output_dir, cert_usage, csr_info, fqdn=None):
    """
    Generate config to be used by certool
    """
    if cert_usage in vmdir.get_solution_users():
        print_task(cert_usage)
    else:
        print_task('Generate certool configuration')
    env = Environment.get_environment()
    hostname = env.get_value('HOSTNAME')
    pnid = env.get_value('PNID')
    ip_address = env.get_value('IP_ADDRESS')
    config = []
    if cert_usage == 'auth-proxy':
        filename = "{}/auth-proxy.cfg".format(output_dir)
        config.append("Country = {}".format(csr_info['country']))
        config.append("Organization = {}".format(csr_info['org']))
        config.append("OrgUnit = {}".format(csr_info['org_unit']))
        config.append("Name = {}".format(hostname))
        config.append("Hostname = {}".format(hostname))
        config.append('')
    elif cert_usage == 'vmdir':
        filename = "{}/vmdir.cfg".format(output_dir)
        config.append("Country = {}".format(csr_info['country']))
        config.append("Name = {}".format(hostname))
        config.append("Hostname = {}".format(hostname))
    elif cert_usage == 'sso-sts':
        filename = "{}/sso-sts.cfg".format(output_dir)
        config.append('Name = ssoserverSign')
        config.append("Hostname = {}".format(hostname))
    else:
        filename = "{}/{}.cfg".format(output_dir, cert_usage)
        config.append("Country = {}".format(csr_info['country']))
        config.append("Name = {}".format(fqdn))
        config.append("Organization = {}".format(csr_info['org']))
        config.append("OrgUnit = {}".format(csr_info['org_unit']))
        config.append("State = {}".format(csr_info['state']))
        config.append("Locality = {}".format(csr_info['locality']))
        if fqdn == ip_address:
            config.append("IPAddress = {}".format(fqdn))
        elif csr_info['ip']:
            config.append("IPAddress = {}".format(csr_info['ip']))
        if csr_info['email']:
            config.append("Email = {}".format(csr_info['email']))

        hostnames = [hostname]
        if pnid.lower() != hostname.lower() and pnid != ip_address:
            hostnames.append(pnid)
        additional_dns = csr_info['dns']
        if additional_dns:
            hostnames.extend(additional_dns)
        config.append("Hostname = {}".format(', '.join(hostnames)))

    save_text_to_file('\n'.join(config), filename)
    print_task_status('OK')


def backup_vecs_cert_key(cert_usage):
    """
    Backup some certificates from VECS to the backup directory
    """
    if cert_usage == 'machine-ssl':
        store = 'MACHINE_SSL_CERT'
        alias = '__MACHINE_CERT'
        print_task('Backing up Machine SSL certificate and private key')
    elif cert_usage == 'machine-ssl-csr':
        store = 'MACHINE_SSL_CERT'
        alias = '__MACHINE_CSR'
        print_task('Backing up Machine SSL CSR certificate and private key')
    else:
        store = alias = cert_usage
        if cert_usage == 'data-encipherment':
            print_task('Backing up certificate and private key')
        else:
            print_task("   {}".format(get_cert_usage_value(cert_usage)))

    if alias in vecs.get_certificate_aliases(store):
        cert_pem = vecs.get_certificate(store, alias)
        key_pem = vecs.get_key(store, alias)
        env = Environment.get_environment()
        backup_dir = env.get_value('BACKUP_DIR')
        timestamp = get_timestamp()
        save_text_to_file(cert_pem, "{}/{}-{}.crt".format(backup_dir, cert_usage, timestamp))
        key_file = "{}/{}-{}.key".format(backup_dir, cert_usage, timestamp)
        save_text_to_file(key_pem, key_file)
        set_file_mode(key_file, stat.S_IRUSR | stat.S_IWUSR)
        print_task_status('OK')
    else:
        print_task_status_warning('NOT FOUND')


def backup_filesystem_cert_key(cert, key, cert_usage):
    """
    Backup certificates from file system to the backup directory
    """
    env = Environment.get_environment()
    print_task('Backing up certificate and private key')
    timestamp = get_timestamp()
    backup_dir = env.get_value('BACKUP_DIR')
    backup_cert_file_path = "{}/{}-{}.crt".format(backup_dir, cert_usage, timestamp)
    backup_key_file_path = "{}/{}-{}.key".format(backup_dir, cert_usage, timestamp)
    if is_file_exists(cert):
        try:
            CommandRunner('cp', cert, backup_cert_file_path).run_and_get_output()
        except CommandExecutionError:
            print_task_status_warning('FAILED')
            error_message = "Unable to backup {} certificate".format(cert_usage)
            logger.error(error_message)
            raise OperationFailed(error_message)
    else:
        print_task_status('NOT FOUND', ColorKey.YELLOW)
        logger.error('Certificate not found at {}'.format(cert))
    if is_file_exists(key):
        try:
            CommandRunner('cp', key, backup_key_file_path).run_and_get_output()
            set_file_mode(backup_key_file_path, stat.S_IRUSR | stat.S_IWUSR)
        except CommandExecutionError:
            print_task_status_warning('FAILED')
            error_message = "Unable to backup {} key".format(cert_usage)
            logger.error(error_message)
            raise OperationFailed(error_message)
    else:
        print_task_status('NOT FOUND', ColorKey.YELLOW)
        logger.error('Private key not found at {}'.format(key))
    print_task_status('OK')
    logger.info("Certificate and key backed up to {} and {}".format(backup_cert_file_path,
                                                                    backup_key_file_path))


def update_vecs(cert_usage, cert_file, key_file):
    """
    Update certificate in VECS
    """
    if cert_usage == 'machine-ssl':
        store = 'MACHINE_SSL_CERT'
        alias = '__MACHINE_CERT'
    elif cert_usage == 'legacy-lookup-service':
        store = 'STS_INTERNAL_SSL_CERT'
        alias = '__MACHINE_CERT'
    else:
        store = alias = cert_usage

    if cert_usage in ['machine-ssl', 'data-encipherment']:
        print_task("Updating {} certificate".format(store))
    else:
        print_task("   {}".format(get_cert_usage_value(cert_usage)))

    if alias in vecs.get_certificate_aliases(store):
        try:
            vecs.delete_entry(store, alias)
        except CommandExecutionError:
            print_task_status_warning('FAILED')
            error_message = "Unable to delete entry {} in the VECS store {}".format(alias, store)
            logger.error(error_message)
            raise OperationFailed(error_message)

    try:
        vecs.add_entry(store, alias, cert_file, key_file)
    except CommandExecutionError:
        print_task_status_warning('FAILED')
        error_message = "Unable to create entry {} in the VECS store {}".format(alias, store)
        logger.error(error_message)
        raise OperationFailed(error_message)

    print_task_status('OK')


def get_leaf_certificate_for_trust_anchor(cert_file):
    """
    Return the leaf (server) certificate that appropriate for trust anchor settings in DB
    """
    certs_pem = get_file_contents(cert_file)
    certs = TextFilter(certs_pem).match_block('^-----BEGIN CERTIFICATE-----',
                                              '^-----END CERTIFICATE-----',
                                              concatenate=True).get_lines()
    leaf_cert = certs[0]
    cert_x509 = get_x509_certificate(leaf_cert)

    one_line_pem = TextFilter(leaf_cert).head(-1).tail(-1).get_text().replace('\n', '')
    cert_der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_x509)
    return one_line_pem, cert_der


def update_ssl_trust_anchors(cert_file, node_fqdn=None):
    """
    Update trust anchors in the service endpoints
    """
    if not node_fqdn:
        node_fqdn = Environment.get_environment().get_value('PNID')
    print_header("Update SSL Trust Anchors ({})".format(node_fqdn))
    cert_pem, cert_der = get_leaf_certificate_for_trust_anchor(cert_file)
    pattern = "^https://{0}:.*|^https://{0}/.*".format(node_fqdn)
    endpoints = vmdir.get_all_lookup_service_endpoints()
    service_dns = []
    total_service_updated = 0
    for endpoint in endpoints:
        if re.match(pattern, endpoint['vmwLKUPURI']):
            service_dn = ','.join(endpoint['dn'].split(',')[1:])
            if service_dn not in service_dns:
                service_dns.append(service_dn)
    service_dns = sorted(service_dns)
    logger.info("Service registration DNs to update: {}".format(service_dns))
    for service_dn in service_dns:
        logger.info("Updating service {}".format(service_dn))
        update_ssl_trust_anchor_for_service(service_dn, cert_pem, cert_der)
        total_service_updated += 1

    logger.info('Searching for ghost trust anchors')
    vcs = vmdir.get_registered_vcenters()
    for deployment_id, dn in vcs:
        uris = '\n'.join(vmdir.get_endpoint_registrations(dn))
        pattern = ".*https://{0}/.*|.*https://{0}:.*".format(node_fqdn)
        if not re.match(pattern, uris):
            continue

        logger.debug("Found vCenter registration for {}: {}".format(node_fqdn, deployment_id))
        ghost_vmonapi_dn = get_ghost_vmonapi_dn(deployment_id)
        if not ghost_vmonapi_dn:
            continue

        logger.debug("cis.vmonapi registration DN: {}".format(ghost_vmonapi_dn))
        vmonapi_endpoint_dns = get_ghost_vmonapi_endpoint_dns(ghost_vmonapi_dn)
        for vep_dn in vmonapi_endpoint_dns:
            service_dn = ','.join(vep_dn.split(',')[1:])
            if service_dn not in service_dns:
                logger.info("Updating ghost service: {}".format(service_dn))
                update_ssl_trust_anchor_for_service(service_dn, cert_pem, cert_der)
                total_service_updated += 1

    print_text("Updated {} service(s)".format(total_service_updated))


def get_ghost_vmonapi_dn(deployment_id):
    domain_dn = Environment.get_environment().get_value("SSO_DOMAIN_DN")
    search_base = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    search_filter = "(&(vmwLKUPType=cis.vmonapi)(vmwLKUPDeploymentNodeId={}))".format(deployment_id)
    search_attributes = ['dn']
    results = vmdir.perform_ldap_search(search_base, search_filter, search_attributes)
    return results[0]['dn'] if results else ''


def get_ghost_vmonapi_endpoint_dns(vmonapi_dn):
    search_filter = '(vmwLKUPURI=http://localhost*)'
    search_attributes = ['dn']
    result = vmdir.perform_ldap_search(vmonapi_dn, search_filter, search_attributes)
    return [entry['dn'] for entry in result]


def update_ssl_trust_anchor_for_service(service_dn, cert_pem, cert_der):
    service_id = service_dn.split(',')[0].replace('cn=', '')
    print_text("Updating service: {}".format(service_id))
    endpoints = vmdir.get_all_lookup_service_endpoints(service_dn)
    for endpoint in endpoints:
        try:
            if 'vmwLKUPServiceEndpoint' in endpoint['objectClass']:
                vmdir.perform_ldap_modify(endpoint['dn'], 'vmwLKUPSslTrustAnchor', cert_der)
            else:
                vmdir.perform_ldap_modify(endpoint['dn'], 'vmwLKUPEndpointSslTrust', cert_pem)
        except LdapException:
            error_message = "Failed updating trust anchor for service dn: {}".format(service_dn)
            logger.error(error_message)
            raise OperationFailed(error_message)


def update_vc_ext_thumbprints():
    print_header('Update vCenter Extension Thumbprints')
    check_vpostgres_service()
    vcenter_extensions = get_vcenter_extensions()
    extension_thumbprints = vcdb.get_extension_thumbprints(vcenter_extensions)
    expected_thumbprints = get_vcenter_extension_expected_thumbprints(vcenter_extensions)
    for extension, (thumbprint, db_cert_pem) in extension_thumbprints.items():
        expected_thumbprint, expected_cert_type, expected_cert_pem = expected_thumbprints[extension]
        print_task("{} ({})".format(extension, expected_cert_type))
        logger.info("Comparing {} thumbprint of '{}' to '{}'".format(extension, thumbprint, expected_thumbprint))
        if get_vc_version() < VcVersion.V9:
            if thumbprint == expected_thumbprint:
                print_task_status('MATCHES')
            else:
                if not vcdb.update_extension_thumbprint(extension, expected_thumbprint):
                    print_task_status_warning('FAILED')
                    error_message = "Unable to update {} extension thumbprint in VCDB".format(extension)
                    logger.error(error_message)
                    raise OperationFailed(error_message)
                print_task_status('UPDATED')
        else:
            if thumbprint == expected_thumbprint and db_cert_pem == expected_cert_pem:
                print_task_status('MATCHES')
            else:
                if not vcdb.update_extension_thumbprint(extension, expected_thumbprint, expected_cert_pem):
                    print_task_status_warning('FAILED')
                    error_message = "Unable to update {} extension thumbprint and certificate in VCDB".format(extension)
                    logger.error(error_message)
                    raise OperationFailed(error_message)
                print_task_status('UPDATED')


def update_auto_deploy_db():
    """
    Update Machine SSL thumbprint in Auto Deploy DB
    """
    output = CommandRunner(VMON_CLI, '-s', 'rbd').run_and_get_output()
    startup_type = TextFilter(output).start_with('Starttype').get_text().split(':')[1].strip()
    if startup_type == 'AUTOMATIC':
        print_header('Updating Auto Deploy Database')
        machine_ssl_cert = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')
        cert_x509 = get_x509_certificate(machine_ssl_cert)
        machine_ssl_thumbprint = get_certificate_fingerprint(cert_x509)
        if is_service_running('rbd'):
            print_task('Stopping Auto Deploy Service')
            if not stop_vmware_services('vmware-rbd-watchdog'):
                print_task_status_warning('FAILED')
                error_message = 'Unable to stop Auto Deploy service'
                logger.error(error_message)
                raise OperationFailed(error_message)
            print_task_status('OK')

        print_task('Updating Machine SSL thumbprint')
        query = "update vc_servers set thumbprint = '{}'".format(machine_ssl_thumbprint)
        auto_deploy_db = '/var/lib/rbd/db' if (get_vc_version() == VcVersion.V7) else '/etc/vmware-rbd/db/db'
        ret_code, _, _ = CommandRunner('/usr/bin/sqlite3', auto_deploy_db, query).run()
        if ret_code != 0:
            print_task_status_warning('FAILED')
            error_message = 'Unable to update Auto Deploy database'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')

        print_task('Starting Auto Deploy Service')
        if not start_vmware_services('vmware-rbd-watchdog'):
            print_task_status_warning('FAILED')
            error_message = 'Unable to start Auto Deploy service'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')


def get_timestamp():
    return datetime.datetime.utcnow().strftime('%Y%m%d%H%M')


def publish_ca_certificates_to_vmdir():
    """
    Publish CA certificates to VMware Directory

    If the certificate's Subject KeyId already in VMDir, the previous certificate will be
    un-published first. For any CA certificate, this method will check the certificate is
    included in the embedded certificate.
    """
    menu_input = MenuInput('Enter path to CA certificate (or chain): ', case_insensitive=False)
    retry = 0
    ca_file = None
    while not ca_file and retry < 3:
        ca_file = menu_input.get_input().strip()
        if not is_file_exists(ca_file):
            print_text_error('Error: file not found')
            ca_file = None
            retry += 1
            continue
    if not ca_file:
        return

    print_header('Publish CA Certificate(s) to VMware Directory')
    cert_pem, _ = detect_and_convert_to_pem(ca_file, allow_input=True)
    ca_certs = split_certificates_from_pem(cert_pem)
    subject_keyids = vmdir.get_all_ca_subject_keyids(use_cache=False)
    temp_dir = Environment.get_environment().get_value('TEMP_DIR')

    total_published = 0
    total_non_ca = 0
    total_embedded_updated = 0
    for ca_cert in ca_certs:
        cert_x509 = get_x509_certificate(ca_cert)
        if not is_ca_certificate(cert_x509):
            total_non_ca += 1
            continue
        skid = get_subject_keyid(cert_x509, remove_colons=True)
        try:
            if skid in subject_keyids:
                logger.info("Found CA certificate with Subject KeyId {}, unpublishing".format(skid))
                ca_file = "{}/ca-certificate-old-{}.crt".format(temp_dir, skid)
                ca_pem = vmdir.get_ca_certificate(skid)
                save_text_to_file(ca_pem, ca_file)
                vmdir.unpublish_trusted_certificate(ca_file)
            ca_file = "{}/ca-certificate-{}.crt".format(temp_dir, skid)
            save_text_to_file(ca_cert, ca_file)
            vmdir.publish_trusted_certificate(ca_file)

            serial_number = get_serial_number(cert_x509)
            total_embedded_updated += check_and_update_embedded_ca_chain(ca_cert, skid, serial_number)
            total_published += 1
        except CommandExecutionError as e:
            error_message = "Unable to publish CA certificate {}: {}".format(skid, str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)

    print_text("Published {}{}{} certificates to VMware Directory".format(ColorKey.GREEN, total_published,
                                                                          ColorKey.NORMAL))
    if total_non_ca > 0:
        print()
        print_text('Found {COLORS[YELLOW]} ', total_non_ca,
                   ' {COLORS[NORMAL]} non-CA certificate in the provided file')
        print_text('These certificates were not published to VMware Directory.')

    if total_published == 0:
        return

    print_task('Refreshing CA certificates to VECS')
    try:
        vecs.force_refresh()
        print_task_status('OK')
    except CommandExecutionError as e:
        error_message = "Unable to perform a force-refresh of CA certificates to VECS: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)

    if total_embedded_updated > 0:
        print_text_warning('Certificate(s) with an embedded CA chain have been updated.')
        restart_vmware_services()


def check_and_update_embedded_ca_chain(ca_cert, ca_skid, ca_serial_number):
    """
    Check if the CA certificate is included in the end entity certificates in VECS. If that's the case,
    update the certificate chain as necessary.

    :param ca_cert: The new CA certificate
    :param ca_skid: The new CA certificate's Subject KeyIdentifier
    :param ca_serial_number: The new CA certificate serial number
    :return: The total number of end entity certificate updated
    """
    stores_and_aliases = [('MACHINE_SSL_CERT', '__MACHINE_CERT')]
    solution_users = Environment.get_environment().get_value('SOLUTION_USERS')
    for sol_user in solution_users:
        stores_and_aliases.append((sol_user, sol_user))
    total_updated = check_and_update_embedded_ca_chain_in_vecs(ca_cert, ca_skid, ca_serial_number,
                                                               stores_and_aliases)

    cert_files = [(AUTH_PROXY_CERT_FILE_PATH, 'Auth Proxy Cert'),
                  (RBD_CERT_FILE_PATH, 'Auto Deploy CA Cert'),
                  (VMCA_CERT_FILE_PATH, 'VMCA Cert')]
    total_updated += check_and_update_embedded_ca_chain_in_files(ca_cert, ca_skid, ca_serial_number,
                                                                 cert_files)
    return total_updated


def check_and_update_embedded_ca_chain_in_vecs(ca_cert, ca_skid, ca_serial_number, stores_and_aliases):
    total_updated = 0
    env = Environment.get_environment()
    backup_dir = env.get_value('BACKUP_DIR')
    temp_dir = env.get_value('TEMP_DIR')
    for store, alias in stores_and_aliases:
        cert_pem = vecs.get_certificate(store, alias)
        updated_cert_pem = get_updated_cert_chain(cert_pem, ca_cert, ca_skid, ca_serial_number)
        if updated_cert_pem is not None:
            logger.info("Updating CA certificate {} in alias {}, store {}".format(ca_skid, alias, store))
            print_task('Updating embedded CA cert in VECS')
            backup_file = "{}/vecs-cert-{}-{}-{}.crt".format(backup_dir, store, alias, get_timestamp())
            cert_file = "{}/embedded-cert-{}-{}.crt".format(temp_dir, store, alias)
            key_file = "{}/embedded-cert-{}.key".format(temp_dir, ca_skid)
            try:
                save_text_to_file(updated_cert_pem, backup_file)
                save_text_to_file(updated_cert_pem, cert_file)
                key_pem = vecs.get_key(store, alias)
                save_text_to_file(key_pem, key_file)
                vecs.delete_entry(store, alias)
                vecs.add_entry(store, alias, cert_file, key_file)
            except CommandExecutionError as e:
                print_task_status_warning('FAILED')
                error_message = "Error: failed to update embedded CA certificate in VECS: {}".format(str(e))
                logger.error(error_message)
                raise OperationFailed(error_message)
            print_task_status('OK')
            total_updated += 1

    return total_updated


def check_and_update_embedded_ca_chain_in_files(ca_cert, ca_skid, ca_serial_number, cert_files):
    env = Environment.get_environment()
    backup_dir = env.get_value('BACKUP_DIR')
    total_updated = 0
    for cert_file, cert_name in cert_files:
        cert_pem = get_file_contents(cert_file)
        new_cert_pem = get_updated_cert_chain(cert_pem, ca_cert, ca_skid, ca_serial_number)
        if new_cert_pem is not None:
            print_task("Updating embedded CA cert in {}".format(cert_name))
            logger.info("Updating CA cert {} in {}".format(ca_skid, cert_file))
            backup_cert_file = "{}/{}-backup-{}{}".format(backup_dir, pathlib.Path(cert_file).stem,
                                                          get_timestamp(), pathlib.Path(cert_file).suffix)
            save_text_to_file(cert_pem, backup_cert_file)
            save_text_to_file(new_cert_pem, cert_file)
            print_task_status('OK')
            total_updated += 1
    return total_updated


def get_updated_cert_chain(cert_pem, ca_cert, ca_skid, ca_serial_number):
    """
    Return the updated certificate chain it contain CA certificate with same Subject KeyId and
    updated serial number
    """
    certs = split_certificates_from_pem(cert_pem)
    need_update = False
    for index, cert in enumerate(certs):
        cert_x509 = get_x509_certificate(cert)
        skid = get_subject_keyid(cert_x509, remove_colons=True)
        serial_number = get_serial_number(cert_x509)
        if ca_skid == skid and ca_serial_number != serial_number:
            subject_dn, _ = get_subject_and_issuer_dn(cert_x509)
            certs[index] = ca_cert
            need_update = True
    return '\n'.join(certs) if need_update else None


def get_certificate_selection(max_number):
    print()
    menu_input = MenuInput('Enter the number(s) of the certificate(s) to delete (multiple entries '
                           'separated by a comma): ')
    cert_nums = None
    while not cert_nums:
        user_input = menu_input.get_input().strip()
        if not user_input:
            return

        cert_nums = []
        for num_str in user_input.split(','):
            try:
                num = int(num_str)
                if num < 1 or num > max_number:
                    print_text_error("Invalid certificate number: {}".format(num_str))
                    cert_nums = None
                    break
                else:
                    cert_nums.append(num)
            except ValueError:
                cert_nums = None
                break
    return cert_nums


def remove_ca_certificate_from_vmdir():
    """
    Remove CA certificates from VMware Directory. The certificate will be copied to the backup directory
    before the removal.
    """
    subject_keyids = vmdir.get_all_ca_subject_keyids()
    cert_nums = get_certificate_selection(len(subject_keyids))
    backup_dir = Environment.get_environment().get_value('BACKUP_DIR')
    print_header('Remove Certificate(s) from VMware Directory')
    for num in cert_nums:
        subject_keyid = subject_keyids[num-1]
        print_task("Backup {}".format(subject_keyid))
        cert_pem = vmdir.get_ca_certificate(subject_keyid)
        backup_file = "{}/ca-certificate-vmdir-{}.crt".format(backup_dir, subject_keyid)
        save_text_to_file(cert_pem, backup_file)
        print_task_status('OK')

        print_task("Remove {}".format(subject_keyid))
        try:
            vmdir.unpublish_trusted_certificate(backup_file)
            print_task_status('OK')
            continue
        except CommandExecutionError:
            print_task_status_warning('FAILED')

        print_task("Remove {} directly".format(subject_keyid))
        try:
            vmdir.remove_ca_certificate_from_ldap(subject_keyid)
            print_task_status('OK')
        except LdapException as e:
            print_task_status_warning('FAILED')
            logger.error("Unable to delete certificate with Subject Key ID {} from VMware "
                         "Directory: {}".format(subject_keyid, str(e)))

    print_task('Refreshing CA certificates to VECS')
    try:
        vecs.force_refresh()
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        logger.error("Error refreshing CA certificates to VECS: {}".format(str(e)))


def manage_ca_certificates_in_vmdir():
    """
    Entry point for managing certificate in VMware Directory
    """
    view_ca_certificates_in_vmdir(show_list_only=True)

    menu = Menu()
    menu.set_menu_options('Manage Certificates in VMware Directory')
    menu.add_menu_item('Publish CA certificate(s) to VMware Directory', publish_ca_certificates_to_vmdir)
    menu.add_menu_item('Remove CA certificate(s) from VMware Directory', remove_ca_certificate_from_vmdir)
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True, use_label_as_key=True)
    menu.run()


def remove_ca_certificate_from_vecs():
    """
    Remove CA certificate from VECS
    """
    print()
    print_text_warning('To add CA certificates to VECS, publish them to VMware Directory.')

    aliases = vecs.get_certificate_aliases('TRUSTED_ROOTS')
    cert_nums = get_certificate_selection(len(aliases))
    backup_dir = Environment.get_environment().get_value('BACKUP_DIR')
    print_header('Removing CA certificates from VECS')
    for num in cert_nums:
        alias = aliases[num-1]
        print_task("Backup {}".format(alias))
        cert_pem = vecs.get_certificate('TRUSTED_ROOTS', alias)
        backup_file = "{}/ca-certificate-vecs-{}.crt".format(backup_dir, alias.replace('/', '_'))
        save_text_to_file(cert_pem, backup_file)
        print_task_status('OK')

        print_task("Remove {}".format(alias))
        try:
            vecs.delete_entry('TRUSTED_ROOTS', alias)
        except CommandExecutionError:
            print_task_status_warning('FAILED')
            error_message = "Unable to delete certificate with Alias {}".format(alias)
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')


def manage_ca_certificates_in_vecs():
    """
    Entry point for managing certificate in VECS
    """
    print_header('CA Certificates in TRUSTED_ROOTS store in VECS')
    view_ca_certificates_in_vecs(show_list_only=True)

    menu = Menu()
    menu.set_menu_options('Manage Certificates in VECS')
    menu.add_menu_item('Remove CA certificate(s) from VECS', remove_ca_certificate_from_vecs)
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=True, key='R',
                       is_default=True, use_label_as_key=True)
    menu.run()


def manage_vcenter_extension_thumbprints():
    """
    Entry point for managing vCenter extension thumbprints
    """
    print_header('Check vCenter Extension Thumbprints')
    result = check_vcenter_extension_thumbprints()
    if result is not False:
        return

    print()
    print_text_warning('------------------------!!! Attention !!!------------------------')
    print_text_warning('Mismatched thumbprints detected.')
    print()
    menu_input = MenuInput('Update extension thumbprints? [n]: ', acceptable_inputs=['Y', 'N'], default_input='N')
    if menu_input.get_input() == 'Y':
        update_vc_ext_thumbprints()


def confirm_replace_sts_signing_certificate():
    if not vcdb.scheduled_task_table_exists():
        return True
    
    num_scheduled_tasks = vcdb.get_number_scheduled_tasks()
    logger.debug("Number of scheduled tasks: {}".format(num_scheduled_tasks))
    sts_warning_text = """
{}------------------------!!! Attention !!!------------------------{}

Replacing the STS Signing Certificate will invalidate the authentication
token for all user-defined Scheduled Tasks created in vCenter. 

There are {}{}{} user-defined Scheduled Tasks found in the vCenter database. 
Replacing the STS Signing Certificate will require removing and 
recreating {}{}ALL{} of these tasks. 

Please see the following KB article for details:
{}{}https://knowledge.broadcom.com/external/article/385375/domain-user-based-scheduled-tasks-failin.html{}
""".format(ColorKey.YELLOW, ColorKey.NORMAL, ColorKey.CYAN, num_scheduled_tasks, ColorKey.NORMAL, ColorKey.YELLOW, ColorKey.UNDER_LINE, ColorKey.NORMAL, ColorKey.YELLOW, ColorKey.UNDER_LINE, ColorKey.NORMAL)

    print_text(sts_warning_text)

    user_input = MenuInput('Replace STS Signing Certificate? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N')
    return True if user_input.get_input() == 'Y' else False


def manage_sts_signing_certificate_with_vmca_signed():
    if confirm_replace_sts_signing_certificate():
        replace_sts_signing_certificate_with_vmca_signed()
        restart_vmware_services()


def replace_sts_signing_certificate_with_vmca_signed():
    """
    Entry point for replacing SSO STS Signing certificate using VMCA signed certificate
    """
    output_dir = Environment.get_environment().get_value('TEMP_DIR')

    print_header('Replace SSO STS Signing Certificate')
    generate_certool_config(output_dir, 'sso-sts', None)

    print_task('Regenerate STS signing SSL certificate')
    config = "{}/sso-sts.cfg".format(output_dir)
    generate_vmca_signed_certificate(config, output_dir, 'sso-sts')
    print_task_status('OK')

    cert_file = "{}/sso-sts.crt".format(output_dir)
    key_file = "{}/sso-sts.key".format(output_dir)

    replace_sts_signing_certificate(cert_file, key_file, VMCA_CERT_FILE_PATH)
    clear_csr_info()


def import_custom_ca_signed_sts_signing_certificate():
    """
    Entry point for importing custom CA signed certificate as STS signing certificate
    """
    if confirm_replace_sts_signing_certificate():
        logger.info('User has chosen to import a CA-signed STS Signing certificate and key')
        print()
        cert_pem_file, key_pem_file, ca_pem_file, cert_pem, ca_pem  = get_custom_ca_signed_certificate_files('sso-sts')
        publish_ca_signing_certificate(ca_pem_file)
        replace_sts_signing_certificate(cert_pem_file, key_pem_file, ca_pem_file)
        restart_vmware_services()


def get_sts_key_in_pem(tenant_credential_dn):
    result = vmdir.perform_ldap_search(tenant_credential_dn, '(objectClass=vmwSTSTenantCredential)',
                                       ['vmwSTSPrivateKey'])
    if result:
        key_der = result[0]['vmwSTSPrivateKey']
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, key_der)
        return OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey).decode('utf-8')
    return None


def replace_sts_signing_certificate(cert_file, key_file, ca_file):
    print_task('Backup and delete tenant credentials')
    backup_dir = Environment.get_environment().get_value('BACKUP_DIR')
    tenant_cred_entries = vmdir.get_sts_tenant_certificates(include_tenant_credential=True,
                                                            include_certificate_chain=False)
    timestamp = get_timestamp()
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    for cn in tenant_cred_entries.keys():
        backup_cert_file = "{}/{}-{}.crt".format(backup_dir, cn, timestamp)
        backup_key_file = "{}/{}-{}.key".format(backup_dir, cn, timestamp)
        certs = tenant_cred_entries[cn]
        save_text_to_file('\n'.join(certs), backup_cert_file)
        dn = "cn={},cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}".format(cn, sso_domain, domain_dn)
        key_pem = get_sts_key_in_pem(dn)
        save_text_to_file(key_pem, backup_key_file)
        set_file_mode(backup_key_file, stat.S_IRUSR | stat.S_IWUSR)
        vmdir.perform_ldap_delete(dn)
    print_task_status('OK')

    print_task('Backup and delete trusted cert chains')
    cert_chain_entries = vmdir.get_sts_tenant_certificates(include_tenant_credential=False,
                                                           include_certificate_chain=True)
    for cn in cert_chain_entries.keys():
        backup_cert_file = "{}/{}-ca-{}.crt".format(backup_dir, cn, timestamp)
        certs = cert_chain_entries[cn]
        save_text_to_file('\n'.join(certs), backup_cert_file)
        dn = "cn={},cn=TrustedCertificateChains,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}"\
            .format(cn, sso_domain, domain_dn)
        vmdir.perform_ldap_delete(dn)
    print_task_status('OK')

    print_task('Add new STS signing certificate to VMDir')
    certs_der = load_pem_certificate_file_in_der(cert_file, leaf_only=True)
    ca_certs_der = load_pem_certificate_file_in_der(ca_file)
    key_der = load_pem_key_file_in_pkcs8_der(key_file)
    try:
        certs_der.extend(ca_certs_der)
        dn_tenant_cred = "cn=TenantCredential-1,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}"\
            .format(sso_domain, domain_dn)
        attributes_tenant_cred = {
            'objectClass': ['vmwSTSTenantCredential', 'top'],
            'cn': ['TenantCredential-1'],
            'userCertificate': certs_der,
            'vmwSTSPrivateKey': [key_der]
        }
        vmdir.perform_ldap_add(dn_tenant_cred, 'vmwSTSTenantCredential', attributes_tenant_cred,
                               use_machine_account=True)

        dn_cert_chain = "cn=TrustedCertChain-1,cn=TrustedCertificateChains,cn={},cn=Tenants,"\
                        "cn=IdentityManager,cn=Services,{}".format(sso_domain, domain_dn)
        attributes_cert_chain = {
            'objectClass': ['vmwSTSTenantTrustedCertificateChain', 'top'],
            'cn': ['TrustedCertChain-1'],
            'userCertificate': certs_der
        }
        vmdir.perform_ldap_add(dn_cert_chain, 'vmwSTSTenantTrustedCertificateChain',
                               attributes_cert_chain, use_machine_account=True)
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = "Failed updating STS signing certificate: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)


def check_ssl_trust_anchors(show_service_id=False, show_endpoint_uris=False, use_sha256_fingerprint=False):
    """
    Entry point for Check SSL Trust Anchors

    :param show_service_id: Show service Id list
    :param show_endpoint_uris: Show Endpoints' URIs
    :param use_sha256_fingerprint:  Use SHA256 fingerprint instead of SHA1
    """
    endpoints = vmdir.get_all_lookup_service_endpoints()
    trust_anchors = get_ssl_trust_anchors(endpoints)
    indent = '    '
    for index, cert in enumerate(trust_anchors, 1):
        print_text('{}-----Endpoint Certificate {}-----{}'.format(ColorKey.CYAN, index, ColorKey.NORMAL))
        cert_x509 = get_x509_certificate(cert)
        print_cert_info_basic(cert_x509, use_sha256_fingerprint)

        if show_service_id or show_endpoint_uris:
            service_ids, uris = get_service_ids_and_uri_by_certificate(endpoints, cert)
            if show_service_id:
                print("Used by {} service registrations:".format(len(service_ids)))
                for service_id in service_ids:
                    service_type = vmdir.get_endpoint_service_type(service_id)
                    print("{}{} ({})".format(indent * 2, service_id, service_type))
            if show_endpoint_uris:
                print("Used by {} endpoints:".format(len(uris)))
                for uri in uris:
                    print("{}{}".format(indent * 2, uri))
        print_text("{}--------------------------------{}".format(ColorKey.CYAN, ColorKey.NORMAL))

    sso_nodes = vmdir.get_sso_domain_nodes()
    for node in sso_nodes:
        set_text_color(ColorKey.CYAN)
        print('-----Machine SSL Certificate-----')
        print(node)
        set_text_color(ColorKey.NORMAL)
        print('Certificate Info:')
        certs = split_certificates_from_pem(get_certificate_from_host(node))
        if not certs:
            set_text_color(ColorKey.YELLOW)
            print("Unable to get certificate from {} on port 443".format(node))
            print("Please make sure the server is up and the reverse proxy service is running.")
            set_text_color(ColorKey.NORMAL)
            continue

        cert_x509 = get_x509_certificate(certs[0])
        print_cert_info_basic(cert_x509, use_sha256_fingerprint)
        print_text("{}--------------------------------{}".format(ColorKey.CYAN, ColorKey.NORMAL))


def print_cert_info_basic(cert_x509, use_sha256_fingerprint=False):
    indent = '    '
    output_format = '%b %e %H:%M:%S %Y GMT'
    subject_dn, issuer_dn = get_subject_and_issuer_dn(cert_x509)
    print("{}Issuer: {}".format(indent * 2, issuer_dn))
    print("{}Validity".format(indent * 2))
    start_date = get_certificate_start_date(cert_x509).strftime(output_format)
    end_date = get_certificate_end_date(cert_x509).strftime(output_format)
    if is_x509_expired(cert_x509):
        set_text_color(ColorKey.RED)
    print("{}Not Before: {}".format(indent * 3, start_date))
    print("{}Not After : {}".format(indent * 3, end_date))
    set_text_color(ColorKey.NORMAL)
    print_text("{}{}Subject:{} {}".format(indent * 2, ColorKey.GREEN, ColorKey.NORMAL, subject_dn))

    if use_sha256_fingerprint:
        fingerprint = get_certificate_fingerprint(cert_x509, 'sha256')
        print_text("{}SHA256 Fingerprint={}{}{}".format(indent * 2, ColorKey.YELLOW,
                                                        fingerprint, ColorKey.NORMAL))
    else:
        fingerprint = get_certificate_fingerprint(cert_x509)
        print_text("{}SHA1 Fingerprint={}{}{}".format(indent * 2, ColorKey.YELLOW,
                                                      fingerprint, ColorKey.NORMAL))


def manage_ssl_trust_anchors():
    """
    Entry point for Update SSL Trust Anchor operation
    """
    env = Environment.get_environment()
    sso_domain = env.get_value('SSO_DOMAIN')
    menu = Menu()
    menu.set_menu_options('', "Nodes in SSO domain '{}'".format(sso_domain),
                          input_text='Select node to update [1]: ')
    nodes = vmdir.get_sso_domain_nodes()
    menu.add_menu_item(nodes[0], is_default=True)
    for node in nodes[1:]:
        menu.add_menu_item(node)
    menu.add_menu_item('Custom hostname or IP address', key='C')
    menu.add_menu_item('Return to previous menu', Menu.run_navigation_return, key='R')
    print()
    menu.show_menu()
    print()
    user_input = menu.get_input()
    if user_input == 'R':
        return
    if user_input != 'C':
        node_fqdn = nodes[int(user_input) - 1]
        node_ssl_fqdn = node_fqdn
    else:
        set_text_color(ColorKey.YELLOW)
        print()
        print('Note: This operation is used when the endpoint URIs refer to a hostname or IP address')
        print('other than the target vCenter/PSC hostname or IP address. These situations are very uncommon.')
        print('Only use this option at the direction of VMware Global Support.')
        print()
        set_text_color(ColorKey.NORMAL)
        node_fqdn = MenuInput('Enter hostname or IP address of registration endpoint URIs to update: ',
                              allow_empty_input=False, case_insensitive=False).get_input()

        node_ssl_fqdn = MenuInput("Enter the hostname or IP address of the node serving the SSL "
                                  "certificate to update [{}]: ".format(node_fqdn), default_input=node_fqdn,
                                  case_insensitive=False).get_input()

    logger.info("User has selected '{}'".format(node_fqdn))
    logger.info("SSL certificate to update will be obtained from {}:443".format(node_ssl_fqdn))

    cert = get_certificate_from_host(node_ssl_fqdn)
    if not cert:
        error_message = "Failed to obtain certificate from {}:443".format(node_ssl_fqdn)
        logger.error(error_message)
        raise OperationFailed(error_message)

    temp_dir = Environment.get_environment().get_value('TEMP_DIR')
    cert_file = "{}/trust-anchor-machine-ssl.crt".format(temp_dir)
    save_text_to_file(cert, cert_file)
    update_ssl_trust_anchors(cert_file, node_fqdn)
    restart_vmware_services()


def recreate_missing_vecs_store(missing_stores):
    env = Environment.get_environment()
    permissions = env.get_value('VECS_STORE_PERMISSIONS')
    vc_build = int(env.get_value('VC_BUILD'))
    for store in missing_stores:
        store_perm = permissions.get(store)
        print_task("Recreate store {}".format(store))
        vecs.create_store(store)
        print_task_status('OK')
        print('Assigning permissions:')
        if READ in store_perm:
            read_users = {}
            if store_perm[READ]:
                read_users = sorted(store_perm[READ])
            for user in read_users:
                print_task("   Read permission for user {}".format(user))
                vecs.grant_vecs_permission(store, user, READ)
                print_task_status('OK')
        if WRITE in store_perm and vc_build >= 20051473:
            write_users = {}
            if store_perm[WRITE]:
                write_users = sorted(store_perm[WRITE])
            for user in write_users:
                print_task("   Write permission for user {}".format(user))
                vecs.grant_vecs_permission(store, user, WRITE)
                print_task_status('OK')


def clear_trusted_root_crls():
    """
    Clear the entries in the TRUSTED_ROOT_CRLS store in VECS, which if there are too many
    can cause the vpostgres service to not start
    """
    print_task('Backup CRLs')
    env = Environment.get_environment()
    backup_dir = env.get_value('BACKUP_DIR')
    if not os.path.exists("{}/old-CRLs".format(backup_dir)):
        make_directory("{}/old-CRLs".format(backup_dir))
    for file in sorted(glob.glob('/etc/ssl/certs/*.r[0-9]')):
        try:
            os.rename(file, "{}/old-CRLs/{}".format(backup_dir, os.path.basename(file)))
        except PermissionError as error:
            print_task_status_error('FAILED')
            raise OperationFailed(error)
        except OSError as error:
            print_task_status_error('FAILED')
            raise OperationFailed(error)
    print_task_status('OK')
    print_task('Delete CRLs from VECS (this may take some time)')
    for alias in vecs.get_certificate_aliases('TRUSTED_ROOT_CRLS'):
        logger.info("Deleting alias {} from TRUSTED_ROOT_CRLS".format(alias))
        vecs.delete_entry('TRUSTED_ROOT_CRLS', alias)
    print_task_status('OK')
    restart_vmware_services(['vmafdd', 'vmdird', 'vmcad'])


def download_proxy_ca_certificates():
    """
    Download certificates from hostupdate.vmware.com and publish CA certs to workaround SSL Interception
    """
    print_task('Getting CA certificates from proxy server')
    depot_certs = split_certificates_from_pem(get_certificate_from_host('hostupdate.vmware.com'))
    depot_ca_certs = depot_certs[1:]
    if len(depot_ca_certs) == 0:
        print_task_status_warning('WARNING')
        print_text_warning('No CA certificates provided by the proxy, please import CA certificates directly.')
        return
    else:
        print_task_status('OK')
        publish_proxy_ca_certs(depot_ca_certs)
        terminal_proxy_ca = depot_ca_certs[-1]
        terminal_proxy_ca_x509 = get_x509_certificate(terminal_proxy_ca)
        if not is_self_signed_certificate(terminal_proxy_ca_x509):
            print_text_warning('The Root CA is not provided in the signing chain by the proxy.')
            print_text_warning('Please obtain this certificate and import it.')


def import_proxy_ca_certificates():
    """
    Import and publish CA certs not provided by proxy to workaround SSL Interception
    """
    depot_certs = split_certificates_from_pem(get_certificate_from_host('hostupdate.vmware.com'))
    depot_cert = depot_certs[0]
    menu_input = MenuInput("Provide path to the Certificate Authority chain for the proxy: ",
                           allow_empty_input=False, case_insensitive=False)
    cert_file = ''
    while not cert_file:
        cert_file = menu_input.get_input()
        if not is_file_exists(cert_file):
            print_text_error("Error: file not found: {}\n".format(cert_file))
            cert_file = ''
    verify_certification_path(depot_cert, get_file_contents(cert_file))
    publish_proxy_ca_certs(cert_file, from_file=True)


def publish_proxy_ca_certs(ca_certs, from_file=False):
    """
    Publish SSL Interception CA certificates to VMware Directory, python trust store, and Java keystore
    :param ca_certs:  CA certificates in either a list, or file path
    :param from_file:  determines if the CAs are provided in a list, or in a specified file
    """
    env = Environment.get_environment()
    backup_dir = env.get_value('BACKUP_DIR')
    temp_dir = env.get_value('TEMP_DIR')
    vc_build = env.get_value('VC_BUILD')

    if not from_file:
        ca_cert_file = '{}/ssl-proxy-ca-certs.pem'.format(temp_dir)
        ca_cert_list = ca_certs
        try:
            save_text_to_file('\n'.join(ca_certs), ca_cert_file)
        except Exception as e:
            error_message = 'Unable to create proxy CA file: {}'.format(str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)
    else:
        ca_cert_file = ca_certs
        ca_cert_list = split_certificates_from_pem(get_file_contents(ca_cert_file))

    publish_ca_signing_certificate(ca_cert_file)

    if int(vc_build) >= 17327517:
        python_trust_store_search = glob.glob('/usr/lib/python*/site-packages/certifi/cacert.pem')
        python_trust_store = python_trust_store_search[0]
        java_keystore = '/usr/java/jre-vmware/lib/security/cacerts'
        logger.info('Python trust store found at: {}'.format(python_trust_store))
        print_header('Add Proxy CA to Python Trust Store')

        if not is_file_exists('{}.backup'.format(python_trust_store)):
            print_task('Backup Python trust store')
            CommandRunner('/bin/cp', python_trust_store, '{}.backup'.format(python_trust_store)).run()
            print_task_status('OK')
        for cert in ca_cert_list:
            x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            if is_ca_certificate(x509_cert):
                ca_subject_hash = get_subject_hash(cert)
                print_task('  Adding {}'.format(ca_subject_hash))
                try:
                    append_text_to_file(cert, python_trust_store)
                    print_task_status('OK')
                except:
                    error_message = 'Unable to add CA {} to Python trust store file: {}'.format(ca_subject_hash, str(e))
                    logger.error(error_message)
                    raise OperationFailed(error_message)

        print_header('Add Proxy CA to Java Keystore')
        if not is_file_exists('{}.backup'.format(java_keystore)):
            print_task('Backup keystore')
            CommandRunner('/bin/cp', java_keystore, '{}.backup'.format(java_keystore)).run()
            print_task_status('OK')

        java_keystore_certs = CommandRunner('keytool', '-list', '-keystore', '-storepass', 'changeit', java_keystore ).run_and_get_output()
        for cert in ca_cert_list:
            x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            if is_ca_certificate(x509_cert):
                ca_subject_hash = get_subject_hash(cert)
                print_task('  Adding {}'.format(ca_subject_hash))
                proxy_ca_file = '{}/proxy-ca-{}.crt'.format(temp_dir, ca_subject_hash)
                try:
                    save_text_to_file(cert, proxy_ca_file)
                except Exception as e:
                    error_message = 'Unable to create Proxy CA file: {}'.format(str(e))
                    logger.error(error_message)
                    raise OperationFailed(error_message)
                if not TextFilter(java_keystore_certs).start_with('sslproxyca-{}'.format(ca_subject_hash)).get_text():
                    CommandRunner('keytool', '-noprompt', '-import', '-file', proxy_ca_file, '-trustcacerts',
                                  '-alias', 'sslproxyca-{}'.format(ca_subject_hash), '-storepass', 'changeit',
                                  '-keystore', java_keystore, expected_return_code=0).run()
                    print_task_status('OK')
                else:
                    print_task_status_warning('EXISTS')


def manage_sms_certificates():
    print_header('Manage Certificates in the SMS store in VECS')
    view_sms_certificates_in_vecs(show_list_only=True)
    menu = Menu.load_menu_from_config('config/manage_cert/sms/menu_manage_sms.yaml')
    try:
        menu.run()
    except MenuExitException:
        pass


def manage_sms_certificate(alias):
    store = 'SMS'
    header = 'Replace SMS self-signed certificate' if alias == 'sms_self_signed' else 'Replace SPS-extension VMCA-signed certificate'
    task = 'Remove SMS self-signed certificate' if alias == 'sms_self_signed' else 'Remove SPS-extension VMCA-signed certificate'
    print_header(header)
    print_task(task)
    try:
        vecs.delete_entry(store, alias)
    except CommandExecutionError:
        print_task_status_warning('FAILED')
        error_message = "Unable to delete entry {} in the VECS store {}".format(alias, store)
        logger.error(error_message)
        raise OperationFailed(error_message)

    print_task_status('OK')
    restart_vmware_services('vmware-sps')


def manage_sms_certificate_with_self_signed():
    manage_sms_certificate('sms_self_signed')


def manage_sps_certificate_with_vmca_signed():
    manage_sms_certificate('sps-extension')


def manage_ldaps_identity_source_certificates():
    identity_sources = vmdir.get_identity_sources()
    print_header('Select Domain to Manage LDAP Certificates')
    index = 1
    for ids in identity_sources:
        print('{:>2}. {} ({})'.format(index, ids['domain_name'], ids['type']))
    print()
    keys = [str(i) for i in range(1, len(identity_sources) + 1)]
    keys.append('R')
    menu_input = MenuInput('Select domain [Return to menu]: ', acceptable_inputs=keys,
                           default_input='R')
    key = menu_input.get_input()
    print()
    if key != 'R':
        ids = identity_sources[int(key) - 1]
        logger.info('Show domain: {}'.format(ids['domain_name']))
        logger.info('Identity Source Type: {}'.format(ids['type']))
        identity_source_certs = view_ldaps_identity_source_certificates(show_domain=ids['domain_name'], identity_source_type=ids['type'],
                                                show_list_only=True)

        identity_source_certs_der = []
        identity_source_certs = identity_source_certs[1:] if identity_source_certs[0] == '-' else identity_source_certs
        for cert in identity_source_certs:
            x509_cert = get_x509_certificate(cert)
            identity_source_certs_der.append(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_cert))
        menu = Menu()
        menu.set_menu_options('Manage Certificates for Identity Provider: Domain {}'.format(ids['domain_name']), run_once=True)
        menu.add_menu_item('Add LDAP server certificate(s)', publish_ldaps_identity_source_certificate,
                           {'domain_name': ids['domain_name'], 'identity_source_type' : ids['type'], 'certs_der' : identity_source_certs_der})
        menu.add_menu_item('Remove LDAP server certificate(s)', remove_ldaps_identity_source_certificate,
                           {'domain_name': ids['domain_name'], 'identity_source_type' : ids['type'], 'certs_der' : identity_source_certs_der})
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True,
                           use_label_as_key=True)
        menu.run()


def publish_ldaps_identity_source_certificate(domain_name, identity_source_type, certs_der):
    env = Environment.get_environment()
    menu_input = MenuInput('Enter path to LDAPS certificate(s): ', case_insensitive=False)
    retry = 0
    ldaps_file = None
    while not ldaps_file and retry < 3:
        ldaps_file = menu_input.get_input().strip()
        if not is_file_exists(ldaps_file):
            print_text_error('Error: file not found')
            ldaps_file = None
            retry += 1
            continue
    if not ldaps_file:
        return

    print_header('Publish new LDAP server certificate')
    new_certs_der = load_pem_certificate_file_in_der(ldaps_file)
    new_certs_der.extend(certs_der)
    if identity_source_type == 'ADFS':
        identity_source_dn = 'cn=VCIdentityProviders,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(env.get_value('SSO_DOMAIN'), env.get_value('SSO_DOMAIN_DN'))
    else:
        identity_source_dn = 'cn={},cn=IdentityProviders,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(domain_name, env.get_value('SSO_DOMAIN'), env.get_value('SSO_DOMAIN_DN'))
    try:
        print_task('Adding LDAP certificate')
        vmdir.perform_ldap_modify(identity_source_dn, 'userCertificate', new_certs_der)
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = "Failed adding LDAPS certificate: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)


def remove_ldaps_identity_source_certificate(domain_name, identity_source_type, certs_der):
    print_header('Remove LDAP server certificate')
    env = Environment.get_environment()
    menu_input = MenuInput('Enter the number(s) of the LDAP server certificate(s) to delete (multiple entries separated by a comma): ')
    while not menu_input:
        menu_input = MenuInput('Enter the number(s) of the LDAP server certificate(s) to delete (multiple entries separated by a comma): ')

    if identity_source_type == 'ADFS':
        identity_source_dn = 'cn=VCIdentityProviders,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(env.get_value('SSO_DOMAIN'), env.get_value('SSO_DOMAIN_DN'))
    else:
        identity_source_dn = 'cn={},cn=IdentityProviders,cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(domain_name, env.get_value('SSO_DOMAIN'), env.get_value('SSO_DOMAIN_DN'))

    user_input = menu_input.get_input().strip()
    certs_to_remove_str = user_input.split(',') if ',' in user_input else [user_input]
    certs_to_remove_int = [int(v) for v in certs_to_remove_str]
    certs_to_remove_set = set(certs_to_remove_int)
    new_certs_der = [v for i, v in enumerate(certs_der) if (i + 1) not in certs_to_remove_set]
    try:
        print_task('Remove LDAP certificate')
        vmdir.perform_ldap_modify(identity_source_dn, 'userCertificate', new_certs_der)
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = "Failed removing LDAPS certificate: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)


def manage_smart_card_certificates():
    smart_card_filter_file_certificates, smart_card_vmdir_certificates = view_smart_card_certificates(show_list_only=True)
    menu = Menu()
    menu.set_menu_options('Manage Smart Card Certificate Options')
    menu.add_menu_item('Manage Smart Card filter file certificate', manage_smart_card_filter_certificates, {'filter_file_certificates' : smart_card_filter_file_certificates})
    menu.add_menu_item('Manage Smart Card CA certificate', manage_smart_card_ca_certificates, {'vmdir_certificates' : smart_card_vmdir_certificates})
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True,
                           use_label_as_key=True)
    menu.run()


def manage_smart_card_filter_certificates(filter_file_certificates):
    env = Environment.get_environment()
    filter_file = env.get_value('SMART_CARD_FILTER_FILE')
    menu = Menu()
    menu.set_menu_options('Manage Smart Card Filter File Certificates', run_once=True)
    menu.add_menu_item('Add certificate to filter file', add_smart_card_filter_file_certificate,
                       {'filter_file_certs' : filter_file_certificates, 'filter_file' : filter_file})
    menu.add_menu_item('Remove certificate from filter file', remove_smart_card_filter_file_certificate,
                       {'filter_file_certs' : filter_file_certificates, 'filter_file' : filter_file})
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True,
                           use_label_as_key=True)
    menu.run()


def add_smart_card_filter_file_certificate(filter_file_certs, filter_file):
    print()
    menu_input = MenuInput('Enter path to new Smart Card filter file certificate(s): ', case_insensitive=False)
    retry = 0
    new_certs_file = None
    while not new_certs_file and retry < 3:
        new_certs_file = menu_input.get_input().strip()
        if not is_file_exists(new_certs_file):
            print_text_error('Error: file not found')
            new_certs_file = None
            retry += 1
            continue
    if not new_certs_file:
        return

    new_certs_pem, _ = detect_and_convert_to_pem(new_certs_file)
    new_certs = split_certificates_from_pem(new_certs_pem)

    for new_cert in new_certs:
        if new_cert not in filter_file_certs:
            filter_file_certs.append(new_cert)

    new_filter_file_contents = '\n'.join(filter_file_certs)
    print_header('Add Smart Card Filter File Certificate')
    print_task('Updating smart card filter file')
    try:
        save_text_to_file(new_filter_file_contents, filter_file)
        print_task_status('OK')
    except:
        print_task_status_warning('FAILED')
        error_message = 'Failed Updating smart card filter file'
        logger.error(error_message)
        raise OperationFailed(error_message)


def remove_smart_card_filter_file_certificate(filter_file_certs, filter_file):
    print()
    menu_input = MenuInput('Enter the number(s) of the Smart Card filter file certificate(s) to delete (multiple entries separated by a comma): ')
    while not menu_input:
        menu_input = MenuInput('Enter the number(s) of the Smart Card filter file certificate(s) to delete (multiple entries separated by a comma): ')
    user_input = menu_input.get_input().strip()
    certs_to_remove_str = user_input.split(',') if ',' in user_input else [user_input]

    certs_to_remove_int = [int(v) for v in certs_to_remove_str]
    certs_to_remove_set = set(certs_to_remove_int)
    new_filter_file_certs = [v for i, v in enumerate(filter_file_certs) if (i + 1) not in certs_to_remove_set]

    new_filter_file_contents = '\n'.join(new_filter_file_certs)
    print_header('Remove Smart Card Filter File Certificate')
    print_task('Updating smart card filter file')
    try:
        save_text_to_file(new_filter_file_contents, filter_file)
        print_task_status('OK')
    except:
        print_task_status_warning('FAILED')
        error_message = 'Failed Updating smart card filter file'
        logger.error(error_message)
        raise OperationFailed(error_message)


def manage_smart_card_ca_certificates(vmdir_certificates):
    menu = Menu()
    menu.set_menu_options('Manage Smart Card CA Certificates', run_once=True)
    menu.add_menu_item('Add Smart Card CA certificate to VMware Directory', add_smart_card_ca_certificate,
                       {'vmdir_certs_der' : vmdir_certificates})
    menu.add_menu_item('Remove Smart Card CA certificate from VMware Directory', remove_smart_card_ca_certificate,
                       {'vmdir_certs_der' : vmdir_certificates})
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True,
                           use_label_as_key=True)
    menu.run()


def add_smart_card_ca_certificate(vmdir_certs_der):
    print()
    env = Environment.get_environment()
    menu_input = MenuInput('Enter path to new Smart Card CA certificate(s): ', case_insensitive=False)
    retry = 0
    new_certs_file = None
    while not new_certs_file and retry < 3:
        new_certs_file = menu_input.get_input().strip()
        if not is_file_exists(new_certs_file):
            print_text_error('Error: file not found')
            new_certs_file = None
            retry += 1
            continue
    if not new_certs_file:
        return

    new_certs_der = load_pem_certificate_file_in_der(new_certs_file)
    new_certs_der.extend(vmdir_certs_der)
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    smart_card_certs_dn = \
        'cn=DefaultClientCertCAStore,cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,'\
        'cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(sso_domain, domain_dn)
    try:
        print_header('Add Smart Card CA certificate')
        print_task('Updating certificates in VMware Directory')
        vmdir.perform_ldap_modify(smart_card_certs_dn, 'userCertificate', new_certs_der)
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = 'Failed adding Smart Card CA certificate: {}'.format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)


def remove_smart_card_ca_certificate(vmdir_certs_der):
    print()
    env = Environment.get_environment()
    menu_input = MenuInput('Enter the number(s) of the Smart Card CA certificate(s) to delete (multiple entries separated by a comma): ')
    while not menu_input:
        menu_input = MenuInput('Enter the number(s) of the Smart Card CA certificate(s) to delete (multiple entries separated by a comma): ')

    user_input = menu_input.get_input().strip()
    certs_to_remove_str = user_input.split(',') if ',' in user_input else [user_input]
    certs_to_remove_int = [int(v) for v in certs_to_remove_str]
    certs_to_remove_set = set(certs_to_remove_int)
    new_certs_der = [v for i, v in enumerate(vmdir_certs_der) if (i + 1) not in certs_to_remove_set]
    sso_domain = env.get_value('SSO_DOMAIN')
    domain_dn = env.get_value('SSO_DOMAIN_DN')
    smart_card_certs_dn = \
        'cn=DefaultClientCertCAStore,cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,'\
        'cn={},cn=Tenants,cn=IdentityManager,cn=Services,{}'.format(sso_domain, domain_dn)
    try:
        print_header('Remove Smart Card CA certificate')
        print_task('Updating certificates in VMware Directory')
        vmdir.perform_ldap_modify(smart_card_certs_dn, 'userCertificate', new_certs_der)
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = "Failed removing Smart Card CA certificate: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)


def manage_machine_ssl_csr():
    def clearSSLCSR():
        clear_machine_ssl_csr()

    def runSSLCSRMenu():
        menu = Menu()
        menu.set_menu_options('Manage Machine SSL CSR', run_once=True)
        menu.add_menu_item('Clear Machine SSL CSR in VECS', clear_machine_ssl_csr)
        menu.add_menu_item('Get Machine SSL CSR', get_machine_ssl_csr)
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True,
                           use_label_as_key=True)
        menu.run()

    # In the following DB, search stops on first match.
    # Order of entries in the DB must be from most specific to least specific
    # (for example an entry with a version specifying a build must be before
    # the same version with no build).
    machineSSLCSRDB = [
    #   Version        Build     Management Function
    #   -------------  --------  -------------------
        (VcVersion.V7, None,     clearSSLCSR),
        (VcVersion.V8, 22385739, runSSLCSRMenu),
        (VcVersion.V8, None,     clearSSLCSR),
        (VcVersion.V9, None,     runSSLCSRMenu),
    ]

    env = Environment.get_environment()
    vc_version = get_vc_version()
    vc_build = int(env.get_value('VC_BUILD'))

    # Resolve the management function. We break on first match.
    manage_ssl_csr = None
    for versionConstraint, buildConstraint, func in machineSSLCSRDB:
        if vc_version != versionConstraint:
            continue
        if buildConstraint and vc_build < buildConstraint:
            continue

        # Found a match.
        manage_ssl_csr = func
        break

    if manage_ssl_csr:
        manage_ssl_csr()
    else:
        # This should never happen. If we don't match a version do nothing.
        pass


def get_machine_ssl_csr():
    temp_dir = Environment.get_environment().get_value('TEMP_DIR')
    CommandRunner(vecs.VECS_CLI, 'entry', 'getcert', '--store', 'MACHINE_SSL_CERT',
                  '--alias', '__MACHINE_CSR', '--output', '{}/machine_ssl_csr.crt'.format(temp_dir)).run()
    CommandRunner(vecs.VECS_CLI, 'entry', 'getkey', '--store', 'MACHINE_SSL_CERT',
                  '--alias', '__MACHINE_CSR', '--output', '{}/machine_ssl_csr.key'.format(temp_dir)).run()
    machine_ssl_csr = CommandRunner(OPENSSL_CLI, 'x509', '-x509toreq', '-in', '{}/machine_ssl_csr.crt'.format(temp_dir),
                                    '-key', '{}/machine_ssl_csr.key'.format(temp_dir), '-copy_extensions', 'copy').run_and_get_output()
    print_header('Machine SSL Certificate Signing Request')
    print_text('{}'.format(machine_ssl_csr))


def clear_machine_ssl_csr():
    print()
    print_text_warning('-------------------------!!! WARNING !!!-------------------------')
    print_text_warning('This entry was created using the "Generate Certificate')
    print_text_warning('Signing Request (CSR)" option from the vSphere Client.')
    print_text_warning('It contains the corresponding private key associated')
    print_text_warning('with this CSR. DO NOT DELETE if you are still waiting')
    print_text_warning('for this request to be signed by your Certificate Authority!')
    print()
    user_input = MenuInput('Delete the __MACHINE_CSR entry from VECS? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N').get_input().strip()

    if user_input == 'Y':
        print_header('Delete Machine SSL CSR entry in VECS')
        backup_vecs_cert_key('machine-ssl-csr')
        print_task('Delete entry in MACHINE_SSL_CERT store')
        try:
            vecs.delete_entry('MACHINE_SSL_CERT', '__MACHINE_CSR')
            Environment.get_environment().set_value('HAS_MACHINE_SSL_CSR', False)
            print_task_status('OK')
        except CommandExecutionError as e:
            print_task_status_warning('FAILED')
            error_message = "Failed deleting alias '__MACHINE_CSR' in VECS store 'MACHINE_SSL_CERT': {}".format(str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)


def manage_expired_backup_store():
    vecs_stores = vecs.get_store_list()
    if 'BACKUP_STORE' in vecs_stores:
        process_backup_store('BACKUP_STORE')
    if 'BACKUP_STORE_H5C' in vecs_stores:
        process_backup_store('BACKUP_STORE_H5C')


def process_backup_store(store):
    print_text('Entries in {}:'.format(store))
    for alias in vecs.get_certificate_aliases(store):
        print_task('    {}'.format(alias))
        alias_cert_pem = vecs.get_certificate(store, alias)
        alias_cert = get_x509_certificate(alias_cert_pem)
        days_left = get_certificate_expiry_in_days(alias_cert)
        logger.info('Checking expiration for certificate in alias {} in store {}: {} days'.format(alias, store, days_left))
        if days_left < 0:
            try:
                vecs.delete_entry(store, alias)
                print_task_status('OK')
            except CommandExecutionError as e:
                print_task_status_warning('FAILED')
                error_message = "Failed deleting alias {} in VECS store '{}': {}".format(alias, store, str(e))
                logger.error(error_message)
                raise OperationFailed(error_message)
        else:
            print_task_status('SKIPPING')


def manage_data_encipherment_certificate():
    user_input = MenuInput('Generate new Data Encipherment certificate? [N]: ', acceptable_inputs=['Y', 'N'], default_input='N').get_input().strip()
    if user_input == 'Y':
        print_header('Generate Data Enciphement Certificate')
        backup_vecs_cert_key('data-encipherment')
        print_task('Generate new certificate')
        env = Environment.get_environment()
        stage_dir = env.get_value('TEMP_DIR')
        pnid = env.get_value('PNID')
        key_pem = vecs.get_key('data-encipherment', 'data-encipherment')
        key_file = "{}/data-encipherment.key".format(stage_dir)
        cert_file = "{}/data-encipherment.crt".format(stage_dir)
        save_text_to_file(key_pem, key_file)
        privkey_arg = "--privkey={}".format(key_file)
        cert_arg = "--cert={}".format(cert_file)
        config_arg = '--config=/dev/null'
        name_arg = '--Name=data-encipherment'
        fqdn_arg = "--FQDN={}".format(pnid)
        CommandRunner(CERTOOL_CLI, privkey_arg, '--gencert', cert_arg, '--dataencipherment', '--genCIScert', name_arg, config_arg, fqdn_arg, expected_return_code=0).run()
        print_task_status('OK')
        print_task('Delete current certificate and private key')
        vecs.delete_entry('data-encipherment', 'data-encipherment')
        print_task_status('OK')
        print_task('Install new certificate and private key')
        vecs.add_entry('data-encipherment', 'data-encipherment', cert_file, key_file)
        print_task_status('OK')
        restart_vmware_services('vmware-vpxd')
