# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import re
import OpenSSL
import glob

from enum import Enum

from lib import vcdb
from lib import vecs
from lib import vmdir
from lib.certificate_utils import (
    get_x509_certificate, get_certificate_expiry_in_days, get_certificate_extensions,
    get_certificate_fingerprint, build_certification_path, split_certificates_from_pem,
    get_subject_keyid, get_certificate_from_host, build_pem_certificate,
    is_ca_certificate, get_subject_hash, get_authority_keyid, get_subject_and_issuer_dn,
    get_certificate_name
)
from lib.console import (
    print_task, print_task_status, print_text_error, print_task_status_error,
    print_task_status_warning, print_header, ColorKey, print_text
)
from lib.constants import (VMCA_CERT_FILE_PATH, RBD_CERT_FILE_PATH, READ, WRITE, VMWARE_DEPOT_HOST, VMWARE_DEPOT_CERT_ISSUER)
from lib.environment import Environment
from lib.exceptions import MenuExitException
from lib.host_utils import (
    is_file_exists, get_file_contents, get_vc_version, VcVersion,
    get_ip_address
)
from lib.menu import Menu
from lib.services import is_service_running
from operation.common import get_vcenter_extensions, get_vcenter_extension_expected_thumbprints


logger = logging.getLogger(__name__)


class CertificateStatus(Enum):
    CERT_STATUS_EXPIRES_SOON = 'One or more certificates are expiring within 30 days'
    CERT_STATUS_MISSING_PNID = 'One or more certificates are missing the PNID >>DETAILS<< from the SAN entry'
    CERT_STATUS_MISSING_SAN = 'One or more certificates do not have any Subject Alternative Name values'
    CERT_STATUS_KEY_USAGE = 'One or more certificates do not have the recommended\nKey Usage values'
    CERT_STATUS_EXPIRED = 'One or more certificates are expired'
    CERT_STATUS_NON_CA = 'One or more certificates are not CA certificates'
    CERT_STATUS_BAD_ALIAS = \
        'One or more entries in the TRUSTED_ROOTS store have an alias that is not the SHA1 thumbprint'
    CERT_STATUS_SHA1_SIGNING = 'One or more certificates are signed using the SHA-1 algorithm'
    CERT_STATUS_MISSING = 'One or more certificates are missing'
    CERT_STATUS_MISSING_VMDIR = \
        'One or more CA certificates are missing from VMware Directory'
    CERT_STATUS_MISMATCH_SERVICE_PRINCIPAL = \
        'One or more Solution User certificates does not match\nthe Service Principal certificate in VMware Directory'
    CERT_STATUS_TOO_MANY_CRLS = 'The number of CRLs in VECS may be preventing some services from starting'
    CERT_STATUS_MISSING_CA = \
        'One or more certificates do not have all of the CA\n' \
        'certificates in its signing chain in VMware Directory'
    CERT_STATUS_EXPIRED_EMBEDDED_CA = \
        'One or more certificates has a CA certificate embedded\n' \
        'in its chain that is expired'
    CERT_STATUS_STORE_MISSING = 'One or more VECS stores are missing'
    CERT_STATUS_STORE_PERMISSIONS = 'One or more VECS stores are missing permissions'
    CERT_STATUS_SERVICE_PRINCIPAL_MISSING = \
        'One or more Service Principal entries are missing\nfrom VMware Directory'
    CERT_STATUS_VMCA_EMPTY_CONFIG = \
        'There are one or more vpxd.certmgmt.certs.cn.* settings with empty values\n' \
        'This can cause issues pushing VMCA-signed certificates to ESXi hosts'
    CERT_STATUS_VMCA_MODE = \
        "The certificate management mode is set to 'thumbprint'\n" \
        "This is not recommended, and should be set to 'vmca' or 'custom'"
    CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING = \
        'The Smart Card issuing CA filter file does not exist at the following location:\n>>DETAILS<<'
    CERT_STATUS_CLIENT_CA_LIST_FILE_EMPTY = \
        'The Smart Card issuing CA filter file at the following location is empty:\n>>DETAILS<<'
    CERT_STATUS_STS_VECS_CONFIG = \
        'The STS server is configured to use a VECS store other than\nthe MACHINE_SSL_CERT store'
    CERT_STATUS_STS_CONNECTION_STRINGS_NUMBER = \
        'There are multiple STS ConnectionStrings values found in VMware Directory'
    CERT_STATUS_STS_CONNECTION_STRINGS_HOSTNAME = \
        'The STS ConnectionStrings value is not set properly for an SSO\ndomain with multiple Domain Controllers'
    CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM = \
        'One or more certificates is using an unsupported\nsignature algorithm'
    CERT_STATUS_CA_MISSING_SKID = 'One or more CA certificates is missing the Subject Key ID extension'
    CERT_STATUS_ROGUE_CA = \
        'One or more certificates are invalid because it or a signing CA\n' \
        'extends beyond the pathlen restrictions of a parent CA'
    CERT_STATUS_DUPLICATE_CA = \
        'Two or more CA certificates in VMWare Directory or VECS have the\n' \
        'same Subject string, which can cause issues with certificate\n' \
        'validation'
    TRUST_ANCHORS_MISMATCH = "One or more vCenter/PSC nodes have mismatched SSL trust anchors"
    TRUST_ANCHORS_UNKNOWN = \
        'The Machine SSL certificate could not be obtained from\n' \
        'the following nodes to check SSL trust anchors:'
    TRUST_ANCHORS_CHECK_URI_MISMATCH = \
        'One or more vCenter/PSC nodes have mismatched SSL trust anchors and\n' \
        'have Lookup Service registrations using the IP address instead\n' \
        'of the PNID in the endpoint URIs. These can be fixed with the\n' \
        'lsdoctor utility: https://knowledge.broadcom.com/external/article/320837/using-the-lsdoctor-tool.html'
    TRUST_ANCHORS_CHECK_URI_IP = \
        'One or more vCenter/PSC nodes have Lookup Service registrations\n' \
        'using the IP address instead of the PNID in the endpoint URIs.\n' \
        'These can be fixed with the lsdoctor utility:\n' \
        'https://knowledge.broadcom.com/external/article/320837/using-the-lsdoctor-tool.html'
    TRUST_ANCHORS_CHECK_URI_OTHER = \
        'One or more vCenters have no Lookup Service registration endpoints\n' \
        'using the current hostname or IP address. There could be registrations\n' \
        'for these vCenters using a different hostname or IP address.\n' \
        'These can be fixed with the lsdoctor utility: \n' \
        'https://knowledge.broadcom.com/external/article/320837/using-the-lsdoctor-tool.html'
    TRUST_ANCHORS_CHECK_PENDING = \
        'The current Machine SSL certificate is not being served on port\n' \
        '443 due to a pending service restart\n'


def check_certificate_dummy(**_):
    print_text_error('=== Unsupported check certificate operation! ===')


def get_check_options(store, is_solution_user):
    """
    Get check options based on VECS store name or solution user

    :param store: VECS store name
    :param is_solution_user: whether the certificate is solution user certificate
    :return: list of check option
    """
    if store == 'MACHINE_SSL_CERT':
        options = ['CHECK_PNID', 'CHECK_KU', 'CHECK_SAN', 'CHECK_CA_CHAIN', 'CHECK_EMBEDDED_CHAIN', 'CHECK_ROGUE_CA']
    elif store == 'SMS':
        options = []
    else:
        options = ['CHECK_KU', 'CHECK_SAN', 'CHECK_CA_CHAIN', 'CHECK_EMBEDDED_CHAIN', 'CHECK_ROGUE_CA']
        if is_solution_user:
            options.append('CHECK_SERVICE_PRINCIPAL')
            if store in ['wcp', 'wcpsvc']:
                options.remove('CHECK_SAN')
    return options


def check_vecs_certificate(store, alias, is_solution_user=False):
    """
    Check specific certificate in VECS

    :param store: VECS store name
    :param alias: certificate alias
    :param is_solution_user: whether the certificate is solution user certificate
    """
    logger.info("Checking VECS certificate: store {}, alias {}".format(store, alias))
    options = get_check_options(store, is_solution_user)
    logger.info("Check options: {}".format(options))
    aliases = vecs.get_certificate_aliases(store)
    if alias not in aliases:
        add_certificate_status(CertificateStatus.CERT_STATUS_MISSING)
        print_task_status_error('NOT FOUND')
        logger.error("Certificate for alias {} was not found in store {}".format(alias, store))
        return

    pem_cert = vecs.get_certificate(store, alias)
    if not pem_cert:
        print_task_status_error('PROBLEM')
        logger.error("Failed to obtain certificate for alias {} in store {}".format(alias, store))
        return

    cert = get_x509_certificate(pem_cert)
    days_left = get_certificate_expiry_in_days(cert)
    cert_desc = "Certificate for alias {} in store {}".format(alias, store)
    if days_left < 0:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED)
        print_task_status_warning('EXPIRED')
        logger.warning("{} is expired".format(cert_desc))
        return
    elif days_left < 30:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRES_SOON)
        print_task_status_warning("{} DAYS".format(days_left))
        logger.info("{} will expire in {} days".format(cert_desc, days_left))
        return

    extensions = get_certificate_extensions(cert)
    env = Environment.get_environment()
    if 'CHECK_PNID' in options:
        pnid = env.get_value('PNID')
        san = extensions.get('subjectAltName')
        if san is None or pnid not in san:
            add_certificate_status(CertificateStatus.CERT_STATUS_MISSING_PNID, pnid)
            print_task_status_warning('NO PNID')
            logger.warning("{} does not have the PNID {} in the Subject Alternative Name field".format(cert_desc, pnid))
            return

    if 'CHECK_KU' in options:
        if not check_key_usage(cert, "{}:{}".format(store, alias)):
            add_certificate_status(CertificateStatus.CERT_STATUS_KEY_USAGE)
            print_task_status_warning('KEY USAGE')
            logger.warning("{} does not have the expected Key Usage values".format(cert_desc))
            return

    if 'CHECK_SAN' in options:
        san = extensions.get('subjectAltName')
        if not san:
            add_certificate_status(CertificateStatus.CERT_STATUS_MISSING_SAN)
            print_task_status_warning('NO SAN')
            logger.warning("{} has no values in Subject Alternative Name field".format(cert_desc))
            return

    if 'CHECK_SERVICE_PRINCIPAL' in options:
        fingerprint1 = get_certificate_fingerprint(cert, 'sha1')
        solution_user_cert = vmdir.get_solution_user_certificate(store)
        fingerprint2 = get_certificate_fingerprint(get_x509_certificate(solution_user_cert), 'sha1')
        if fingerprint1 != fingerprint2:
            add_certificate_status(CertificateStatus.CERT_STATUS_MISMATCH_SERVICE_PRINCIPAL)
            print_task_status_warning('MISMATCH')
            logger.warning("{} does not match the certificate for the corresponding Service Principal "
                           "in VMware Directory".format(cert_desc))
            return

    if 'CHECK_CA_CHAIN' in options:
        if check_missing_ca(pem_cert):
            add_certificate_status(CertificateStatus.CERT_STATUS_MISSING_CA)
            print_task_status_warning('MISSING CA')
            logger.warning("{} is missing one of the CA certificates in the certificate chain".format(cert_desc))
            return

    if 'CHECK_EMBEDDED_CHAIN' in options:
        pem_certs = split_certificates_from_pem(pem_cert)
        pem_certs = pem_certs[1:]
        for pem in pem_certs:
            x509_cert = get_x509_certificate(pem)
            sha1_fingerprint = get_certificate_fingerprint(x509_cert)
            logger.info("Checking embedded CA certificate with SHA1 fingerprint {}".format(sha1_fingerprint))
            days_left = get_certificate_expiry_in_days(x509_cert)
            if days_left < 0:
                add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED_EMBEDDED_CA)
                print_task_status_warning('EMBEDDED CA')
                logger.warning("The embedded CA certificate is expired:\n{}".format(pem))
                return

    if 'CHECK_ROGUE_CA' in options:
        is_rogue_cert, _ = check_rogue_ca(pem_cert)
        if is_rogue_cert:
            add_certificate_status(CertificateStatus.CERT_STATUS_ROGUE_CA)
            print_task_status_warning('ROGUE')
            logger.warning("The certificate is invalid because of a CA that extends beyond a parent CA path length restriction:\n")
            return

    if not check_signature_algorithm(cert):
        add_certificate_status(CertificateStatus.CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM)
        print_task_status_warning('ALGORITHM')
        logger.warning("{} is signed with unsupported signature algorithm".format(cert_desc))
    else:
        print_task_status('VALID')


def check_signature_algorithm(x509_cert):
    """
    Check if the signature algorithm is supported

    :param x509_cert: X509Certificate object
    :return: True if the signature algorithm is supported
    """
    unsupported_signature_algs = ['md2WithRSAEncryption', 'md5WithRSAEncryption', 'RSASSA-PSS', 'dsaWithSHA1',
                                  'ecdsa_with_SHA1', 'sha1WithRSAEncryption']
    sign_alg = x509_cert.get_signature_algorithm().decode('utf-8')
    logger.info("Checking certificate signature algorithm {} against unsupported signature algorithms {}"
                .format(sign_alg, unsupported_signature_algs))
    return False if sign_alg in unsupported_signature_algs else True


def check_key_usage(x509_cert, cert_desc):
    """
    Check certificate keyUsage extension and validate that all keyUsage are in the supported list

    :param x509_cert: X509Certificate object
    :param cert_desc: Certificate description (for logging)
    :return: True if all keyUsages are supported
    """
    supported_kus = ['Digital Signature', 'Key Encipherment', 'Key Agreement', 'Data Encipherment',
                     'Non Repudiation']
    logger.info("Checking Key Usage for cert {} among supported values of: {}".format(cert_desc, supported_kus))
    extensions = get_certificate_extensions(x509_cert)
    kus = extensions.get('keyUsage', '').split(', ')
    for ku in kus:
        if ku not in supported_kus:
            logger.warning("Found unsupported Key Usage value: {}".format(ku))
            return False
    return True


def check_certificate_basic(cert):
    """
    Some basic checks on certificate
    :param cert: X509Certificate
    """
    x509_cert = get_x509_certificate(cert)
    days_left = get_certificate_expiry_in_days(x509_cert)
    if days_left < 0:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED)
        print_task_status_warning('EXPIRED')
        logger.warning("Certificate is expired")
        return
    elif days_left < 30:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRES_SOON)
        print_task_status_warning("{} DAYS".format(days_left))
        logger.warning("Certificate expires in {} days".format(days_left))
        return

    if not check_signature_algorithm(x509_cert):
        add_certificate_status(CertificateStatus.CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM)
        print_task_status_warning('ALGORITHM')
        logger.warning("Certificate is signed with unsupported signature algorithm")
        return

    if is_ca_certificate(x509_cert):
        skid = get_subject_keyid(x509_cert)
        if not skid:
            add_certificate_status(CertificateStatus.CERT_STATUS_CA_MISSING_SKID)
            print_task_status_warning('NO SKID')
            return

    print_task_status('VALID')


def check_file_system_certificate(file):
    """
    Check certificate file stored on file system

    :param file: Path of the certificate file
    :return:
    """
    if not is_file_exists(file):
        add_certificate_status(CertificateStatus.CERT_STATUS_MISSING)
        print_task_status_warning('NOT FOUND')
        logger.error("Certificate at {} could not be found".format(file))
        return

    logger.info("Checking certificate at {}".format(file))
    pem_cert = get_file_contents(file)
    check_certificate_basic(pem_cert)


def check_certificate_status():
    """
    Entry point for check certificate status operation
    """
    env = Environment.get_environment()
    print_task('Checking Machine SSL certificate')
    check_vecs_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')

    aliases = vecs.get_certificate_aliases('MACHINE_SSL_CERT')
    if '__MACHINE_CSR' in aliases:
        print_task('Checking Machine SSL CSR')
        check_vecs_certificate('MACHINE_SSL_CERT', '__MACHINE_CSR')

    print('Checking Solution User certificates:')
    solution_users = env.get_value('SOLUTION_USERS')
    for sol_user in solution_users:
        print_task("   {}".format(sol_user))
        check_vecs_certificate(sol_user, sol_user, is_solution_user=True)

    vc_version = get_vc_version()

    print_task('Checking SMS self-signed certificate')
    check_vecs_certificate('SMS', 'sms_self_signed')
    if vc_version >= VcVersion.V8:
        print_task('Checking SMS VMCA-signed certificate')
        check_vecs_certificate('SMS', 'sps-extension')

    print_task('Checking data-encipherment certificate')
    check_vecs_certificate('data-encipherment', 'data-encipherment')

    print_task('Checking Authentication Proxy certificate')
    check_file_system_certificate(VMCA_CERT_FILE_PATH)

    print_task('Checking Auto Deploy CA certificate')
    check_file_system_certificate(RBD_CERT_FILE_PATH)

    cert_file = '/usr/lib/vmware-vmdir/share/config/vmdircert.pem'
    if is_file_exists(cert_file):
        print_task('Checking VMDir certificate')
        check_file_system_certificate(cert_file)

    store_list = vecs.get_store_list()
    if 'BACKUP_STORE' in store_list:
        print('Checking BACKUP_STORE entries:')
        for alias in vecs.get_certificate_aliases('BACKUP_STORE'):
            print_task("   {}".format(alias))
            check_vecs_certificate('BACKUP_STORE', alias)

    if 'BACKUP_STORE_H5C' in store_list:
        print_task('Checking BACKUP_STORE_H5C entries:')
        for alias in vecs.get_certificate_aliases('BACKUP_STORE_H5C'):
            print_task("   {}".format(alias))
            check_vecs_certificate('BACKUP_STORE_H5C', alias)

    if 'STS_INTERNAL_SSL_CERT' in store_list:
        print_task('Checking legacy Lookup Service certificate')
        check_vecs_certificate('STS_INTERNAL_SSL_CERT', '__MACHINE_CERT')

    print_task('Checking VMCA certificate')
    check_file_system_certificate(VMCA_CERT_FILE_PATH)


def check_sts_tenant_certificates():
    """
    Entry point for STS Tenant certificates check
    """
    certs_map = vmdir.get_sts_tenant_certificates()
    for tenant in certs_map.keys():
        print("Checking {}:".format(tenant))
        for pem_cert in certs_map[tenant]:
            x509_cert = get_x509_certificate(pem_cert)
            check_sts_tenant_certificate(x509_cert, tenant)


def check_sts_tenant_certificate(x509_cert, tenant):
    """
    Check specific STS tenant certificate

    :param x509_cert:  X509Certificate object
    :param tenant: Tenant name (for output message)
    """
    is_ca = is_ca_certificate(x509_cert)
    print_task("   {} {} certificate".format(tenant, 'CA' if is_ca else 'signing'))

    cert_desc = "STS tenant certificate {}".format(tenant)
    days_left = get_certificate_expiry_in_days(x509_cert)
    if days_left < 0:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED)
        print_task_status_warning('EXPIRED')
        logger.warning("{} is expired".format(cert_desc))
        return
    if is_ca:
        skid = get_subject_keyid(x509_cert, remove_colons=True)
        if not vmdir.get_ca_certificate(skid):
            add_certificate_status(CertificateStatus.CERT_STATUS_MISSING_VMDIR)
            print_task_status_warning('MISSING')
            logger.warning("{} is missing from VMDir".format(cert_desc))
            return
    elif not check_key_usage(x509_cert, 'STS Tenant'):
        add_certificate_status(CertificateStatus.CERT_STATUS_KEY_USAGE)
        print_task_status_warning('KEY USAGE')
        return
    if not check_signature_algorithm(x509_cert):
        add_certificate_status(CertificateStatus.CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM)
        print_task_status_warning('ALGORITHM')
        logger.warning("{}is signed with unsupported signature algorithm".format(cert_desc))
        return

    if days_left < 30:
        add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRES_SOON)
        print_task_status_warning("{} DAYS".format(days_left))
        logger.warning("{} expires in {} days".format(cert_desc, days_left))
    else:
        print_task_status('VALID')


def check_ca_certificates_in_vmdir():
    """
    Entry point for CA certificates check in VMDir
    """
    logger.info('Checking CA certificates in VMDir')
    subject_keyids = vmdir.get_all_ca_subject_keyids()
    for subject_keyid in subject_keyids:
        logger.info("Checking certificate with CN(id) {}".format(subject_keyid))
        pem_cert = vmdir.get_ca_certificate(subject_keyid)
        print_task(subject_keyid)
        cert = get_x509_certificate(pem_cert)
        extensions = get_certificate_extensions(cert)
        days_left = get_certificate_expiry_in_days(cert)
        cert_subject_keyid = get_subject_keyid(cert)
        basic_constraints = extensions.get('basicConstraints')
        cert_desc = "Certificate with CN(id) {}".format(subject_keyid)
        is_rogue_ca, _ = check_rogue_ca(pem_cert)
        if days_left < 0:
            add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED)
            print_task_status_warning('EXPIRED')
            logger.warning("{} is expired".format(cert_desc))
        elif basic_constraints is None or 'CA:TRUE' not in basic_constraints:
            add_certificate_status(CertificateStatus.CERT_STATUS_NON_CA)
            print_task_status_warning('NON-CA')
            logger.warning("{} is not a CA certificate".format(cert_desc))
        elif is_rogue_ca:
            add_certificate_status(CertificateStatus.CERT_STATUS_ROGUE_CA)
            print_task_status_warning('ROGUE')
            logger.warning("{} violates the path length restriction of a parent CA certificate".format(cert_desc))
        elif check_duplicate_ca(pem_cert):
            add_certificate_status(CertificateStatus.CERT_STATUS_DUPLICATE_CA)
            print_task_status_warning('DUPLICATE')
            logger.warning("{} has a duplicate Subject string with one or more CA certificates".format(cert_desc))
        elif not cert_subject_keyid:
            add_certificate_status(CertificateStatus.CERT_STATUS_CA_MISSING_SKID)
            print_task_status_warning('NO SKID')
            logger.warning("{} does not have Subject Key Id".format(cert_desc))
        elif days_left < 30:
            add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRES_SOON)
            print_task_status_warning("{} DAYS".format(days_left))
            logger.warning("{} expires in {} days".format(cert_desc, days_left))
        else:
            print_task_status('VALID')


def check_ca_certificates_in_vecs():
    """
    Entry point for CA certificates check in VECS
    """
    logger.info('Checking CA certificates in VECS')
    pem_certs, aliases = vecs.get_all_ca_certificates()
    for pem_cert, alias in zip(pem_certs, aliases):
        logger.info("Checking certificate with alias {}".format(alias))
        print_task(alias)
        cert = get_x509_certificate(pem_cert)
        basic_constraints = get_certificate_extensions(cert).get('basicConstraints')
        days_left = get_certificate_expiry_in_days(cert)
        cert_desc = "Certificate with alias {}".format(alias)
        is_rogue_ca, _ = check_rogue_ca(pem_cert)
        if days_left < 0:
            add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRED)
            print_task_status_warning('EXPIRED')
            logger.warning("{} is expired".format(cert_desc))
        elif basic_constraints is None or 'CA:TRUE' not in basic_constraints:
            add_certificate_status(CertificateStatus.CERT_STATUS_NON_CA)
            print_task_status_warning('NON-CA')
            logger.warning("{} is not a CA certificate".format(cert_desc))
        elif is_rogue_ca:
            add_certificate_status(CertificateStatus.CERT_STATUS_ROGUE_CA)
            print_task_status_warning('ROGUE')
            logger.warning("{} violates the path length restriction of a parent CA certificate".format(cert_desc))
        elif check_duplicate_ca(pem_cert):
            add_certificate_status(CertificateStatus.CERT_STATUS_DUPLICATE_CA)
            print_task_status_warning('DUPLICATE')
            logger.warning("{} has a duplicate Subject string with one or more CA certificates".format(cert_desc))
        elif alias != get_certificate_fingerprint(cert, remove_colons=True).lower():
            add_certificate_status(CertificateStatus.CERT_STATUS_BAD_ALIAS)
            print_task_status_warning('BAD ALIAS')
            logger.warning("{} is registered using a bad alias".format(cert_desc))
        elif days_left < 30:
            add_certificate_status(CertificateStatus.CERT_STATUS_EXPIRES_SOON)
            print_task_status_warning("{} DAYS".format(days_left))
            logger.warning("{} expires in {} days".format(cert_desc, days_left))
        else:
            print_task_status('VALID')


def check_service_principals():
    """
    Entry point for service principals check
    """
    logger.info('Checking service principals in VMware Directory')
    service_principals = vmdir.get_service_principals()
    if not service_principals:
        print_task('Listing SSO Service Principals')
        print_task_status_warning('FAILED')
        logger.error('Could not get list of Service Principal entries from VMware Directory')
        return

    env = Environment.get_environment()
    machine_id = env.get_value('MACHINE_ID')
    solution_users = env.get_value('SOLUTION_USERS')
    print("Node {}:".format(machine_id))
    for solution_user in solution_users:
        print_task("   {}".format(solution_user))
        if "{}-{}".format(solution_user, machine_id) in service_principals:
            print_task_status('PRESENT')
        else:
            print_task_status_warning('MISSING')
            add_certificate_status(CertificateStatus.CERT_STATUS_SERVICE_PRINCIPAL_MISSING)
            logger.warning("Missing service principal {} in VMware Directory".format(solution_user))


def check_crls():
    """
    Check Certificate Revocation List in VECS
    """
    logger.info("Checking the number of CRLS in VECS")
    num_entries = len(vecs.get_certificate_aliases('TRUSTED_ROOT_CRLS'))
    print_task('Number of CRLs in VECS')
    if num_entries < 30:
        print_task_status(num_entries)
    elif num_entries < 100:
        print_task_status_warning(num_entries)
    else:
        print_task_status_error(num_entries)
        add_certificate_status(CertificateStatus.CERT_STATUS_TOO_MANY_CRLS)
    logger.info("Number of CRLs in VECS: {}".format(num_entries))


def get_ids_domain_and_certificates(identity_sources, source_type):
    result = []
    for source in identity_sources:
        if source['type'] == source_type:
            result.append((source['domain_name'], source['certificates']))
    return result


def get_ids_domain_and_certificates_by_domain(identity_sources, source_type, source_domain):
    result = []
    for source in identity_sources:
        if source['type'] == source_type and source['domain_name'] == source_domain:
            result.append((source['domain_name'], source['certificates']))
    return result


def check_identity_source_certificates():
    """
    Entry point for checking identity source certificates
    """
    logger.info('Checking identity source certificates')

    env = Environment.get_environment()
    is_cac_configured = env.get_value('CAC_CONFIGURED')

    if is_cac_configured:
        check_smart_card_filter_file_certs()
        check_smart_card_vmdir_certs()

    identity_sources = vmdir.get_identity_sources()

    # OpenLDAP
    domain_and_certs = get_ids_domain_and_certificates(identity_sources, 'OpenLDAP')
    if domain_and_certs:
        print_header('Checking OpenLDAP LDAPS certificates')
        for domain_name, certificates in domain_and_certs:
            print("Domain: {}".format(domain_name))
            for index, cert in enumerate(certificates, 1):
                print_task("   Certificate {}".format(index))
                check_certificate_basic(cert)

    # AD over LDAP
    domain_and_certs = get_ids_domain_and_certificates(identity_sources, 'AD over LDAP')
    if domain_and_certs:
        print_header('Checking AD over LDAPS certificates')
        for domain_name, certificates in domain_and_certs:
            print("Domain: {}".format(domain_name))
            for index, cert in enumerate(certificates, 1):
                print_task("   Certificate {}".format(index))
                check_certificate_basic(cert)

    # ADFS
    domain_and_certs = get_ids_domain_and_certificates(identity_sources, 'ADFS')
    if domain_and_certs:
        print_header('Checking ADFS certificates')
        for _, certificates in domain_and_certs:
            for index, cert in enumerate(certificates, 1):
                print_task("Certificate {}".format(index))
                check_certificate_basic(cert)


def check_smart_card_filter_file_certs():
    print_header('Check Smart Card Issuing CA Filter File')
    print_task('Check CA Filter File')

    env = Environment.get_environment()
    cac_filter_file = env.get_value('SMART_CARD_FILTER_FILE')

    if not is_file_exists(cac_filter_file):
        print_task_status_warning('MISSING')
        add_certificate_status(CertificateStatus.CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING, cac_filter_file)
    else:
        pem = get_file_contents(cac_filter_file)
        filter_certs = split_certificates_from_pem(pem)

        if not filter_certs:
            print_task_status_warning('EMPTY')
            add_certificate_status(CertificateStatus.CERT_STATUS_CLIENT_CA_LIST_FILE_EMPTY, cac_filter_file)
            return
        
        print_task_status('OK')
        for index, cert in enumerate(filter_certs, 1):
            print_task("Certificate {}".format(index))
            check_certificate_basic(cert)        


def check_smart_card_vmdir_certs():
    print_header('Check VMDir Smart Card Issuing CA Certificates')
    cac_ca_certs = vmdir.get_smart_card_issuing_ca_certs()
    for index, cert in enumerate(cac_ca_certs, 1):
            print_task("Certificate {}".format(index))
            check_certificate_basic(cert)


def check_ssl_trust_anchors():
    """
    Check if trust anchor certificates are match to server SSL certificate by
    calculating the certificate thumbprints

    Note: This check seems not correct. The check should be a certificate chain
    validation using the trust anchor, not just leaf certificate thumbprint
    comparison.
    """
    logger.info("Checking SSL trust anchors")
    env = Environment.get_environment()
    hostname = env.get_value('HOSTNAME')
    sso_domain_nodes = vmdir.get_sso_domain_nodes()
    is_mismatch = False
    is_using_ip_address = False
    is_pending = False
    for node in sso_domain_nodes:
        print_task(node)
        try:
            pem_cert = get_certificate_from_host(node, 443)
            x509_cert = get_x509_certificate(pem_cert)
            node_thumbprint = get_certificate_fingerprint(x509_cert)
        except OpenSSL.crypto.Error:
            add_certificate_status(CertificateStatus.TRUST_ANCHORS_UNKNOWN)
            unknown_nodes = env.get_value('TRUST_ANCHORS_UNKNOWN_NODES')
            if unknown_nodes is None:
                unknown_nodes = []
                env.set_value('TRUST_ANCHORS_UNKNOWN_NODES', unknown_nodes)
            unknown_nodes.append(node)
            print_task_status_warning('UNKNOWN')
            continue

        ip_address = get_ip_address(node)
        trust_anchors = vmdir.get_node_trust_anchors(node)
        if not trust_anchors:
            is_using_ip_address = True
            trust_anchors = vmdir.get_node_trust_anchors(ip_address)

        if not trust_anchors:
            add_certificate_status(CertificateStatus.TRUST_ANCHORS_CHECK_URI_OTHER)
            print_task_status_warning('MISSING')
            continue

        for cert_entry in trust_anchors:
            pem_cert = build_pem_certificate(cert_entry)
            fingerprint = get_certificate_fingerprint(get_x509_certificate(pem_cert))
            logger.info("Checking node thumbprint {} against trust anchor thumbprint {}"
                        .format(node_thumbprint, fingerprint))
            if fingerprint != node_thumbprint:
                if node == hostname or node == ip_address:
                    machine_ssl_cert = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')
                    x509_machine_ssl_cert = get_x509_certificate(machine_ssl_cert)
                    machine_ssl_thumbprint = get_certificate_fingerprint(x509_machine_ssl_cert)
                    if fingerprint == machine_ssl_thumbprint:
                        is_pending = True                        
                else:
                    is_mismatch = True

        logger.info("Searching for ghost trust anchors")
        vcs = vmdir.get_registered_vcenters()
        for deployment_id, dn in vcs:
            uris = '\n'.join(vmdir.get_endpoint_registrations(dn))
            pattern = ".*https://{0}/.*|.*https://{0}:.*|.*https://{1}/.*|.*https://{1}:.*".format(node, ip_address)
            if not re.match(pattern, uris):
                continue

            logger.debug("Found vCenter registration for {}: {}".format(node, deployment_id))
            ghost_vmonapi_dn = get_ghost_vmonapi_dn(deployment_id)
            if not ghost_vmonapi_dn:
                continue

            logger.debug("cis.vmonapi registration DN: {}".format(ghost_vmonapi_dn))
            trust_anchors = get_ghost_vmonapi_trust_anchors(ghost_vmonapi_dn)
            for cert in trust_anchors:
                pem_cert = build_pem_certificate(cert)
                x509_cert = get_x509_certificate(pem_cert)
                fingerprint = get_certificate_fingerprint(x509_cert)
                logger.info("Checking node thumbprint {} against trust anchor thumbprint {}"
                            .format(node_thumbprint, fingerprint))
                if node_thumbprint != fingerprint:
                    if node == hostname or node == ip_address:
                        machine_ssl_cert = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')
                        x509_machine_ssl_cert = get_x509_certificate(machine_ssl_cert)
                        machine_ssl_thumbprint = get_certificate_fingerprint(x509_machine_ssl_cert)
                        if fingerprint == machine_ssl_thumbprint:
                            is_pending = True                        
                    else:
                        is_mismatch = True

        if is_mismatch:
            add_certificate_status(CertificateStatus.TRUST_ANCHORS_MISMATCH)
            if is_using_ip_address:
                add_certificate_status(CertificateStatus.TRUST_ANCHORS_CHECK_URI_MISMATCH)
                print_task_status_warning('MISMATCH*')
            else:
                print_task_status_warning('MISMATCH')
        elif is_pending:
            print_task_status_warning('PENDING')
            add_certificate_status(CertificateStatus.TRUST_ANCHORS_CHECK_PENDING)
        else:
            if is_using_ip_address:
                add_certificate_status(CertificateStatus.TRUST_ANCHORS_CHECK_URI_OTHER)
                print_task_status_warning('CHECK URI')
            else:
                print_task_status('VALID')


def get_ghost_vmonapi_dn(deployment_id):
    domain_dn = Environment.get_environment().get_value("SSO_DOMAIN_DN")
    search_base = "cn=Sites,cn=Configuration,{}".format(domain_dn)
    search_filter = "(&(vmwLKUPType=cis.vmonapi)(vmwLKUPDeploymentNodeId={}))".format(deployment_id)
    search_attributes = ['dn']
    results = vmdir.perform_ldap_search(search_base, search_filter, search_attributes)
    return results[0]['dn'] if results else ''


def get_ghost_vmonapi_trust_anchors(vmonapi_dn):
    search_filter = '(vmwLKUPURI=http://localhost*)'
    search_attributes = ['vmwLKUPEndpointSslTrust']
    results = vmdir.perform_ldap_search(vmonapi_dn, search_filter, search_attributes)
    trust_anchors = []
    for entry in results:
        trust_anchors.extend(entry['vmwLKUPEndpointSslTrust'])
    return trust_anchors


def check_vcenter_extension_thumbprints():
    """
    Entry point for certificate check on vcenter extension thumbprints
    """
    if not is_service_running('vmware-vpostgres'):
        print_text_error('The vPostgres service is stopped!\n'''
                         'Please ensure this service is running before updating vCenter extension thumbprints.\n'
                         'Hint: Check the number of CRL entries in VECS')
        return None

    vcenter_extensions = get_vcenter_extensions()
    extension_thumbprints = vcdb.get_extension_thumbprints(vcenter_extensions)
    expected_thumbprints = get_vcenter_extension_expected_thumbprints(vcenter_extensions)

    check_result = True
    for extension, (thumbprint, db_cert_pem) in extension_thumbprints.items():
        expected_thumbprint, expected_cert_type, expected_cert_pem = expected_thumbprints[extension]
        print_task("{} ({})".format(extension, expected_cert_type))
        logger.info("Comparing {} thumbprint of {} to {}".format(extension, thumbprint, expected_thumbprint))
        if get_vc_version() < VcVersion.V9:
            if thumbprint == expected_thumbprint:
                print_task_status('MATCHES')
            else:
                print_task_status_warning('MISMATCH')
                check_result = False
        else:
            if thumbprint == expected_thumbprint and db_cert_pem == expected_cert_pem:
                print_task_status('MATCHES')
            else:
                print_task_status_warning('MISMATCH')
                check_result = False
    return check_result


def add_certificate_status(cert_status, detail=None):
    env = Environment.get_environment()
    results = env.get_value('CERTIFICATE_CHECK_RESULT')
    if results is None:
        results = []
        env.set_value('CERTIFICATE_CHECK_RESULT', results)
    if cert_status not in [r[0] for r in results]:
        results.append([cert_status, detail])


def reset_certificate_status():
    env = Environment.get_environment()
    env.set_value('CERTIFICATE_CHECK_RESULT', None)
    env.set_value('TRUST_ANCHORS_UNKNOWN_NODES', None)


def show_check_result_summary():
    env = Environment.get_environment()
    results = env.get_value('CERTIFICATE_CHECK_RESULT')
    if not results:
        return
    print_text_error('\n------------------------!!! Attention !!!------------------------')
    for status, detail in results:
        lines = status.value.format_map(env.get_map()).splitlines()
        for idx, line in enumerate(lines):
            print_text_error(' - ' if idx == 0 else '   ', end='')
            if status == CertificateStatus.TRUST_ANCHORS_UNKNOWN:
                for unknown_node in env.get_value('TRUST_ANCHORS_UNKNOWN_NODES'):
                    print_text_error("     {}".format(unknown_node))
            print_text_error(line if not detail else line.replace('>>DETAILS<<', detail))


def check_rogue_ca(pem_cert):
    """
    Check if a certificate is invalid due to a CA extending beyond the
    path length restriction of a parent CA
    :param pem_cert: Base64 certificate hash
    :return  cert_is_rogue: True if certificate is invalid due to a rogue CA, False otherwise, 
             rogue_ca: name of CA in the signing chain that violates the path length restriction
             of a parent CA
    """
    logger.info('Entering the function to check for Rogue CA')
    cert_is_rogue = False
    rogue_ca = ''
    subject_keyids = vmdir.get_all_ca_subject_keyids()
    cert_path = build_certification_path(pem_cert, subject_keyids, vmdir.get_ca_certificate)
    ca_certs_in_path = len(cert_path) if cert_path[-1]['is_ca'] is True else len(cert_path)-1
    for index, cert in enumerate(cert_path):
        logger.info("Checking for path length restrictions on certificate {}".format(cert_path[index]['cert_name']))
        if cert['pathlen'] is not False:
            logger.info("Path length restriction found on certificate {}: {}".format(cert_path[index]['cert_name'], cert_path[index]['pathlen']))
            max_allowed_ca = index + int(cert['pathlen']) + 1
            logger.info("Maximum allowed CAs in the signing chain is: {}".format(max_allowed_ca))
            if ca_certs_in_path > max_allowed_ca:
                cert_is_rogue = True
                rogue_ca = cert_path[max_allowed_ca]['cert_name']
                logger.info("Path length violation found on certificate {}".format(cert_path[max_allowed_ca]['cert_name']))
                break
    return cert_is_rogue, rogue_ca


def check_duplicate_ca(pem_cert):
    """
    Check if there are multiple CA certificates with the same Subject string (but different private key). 
    This can cause certificate validation issues.
    :param pem_cert: Base64 certificate hash
    :return True if there are found to be duplicate certificates with the same Subject string, False otherwise    
    """
    subject_hash = get_subject_hash(pem_cert)
    return True if len(glob.glob("/etc/ssl/certs/{}.[0-9]".format(subject_hash))) > 1 else False


def check_missing_ca(pem_cert, provided_ca_chain=False):
    """
    Check to see if any CA certificates in the signing chain of a cert are missing from VMware Directory

    :param pem_cert: Base64 certificate hash
    :return: True if there is a CA certificate in the signing chain missing from VMware Directory, False otherwise
    """
    ca_is_missing = False
    x509_cert = get_x509_certificate(pem_cert)
    if not provided_ca_chain:
        subject_keyids = vmdir.get_all_ca_subject_keyids()
    else:
        subject_keyids = []
        ca_certs = split_certificates_from_pem(get_file_contents(provided_ca_chain))
        for cert in ca_certs:
            ca_x509 = get_x509_certificate(cert)
            subject_keyids.append(get_authority_keyid(ca_x509, True))
    
    current_keyid = get_authority_keyid(x509_cert, True)
    while True:
        logger.info("Looking for AKID {} in {}".format(current_keyid, subject_keyids))
        if current_keyid not in subject_keyids:
            logger.info("AKID {} was NOT found in {}".format(current_keyid, subject_keyids))
            ca_is_missing = True
            break
        else:
            ca_x509 = get_x509_certificate(vmdir.get_ca_certificate(current_keyid))
            subject_dn, issuer_dn = get_subject_and_issuer_dn(ca_x509)
            # if we've reached the Root CA cert, we're done
            if subject_dn == issuer_dn:
                break
            current_keyid = get_authority_keyid(ca_x509, True)

    return ca_is_missing


def check_ssl_interception():
    """
    Checks to see if SSL interception is occurring between vCenter and one of the online VMware repositories
    """
    print_task("Checking {}".format(VMWARE_DEPOT_HOST))
    depot_certs = split_certificates_from_pem(get_certificate_from_host('hostupdate.vmware.com'))
    if len(depot_certs) == 0:
        print_task_status_warning('FAILED')
        print_text("{}Unable to obtain a certificate for {}".format(ColorKey.YELLOW, VMWARE_DEPOT_HOST))
        print_text("Ensure the remote repository is accessible.{}".format(ColorKey.NORMAL))
        return
    else:
        depot_issuer_cert_name = get_certificate_name(depot_certs[0], 'issuer')
        logger.info("Certificate for {} is issued by {}".format(VMWARE_DEPOT_HOST, depot_issuer_cert_name))
        if depot_issuer_cert_name == VMWARE_DEPOT_CERT_ISSUER:
            print_task_status('OK')
            print()
            print_text("Issuing CA for {} is {}{}{}".format(VMWARE_DEPOT_HOST, ColorKey.GREEN, depot_issuer_cert_name, ColorKey.NORMAL))
            return
        else:
            print_task_status_warning('WARNING')
            print()
            print_text("Issuing CA for {} is {}{}{}".format(VMWARE_DEPOT_HOST, ColorKey.YELLOW, depot_issuer_cert_name, ColorKey.NORMAL))
            print_text("Expected issuer is {}{}{}".format(ColorKey.GREEN, VMWARE_DEPOT_CERT_ISSUER, ColorKey.NORMAL))
            print()
            print_text("{}SSL interception is likely taking place!{}".format(ColorKey.YELLOW, ColorKey.NORMAL))
            env = Environment.get_environment()
            menu = Menu.load_menu_from_config('config/check_config/ssl_interception/menu_manage_ssl_interception.yaml')
            try:
                menu.run()
            except MenuExitException:
                pass
