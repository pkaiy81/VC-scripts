# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import datetime
import os
import pathlib
import re

from OpenSSL.crypto import load_crl, dump_crl, FILETYPE_PEM, FILETYPE_TEXT

from lib import certificate_utils as certutil
from lib import vcdb
from lib import vmdir
from lib import vecs
from lib.certificate_utils import get_x509_certificate
from lib.constants import (
    VCERT_DESC, VMCAM_CERT_FILE_PATH, RBD_CERT_FILE_PATH, RHTTPPROXY_CONFIG_FILE_PATH,
    VMCA_CERT_FILE_PATH, REPORT_FILE_PATH
)
from lib.environment import Environment
from lib.exceptions import CommandExecutionError
from lib.console import init_env_colormap, print_text_warning, print_text_error
from lib.host_utils import is_service_running, get_vc_version, VcVersion, get_file_contents
from lib.text_utils import TextFilter


def write_report(file, text, end='\n', sep=' '):
    print(text, file=file, end=end, sep=sep)
    print(text, end=end, sep=sep)


def generate_header():
    if not is_service_running('vmware-vpostgres'):
        print_text_error(
            'The vPostgres service is stopped!\n'
            'Please ensure this service is running before generating a certificate report.\n'
            'Hint: Check the number of CRL entries in VECS')
        raise CommandExecutionError('vPostgres is not running')
    
    report_path = pathlib.Path(REPORT_FILE_PATH)
    if not os.path.exists(report_path.parent):
        # this may necessary for remote execution on a restricted environment
        report_file_path = str(pathlib.Path('/tmp').joinpath(report_path.relative_to('/')))
    else:
        report_file_path = REPORT_FILE_PATH

    env = Environment.get_environment()
    try:
        file = open(report_file_path, 'w')
        set_report_file(file)
    except IOError as e:
        error_message = "Failed to create report file {}: {}".format(REPORT_FILE_PATH, e)
        print_text_error(error_message)
        raise CommandExecutionError(error_message)

    env.set_value('COLORS_DISABLED', True)
    init_env_colormap()

    write_report(file, '=' * 130)
    write_report(file, 'SSL Certificate Report')
    write_report(file, VCERT_DESC)
    write_report(file, "Host: {}".format(env.get_value('HOSTNAME')))
    write_report(file, "Date: {}".format(datetime.datetime.now().ctime()))
    write_report(file, "Node Type: {}".format(env.get_value('NODE_TYPE')))
    write_report(file, "Version: {}".format(env.get_value('VC_VERSION')))
    write_report(file, "Build: {}".format(env.get_value('VC_BUILD')))
    write_report(file, "Machine ID: {}".format(env.get_value('MACHINE_ID')))
    write_report(file, "PNID: {}".format(env.get_value('PNID')))
    write_report(file, "Certificate Management Mode: {}".format(vcdb.get_certificate_management_mode()))
    write_report(file, '=' * 130)


def report_certificate_details(file, pem_cert, options=None):
    x509_cert = certutil.get_x509_certificate(pem_cert)
    sign_alg = x509_cert.get_signature_algorithm().decode('utf-8')
    subject_kid = certutil.get_subject_keyid(x509_cert)
    extensions = certutil.get_certificate_extensions(x509_cert)

    report_certificate_basic(file, x509_cert)
    write_report(file, "            Signature Algorithm: {}".format(sign_alg))
    write_report(file, "            Subject Key Identifier: {}".format(subject_kid))

    write_report(file, '            Authority Key Identifier:')
    auth_kid_list = get_authority_keyid_list(x509_cert)
    if auth_kid_list:
        for auth_key in auth_kid_list:
            write_report(file, "               |_{}".format(auth_key))
    else:
        akid = certutil.get_authority_keyid(x509_cert)
        if akid:
            write_report(file, "               |_keyid:{}".format(akid))

    write_report(file, '            Key Usage:')
    key_usage = extensions.get('keyUsage')
    if key_usage:
        for ku in key_usage.split(', '):
            write_report(file, "               |_{}".format(ku))

    write_report(file, '            Extended Key Usage:')
    ext_key_usage = extensions.get('extendedKeyUsage')
    if ext_key_usage:
        for ku in ext_key_usage.splitlines():
            write_report(file, "               |_{}".format(ku))

    write_report(file, '            Subject Alternative Name entries:')
    san = extensions.get('subjectAltName')
    if san:
        for entry in san.split(', '):
            if re.match('^[A-Za-z]+: ', entry):
                entry = re.sub('^([A-Za-z]+:) ', '\\1', entry)
            write_report(file, "               |_{}".format(entry))

    write_report(file, '            Other Information:')
    write_report(file, "               |_Is a Certificate Authority: {}"
                 .format('Yes' if certutil.is_ca_certificate(x509_cert) else 'No'))

    auth_keyid_alt = certutil.get_authority_keyid(x509_cert, allow_alternate=True)
    subject_kids_in_vecs = get_subject_keyids_in_vecs()
    subject_kids_in_vmdir = get_subject_keyids_in_vmdir()
    found_in_vecs = auth_keyid_alt in subject_kids_in_vecs
    found_in_vmdir = auth_keyid_alt in subject_kids_in_vmdir
    if not found_in_vmdir and not found_in_vecs:
        status = "No{}".format(' (Self-Signed)' if certutil.is_self_signed_certificate(x509_cert)
                               else '')
    elif found_in_vmdir and not found_in_vecs:
        status = 'Yes, in VMware Directory'
    elif not found_in_vmdir and found_in_vecs:
        status = 'Yes, in VECS'
    else:
        status = 'Yes, in both'
    write_report(file, "               |_Issuing CA in VMware Directory/VECS: {}".format(status))

    if options:
        if 'checkCurrentMachineSSLUsage' in options:
            report_current_machine_ssl_usage(file)
        if 'checkCurrentExtensionThumbprints' in options:
            report_current_extension_thumbprints(file)


def report_certificate_basic(file, x509_cert):
    subject_dn, issuer_dn = certutil.get_subject_and_issuer_dn(x509_cert)
    output_format = '%b %e %H:%M:%S %Y GMT'
    start_date = certutil.get_certificate_start_date(x509_cert).strftime(output_format)
    end_date = certutil.get_certificate_end_date(x509_cert).strftime(output_format)
    fingerprint = certutil.get_certificate_fingerprint(x509_cert)

    write_report(file, "         Issuer: {}".format(issuer_dn))
    write_report(file, "         Subject: {}".format(subject_dn))
    write_report(file, "            Not Before: {}".format(start_date))
    write_report(file, "            Not After : {}".format(end_date))
    write_report(file, "            SHA1 Fingerprint: {}".format(fingerprint))


def report_current_machine_ssl_usage(file):
    machine_cert = certutil.get_certificate_from_host('localhost', 443)
    machine_cert_fingerprint = certutil.get_certificate_fingerprint(get_x509_certificate(machine_cert)) \
        if machine_cert else ''
    write_report(file, "               |_Current certificate used by the reverse proxy: {}"
                 .format(machine_cert_fingerprint))

    vpxd_cert = certutil.get_certificate_from_host('localhost', 8089)
    vpxd_cert_fingerprint = certutil.get_certificate_fingerprint(get_x509_certificate(vpxd_cert)) \
        if vpxd_cert else ''
    write_report(file, "               |_Current certificate used by vCenter (vpxd)   : {}"
                 .format(vpxd_cert_fingerprint))


def report_current_extension_thumbprints(file):
    write_report(file, '               |_Thumbprints in VCDB for extensions that should use the vpxd-extension certificate')
    thumbprint = vcdb.get_extension_thumbprint('com.vmware.vim.eam')
    write_report(file, "                  |_com.vmware.vim.eam     : {}".format(thumbprint))
    thumbprint = vcdb.get_extension_thumbprint('com.vmware.vcIntegrity')
    write_report(file, "                  |_com.vmware.vcIntegrity : {}".format(thumbprint))

    thumbprint = vcdb.get_extension_thumbprint('com.vmware.rbd')
    if thumbprint:
        write_report(file, "                  |_com.vmware.rbd         : {}".format(thumbprint))

    thumbprint = vcdb.get_extension_thumbprint('com.vmware.imagebuilder')
    if thumbprint:
        write_report(file, "                  |_com.vmware.imagebuilder: {}".format(thumbprint))

    if get_vc_version() == VcVersion.V8_0:
        thumbprint = vcdb.get_extension_thumbprint('com.vmware.vlcm.client')
        write_report(file, "                  |_com.vmware.vlcm.client : {}".format(thumbprint))


def report_crl_details(file, pem_text):
    crl = load_crl(FILETYPE_PEM, pem_text)
    output = dump_crl(FILETYPE_TEXT, crl).decode('utf-8')
    issuer = TextFilter(output).contain('Issuer:').cut('Issuer:', [1]).get_text().strip()
    if issuer.startswith('/'):
        issuer = re.sub('/([A-Z]+=)', ', \\1', issuer[1:])
    last_update = TextFilter(output).contain('Last Update:').cut('Update:', [1]).get_text().strip()
    next_update = TextFilter(output).contain('Next Update:').cut('Update:', [1]).get_text().strip()
    sign_alg = TextFilter(output).contain('Signature Algorithm:').head(1).cut('Algorithm:', [1]).get_text().strip()
    write_report(file, "         Issuer: {}".format(issuer))
    write_report(file, "            Last Update: {}".format(last_update))
    write_report(file, "            Next Update: {}".format(next_update))
    write_report(file, "            Signature Algorithm: {}".format(sign_alg))


def get_authority_keyid_list(x509_cert):
    """
    Get Authority KeyId list from X509 certificate

    :param x509_cert: X509Certificate object
    :return: list of  as keyId:, or DirName:.../serial:
    """
    extensions = certutil.get_certificate_extensions(x509_cert)
    akid = extensions.get('authorityKeyIdentifier')
    if akid:
        return TextFilter(akid).match('^keyid:.*|^DirName:.*|^serial:.*').get_lines()
    else:
        return []


def get_subject_keyids_in_vecs(pem_certs=None):
    env = Environment.get_environment()
    subject_kids = env.get_value('SUBJECT_KEYIDS_IN_VECS')
    if subject_kids is not None:
        return subject_kids
    if pem_certs is None:
        pem_certs, _ = vecs.get_all_ca_certificates()
    subject_kids = []
    for pem_cert in pem_certs:
        x509_cert = get_x509_certificate(pem_cert)
        subject_kids.append(certutil.get_subject_keyid(x509_cert, allow_alternate=True))

    env.set_value('SUBJECT_KEYIDS_IN_VECS', subject_kids)
    return subject_kids


def get_subject_keyids_in_vmdir(pem_certs=None):
    env = Environment.get_environment()
    subject_kids = env.get_value('SUBJECT_KEYIDS_IN_VMDIR')
    if subject_kids is not None:
        return subject_kids
    if pem_certs is None:
        pem_certs, _ = vmdir.get_all_ca_certificates()
    subject_kids = []
    for pem_cert in pem_certs:
        x509_cert = get_x509_certificate(pem_cert)
        subject_kids.append(certutil.get_subject_keyid(x509_cert, allow_alternate=True))

    env.set_value('SUBJECT_KEYIDS_IN_VMDIR', subject_kids)
    return subject_kids


def generate_report_ca_certs_in_vmdir():
    file = get_report_file()
    write_report(file, 'VMware Directory Certificates')
    write_report(file, '   CA Certificates')
    pem_certs, aliases = vmdir.get_all_ca_certificates()
    get_subject_keyids_in_vmdir(pem_certs)
    get_subject_keyids_in_vecs()
    for pem_cert, alias in zip(pem_certs, aliases):
        write_report(file, "      CN(id): {}".format(alias))
        report_certificate_details(file, pem_cert)


def generate_report_ca_certs_in_vecs():
    file = get_report_file()
    write_report(file, 'VECS Certificates')
    get_subject_keyids_in_vecs()
    get_subject_keyids_in_vmdir()
    for store in vecs.get_store_list():
        if store == 'APPLMGMT_PASSWORD':
            continue
        write_report(file, "   Store: {}".format(store))
        pem_certs, aliases = vecs.get_all_certificates(store)
        for pem_text, alias in zip(pem_certs, aliases):
            write_report(file, "      Alias: {}".format(alias))
            if store == 'TRUSTED_ROOT_CRLS':
                report_crl_details(file, pem_text)
            else:
                if store == 'MACHINE_SSL_CERT' and alias == '__MACHINE_CERT':
                    options = ['checkCurrentMachineSSLUsage']
                elif store == 'vpxd-extension' and alias == 'vpxd-extension':
                    options = ['checkCurrentExtensionThumbprints']
                else:
                    options = None
                report_certificate_details(file, pem_text, options)


def generate_report_solution_user_certs_in_vmdir():
    file = get_report_file()
    write_report(file, '   Service Principal (Solution User) Certificates')
    solution_users = vmdir.get_solution_users()
    machine_id = Environment.get_environment().get_value('MACHINE_ID')
    for solution_user in solution_users:
        write_report(file, "      Service Principal: {}-{}".format(solution_user, machine_id))
        pem_cert = vmdir.get_solution_user_certificate(solution_user)
        report_certificate_details(file, pem_cert)


def generate_report_sts_tenant_certs():
    file = get_report_file()
    write_report(file, '   Single Sign-On Secure Token Service Certificates')
    tenant_certs = vmdir.get_sts_tenant_certificates()
    for tenant in tenant_certs.keys():
        certs = tenant_certs[tenant]
        for cert in certs:
            x509_cert = get_x509_certificate(cert)
            cert_type = 'CA Certificate' if certutil.is_ca_certificate(x509_cert) else 'Signing Certificate'
            write_report(file, "      {} {}".format(tenant, cert_type))
            report_certificate_details(file, cert)


def generate_report_certs_in_filesystem():
    file = get_report_file()
    write_report(file, 'Filesystem Certificates')

    write_report(file, '   VMCA Certificate')
    write_report(file, "      Certificate: {}".format(VMCAM_CERT_FILE_PATH))
    pem_cert = get_file_contents(VMCA_CERT_FILE_PATH)
    report_certificate_details(file, pem_cert)

    write_report(file, '   Authentication Proxy Certificate')
    write_report(file, "      Certificate: {}".format(VMCAM_CERT_FILE_PATH))
    pem_cert = get_file_contents(VMCAM_CERT_FILE_PATH)
    report_certificate_details(file, pem_cert)

    write_report(file, '   Auto Deploy CA Certificate')
    write_report(file, "      Certificate: {}".format(RBD_CERT_FILE_PATH))
    pem_cert = get_file_contents(RBD_CERT_FILE_PATH)
    report_certificate_details(file, pem_cert)

    config = get_file_contents(RHTTPPROXY_CONFIG_FILE_PATH)
    cert_file = TextFilter(config).match('.*<clientCAListFile>.*</clientCAListFile>.*')\
        .set_options(invert_match=True).contain('<!--').get_text().strip()
    if cert_file:
        write_report(file, '   Smart Card Whitelist Certificates')
        cert_file = TextFilter(config).cut('clientCAListFile', [1])[1:-2].strip()
        file_content = get_file_contents(cert_file)
        certs = TextFilter(file_content).match_block(
            '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----',
            True).get_lines()
        for index, cert in enumerate(certs, 1):
            write_report(file, "      Certificate {}".format(index))
            report_certificate_details(file, cert)


def generate_report_ca_certs_sca():
    file = get_report_file()
    certs = vmdir.get_smart_card_issuing_ca_certs()
    if certs:
        write_report(file, '   Smart Card Issuing CA Certificates')
        for index, cert in enumerate(certs, 1):
            write_report(file, "      Smart Card Issuing CA {}".format(index))
            report_certificate_details(file, certutil.build_pem_certificate(cert))


def generate_report_ca_certs_ad_ldaps():
    file = get_report_file()
    identity_sources = vmdir.get_identity_sources()
    certs = []
    for source in identity_sources:
        if source['type'] == 'AD over LDAP':
            certs.extend(source['certificates'])
    if certs:
        write_report(file, '   AD Over LDAPS Domain Controller Certificates')
        for index, cert in enumerate(certs, 1):
            write_report(file, "      Certificate {}".format(index))
            report_certificate_details(file, certutil.build_pem_certificate(cert))


def generate_report_ssl_trust_anchors():
    file = get_report_file()
    write_report(file, 'Lookup Service Registration Trust Anchors')
    endpoints = vmdir.get_all_lookup_service_endpoints()
    trust_anchors = get_ssl_trust_anchors(endpoints)
    for index, cert in enumerate(trust_anchors, 1):
        write_report(file, "      Endpoint Certificate {}".format(index))
        service_ids, uris = get_service_ids_and_uri_by_certificate(endpoints, cert)
        report_trust_anchor_details(file, certutil.build_pem_certificate(cert), service_ids, uris)


def get_ssl_trust_anchors(endpoints):
    trust_anchors = []
    for endpoint in endpoints:
        endpoint['certificates'] = []
        for cert in sum([endpoint['vmwLKUPEndpointSslTrust'], endpoint['vmwLKUPSslTrustAnchor']], []):
            pem_cert = certutil.build_pem_certificate(cert)
            endpoint['certificates'].append(pem_cert)
            if pem_cert not in trust_anchors:
                trust_anchors.append(pem_cert)
    return trust_anchors


def get_service_ids_and_uri_by_certificate(endpoints, cert):
    service_ids = []
    uris = []
    for endpoint in endpoints:
        if cert in endpoint['certificates']:
            service_id = endpoint['dn'].split(',')[1].replace('cn=', '')
            if service_id not in service_ids:
                service_ids.append(service_id)
            uri = endpoint['vmwLKUPURI']
            if uri not in uris:
                uris.append(endpoint['vmwLKUPURI'])
    return sorted(service_ids), sorted(uris)


def report_trust_anchor_details(file, pem_cert, service_ids, uris):
    x509_cert = get_x509_certificate(pem_cert)
    report_certificate_basic(file, x509_cert)
    write_report(file, '            Service IDs:')
    for service_id in service_ids:
        service_type = vmdir.get_endpoint_service_type(service_id)
        write_report(file, "               |_{} ({})".format(service_id, service_type))

    write_report(file, '            Endpoints:')
    for uri in uris:
        write_report(file, "               |_{}".format(uri))


def set_report_file(file):
    env = Environment.get_environment()
    env.set_value('REPORT_FILE_DESC', file)


def get_report_file():
    env = Environment.get_environment()
    return env.get_value('REPORT_FILE_DESC')


def finalize_report():
    file = get_report_file()
    if file is not None:
        file.close()
        set_report_file(None)

    env = Environment.get_environment()
    env.set_value('COLORS_DISABLED', False)
    init_env_colormap()
    print()
    print_text_warning("Certificate report is available at {}".format(REPORT_FILE_PATH))
