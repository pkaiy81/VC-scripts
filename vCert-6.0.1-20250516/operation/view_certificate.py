# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import OpenSSL
from datetime import datetime

from lib import vcdb
from lib import vecs
from lib import vmdir
from lib.environment import Environment
from lib.certificate_utils import (
    get_certificate_info, get_certificate_fetcher_from_list, get_certificate_extensions,  
    build_certification_path, get_x509_certificate, get_subject_and_issuer_dn, get_subject_keyid,
    is_ca_certificate, split_certificates_from_pem
)
from lib.console import print_header, print_text, print_text_warning, print_text_error, ColorKey
from lib.input import MenuInput
from lib.host_utils import get_file_contents
from lib.constants import VMCA_CERT_FILE_PATH
from lib.menu import Menu, MenuInput
from lib.vmdir import get_smart_card_issuing_ca_certs
from operation.check_certificate import get_ids_domain_and_certificates, get_ids_domain_and_certificates_by_domain
from operation.common import get_vcenter_extensions, get_vcenter_extension_expected_thumbprints

logger = logging.getLogger(__name__)

def view_certificate_dummy(**kwargs):
    print_text("{}=== Unsupported view certificate operation! ==={}".format(ColorKey.YELLOW,
                                                                            ColorKey.NORMAL))


def view_certificate(pem_cert):
    print_header('Certificate Information')
    print(get_certificate_info(pem_cert))

    ca_certs, _ = vecs.get_all_certificates('TRUSTED_ROOTS')
    subject_keyids, fetcher = get_certificate_fetcher_from_list(ca_certs)
    cert_path = build_certification_path(pem_cert, subject_keyids, fetcher)

    print_header('Certification Path')
    print_certification_path(cert_path)


def print_certification_path(cert_path, status_text=False):
    for idx, cert_info in enumerate(cert_path):
        plus_green = "{}+{}".format(ColorKey.GREEN, ColorKey.NORMAL)
        if idx == 0:
            untrusted = '[UNTRUSTED]' if cert_info['is_trusted'] is not True else ''
            incomplete = '[INCOMPLETE]' if cert_info['is_selfsigned'] is not True else ''
            if untrusted or incomplete:
                mark = "{}!{}".format(ColorKey.RED, ColorKey.NORMAL)
            else:
                mark = plus_green
            if status_text:
                print_text("[ {} ] {} {}{}".format(mark, cert_info['cert_name'], incomplete, untrusted))
            else:
                print_text("[ {} ] {}".format(mark, cert_info['cert_name']))
        else:
            print_text("{}|_[ {} ] {}".format(' ' * (4 * idx - 2), plus_green,
                                              cert_info['cert_name']))


def view_machine_ssl_certificate():
    cert = vecs.get_certificate('MACHINE_SSL_CERT', '__MACHINE_CERT')
    view_certificate(cert)


def view_solution_user_certificate():
    env = Environment.get_environment()
    for soluser in env.get_value('SOLUTION_USERS'):
        print(f"\nSolution User: {soluser}")
        cert = vecs.get_certificate(soluser, soluser)
        view_certificate(cert)


def view_ca_certificates_in_vmdir(show_list_only=False):
    print_header('CA Certificates in VMware Directory')
    skids = vmdir.get_all_ca_subject_keyids(use_cache=False)
    for index, subject_key_id in enumerate(skids):
        cert_pem = vmdir.get_ca_certificate(subject_key_id)
        brief = get_certificate_info_brief(cert_pem)
        if index != 0:
            print()
        print("{:>2}. {}".format(index + 1, brief))
    if show_list_only:
        return
    keys = [str(i) for i in range(1, len(skids) + 1)]
    keys.append('R')
    print()
    menu_input = MenuInput('Select certificate [Return to menu]: ', acceptable_inputs=keys,
                           default_input='R')
    key = menu_input.get_input()
    print()
    if key != 'R':
        cert = vmdir.get_ca_certificate(skids[int(key)-1])
        view_certificate(cert)


def view_certificates_in_vecs(store, show_list_only=False):
    certs, aliases = vecs.get_all_certificates(store)
    for idx, cert in enumerate(certs):
        brief = get_certificate_info_brief(cert, aliases[idx])
        print("{:>2}. {}\n".format(idx + 1, brief))
    if show_list_only:
        return
    keys = [str(i) for i in range(1, len(aliases) + 1)]
    keys.append('R')
    menu_input = MenuInput('Select certificate [Return to menu]: ', acceptable_inputs=keys,
                           default_input='R')
    key = menu_input.get_input()
    print()
    if key != 'R':
        cert = certs[int(key) - 1]
        view_certificate(cert)


def view_ca_certificates_in_vecs(show_list_only=False):
    view_certificates_in_vecs('TRUSTED_ROOTS', show_list_only)


def view_sms_certificates_in_vecs(show_list_only=False):
    view_certificates_in_vecs('SMS', show_list_only)


def view_sts_signing_certificates():
    """
    Entry point for STS Tenant certificates view
    """
    certs_map = vmdir.get_sts_tenant_certificates(include_tenant_credential=True,
                                                  include_certificate_chain=False)
    for tenant_idx, tenant in enumerate(certs_map.keys()):
        if tenant_idx != 0:
            print()
        print("{}".format(tenant))
        for cert_idx, pem_cert in enumerate(certs_map[tenant]):
            if cert_idx != 0:
                print()
            basic_constraints = get_certificate_extensions(
                get_x509_certificate(pem_cert)).get('basicConstraints')
            is_ca = basic_constraints is not None and 'CA:TRUE' in basic_constraints
            print("   Certificate Type: {} Certificate".format('CA' if is_ca else 'Signing'))
            brief = get_certificate_info_brief(pem_cert, indent_first_line=True)
            print(brief)


def get_certificate_info_brief(pem_cert, alias=None, computed_skid=None, indent_first_line=False, 
                               domain_name=None, identity_source_type=None):
    """
    indent_first_line is used for 4 space indentation for first line of certificate info,
    in this case, it is alias or subject.
    """
    cert_info = []
    try:
        x509_cert = get_x509_certificate(pem_cert)
        skid = get_subject_keyid(x509_cert)
        subject_dn, issuer_dn = get_subject_and_issuer_dn(x509_cert)
        # '20240708142450Z'  -> 'Jul  8 14:24:50 2024 GMT'
        input_format = '%Y%m%d%H%M%SZ'
        output_format = '%b %e %H:%M:%S %Y GMT'
        end_date = datetime.strptime(x509_cert.get_notAfter().decode('utf-8'), input_format).strftime(output_format)

        if skid is None and computed_skid is not None:
            skid = "{} (computed)".format(computed_skid)

        is_ca = is_ca_certificate(x509_cert)
        indentation = '    ' if indent_first_line else ''
        if alias:
            cert_info.append("{}Alias: {}".format(indentation, alias))
            cert_info.append("    Subject: {}".format(subject_dn))
        else:
            cert_info.append("{}Subject: {}".format(indentation, subject_dn))
        cert_info.append("    Issuer: {}".format(issuer_dn))
        cert_info.append("    End Date: {}".format(end_date))
        cert_info.append("    Subject Key ID: {}".format(skid))
        cert_info.append("    Is CA Cert: {}".format('Yes' if is_ca else 'No'))
        if domain_name is not None:
            cert_info.append('    Domain: {}'.format(domain_name))
        if identity_source_type is not None:
            cert_info.append('    Identity Source Type: {}'.format(identity_source_type))

    except OpenSSL.crypto.Error:
        cert_info.append(print_text_error('Invalid format, certificate cannot be parsed', end=''))
        cert_info.append("    Subject Key ID: {}".format(computed_skid))

    return '\n'.join(cert_info)


def view_ldaps_identity_source_certificates(show_domain='All', identity_source_type=None, show_list_only=False):
    header = 'LDAP Certificates' if show_domain == 'All' else 'LDAP Certificates ({})'.format(show_domain)
    print_header(header)
    identity_sources = vmdir.get_identity_sources()
    index_start = 0
    identity_source_certs = ['-']
    if show_domain == 'All':
        # OpenLDAP
        index_start, identity_source_certs = ldaps_identity_source_certificate_items(identity_sources, index_start, 
                                                                                 identity_source_certs, identity_source_type='OpenLDAP')
    
        # AD over LDAP
        index_start, identity_source_certs = ldaps_identity_source_certificate_items(identity_sources, index_start, 
                                                                                 identity_source_certs, identity_source_type='AD over LDAP')
    
        # ADFS
        index_start, identity_source_certs = ldaps_identity_source_certificate_items(identity_sources, index_start, 
                                                                                 identity_source_certs, identity_source_type='ADFS')
    else:
        index_start, identity_source_certs = ldaps_identity_source_certificate_items(identity_sources, index_start, 
                                                                                 identity_source_certs, domain_name=show_domain, 
                                                                                 identity_source_type=identity_source_type)
    if show_list_only:
        return identity_source_certs
    print()
    keys = [str(i) for i in range(1, len(identity_source_certs) + 1)]
    keys.append('R')
    menu_input = MenuInput('Select certificate [Return to menu]: ', acceptable_inputs=keys,
                            default_input='R')
    key = menu_input.get_input()
    print()
    if key != 'R':
        cert = identity_source_certs[int(key)]
        view_certificate(cert)
    return identity_source_certs
    

def ldaps_identity_source_certificate_items(identity_sources, index_start, identity_source_certs, 
                                            domain_name=None, identity_source_type=None):
    if domain_name is None:
        domain_and_certs = get_ids_domain_and_certificates(identity_sources, identity_source_type)
    else: 
        domain_and_certs = get_ids_domain_and_certificates_by_domain(identity_sources, identity_source_type, domain_name)
    if domain_and_certs:
        for domain_name, certificates in domain_and_certs:
            for index, cert in enumerate(certificates, index_start):
                identity_source_certs.append(cert)
                cert_info = get_certificate_info_brief(cert, domain_name=domain_name, identity_source_type=identity_source_type)
                if index != 0:
                    print()
                print("{:>2}. {}".format(index + 1, cert_info))
                index_start += 1
    return index_start, identity_source_certs


def view_VMCA_Certificate():
    """
    Entry point to view VMCA Certificate
    """
    view_certificate(get_file_contents(VMCA_CERT_FILE_PATH))


def view_vcenter_extension_thumbprints():
    vcenter_extensions = get_vcenter_extensions()
    extension_thumbprints = vcdb.get_extension_thumbprints(vcenter_extensions)
    expected_thumbprints = get_vcenter_extension_expected_thumbprints(vcenter_extensions)

    for extension, thumbprint in extension_thumbprints.items():
        expected_thumbprint, expected_cert_type = expected_thumbprints[extension]
        print("{} ({})".format(extension, expected_cert_type))
        print("   ", thumbprint)


def view_smart_card_certificates(show_list_only=False):
    smart_card_filter_file_certificates = view_smart_card_filter_file_certificates()
    smart_card_vmdir_certificates = view_smart_card_vmdir_certificates()

    if show_list_only:
        return smart_card_filter_file_certificates, smart_card_vmdir_certificates

    menu = Menu()
    menu.set_menu_options('View Smart Card Certificate Options')
    menu.add_menu_item('View Smart Card filter file certificate')
    menu.add_menu_item('View Smart Card CA certificate')
    menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, key='R', is_default=True, is_hidden=True, 
                           use_label_as_key=True)
    menu.show_menu()
    print()
    view_certificate_type = menu.get_input().strip()

    if view_certificate_type != 'R':
        if view_certificate_type == '1':
            keys = [str(i) for i in range(1, len(smart_card_filter_file_certificates) + 1)]
            keys.append('R')
            print()
            view_certificate_selection = MenuInput('Select Smart Card filter file certificate [Return to menu]: ', acceptable_inputs=keys, default_input='R').get_input()
            if view_certificate_selection != 'R':
                view_certificate(smart_card_filter_file_certificates[int(view_certificate_selection) - 1])
        else:
            keys = [str(i) for i in range(1, len(smart_card_vmdir_certificates) + 1)]
            keys.append('R')
            print()
            view_certificate_selection = MenuInput('Select Smart Card CA certificate [Return to menu]: ', acceptable_inputs=keys, default_input='R').get_input()
            if view_certificate_selection != 'R':
                view_certificate(smart_card_vmdir_certificates[int(view_certificate_selection) - 1])


def view_smart_card_filter_file_certificates():
    env = Environment.get_environment()
    smart_card_filter_file = env.get_value('SMART_CARD_FILTER_FILE')
    print_header('Smart Card Filter File Certificates')
    smart_card_ca_certificates = split_certificates_from_pem(get_file_contents(smart_card_filter_file))
    if smart_card_ca_certificates:
        for index, cert in enumerate(smart_card_ca_certificates):
            cert_info = get_certificate_info_brief(cert)
            if index != 0:
                print()
            print("{:>2}. {}".format(index + 1, cert_info))
        return smart_card_ca_certificates
    else:
        print_text_warning('No certificates found in {}'.format(smart_card_filter_file))
        return []


def view_smart_card_vmdir_certificates():
    smart_card_ca_certificates = get_smart_card_issuing_ca_certs()
    logger.info('Smart Card CA Certifiates from VMware Directory: {}'.format(smart_card_ca_certificates))
    print_header('Smart Card Issuing CA Certificates')
    if smart_card_ca_certificates:
        for index, cert in enumerate(smart_card_ca_certificates):
            cert_info = get_certificate_info_brief(cert)
            if index != 0:
                print()
            print("{:>2}. {}".format(index + 1, cert_info))
        return smart_card_ca_certificates
    else:
        print_text_warning('No certificates found in VMware Directory')
        return []