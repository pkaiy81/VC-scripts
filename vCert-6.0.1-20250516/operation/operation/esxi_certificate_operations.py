#!/usr/bin/env python3

# Copyright (c) 2024-2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.


import stat

from lib.console import print_text, print_task_status, print_task_status_warning, ColorKey, \
    print_text_warning, print_header, print_task_status_error

import logging
import os
import urllib3
import re

from lib.command_runner import CommandRunner
from lib.exceptions import OperationFailed, CommandExecutionError
from lib.input import MenuInput
from lib.menu import Menu

from lib import vcdb, vmdir
from lib import vecs
from lib.environment import Environment
from lib.certificate_utils import (
    get_x509_certificate, build_certification_path, get_certificate_fingerprint, split_certificates_from_pem,
    get_certificate_from_host, get_certificate_end_date, get_certificate_start_date,
    get_subject_and_issuer_dn, get_subject_alternative_names, get_certificate_fetcher_from_list,
    is_ca_certificate, detect_and_convert_to_pem, get_key_modulus_from_pem_text, generate_csr
)
from lib.console import (
    print_task, print_text_error
)
from lib.constants import SPACE

from lib.host_utils import (
    get_file_contents, save_text_to_file, find_files,
    set_file_mode, is_file_exists
)
from operation.manage_certificate import find_matched_private_key, verify_certificate_and_key, obtain_ca_chain, \
    get_csr_info, get_san_entries, generate_openssl_config, clear_csr_info, get_timestamp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


def check_esxi_vcenter_trust():
    """
        Entry point for checking esxi vcenter certificate trust
    """

    num_hosts = vcdb.get_number_of_hosts()

    title = "Check ESXi/vCenter certificate trust"
    text_color = ColorKey.YELLOW if num_hosts == 0 else ColorKey.GREEN
    sub_title = "There are {}{}{} hosts connected to vCenter.\n".format(text_color, num_hosts, ColorKey.NORMAL)

    menu = Menu()
    if not get_hosts():
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=False, key='R',
                           is_default=True)
    else:
        menu.set_menu_options(title, sub_title, input_text='Select an option [Return to the previous menu]: ')
        menu.add_menu_item("Perform check on all hosts (requires uniform root password on all hosts)",
                           view_certificate_for_all_esxi_hosts)
        menu.add_menu_item("Perform check on all hosts in a cluster (requires uniform root password on all hosts)",
                           view_esxi_for_all_cluster)
        menu.add_menu_item("Perform check on single host", view_esxi_certificate_for_specific_host)
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=True, key='R',
                           is_default=True)

    menu.run()


def view_esxi_test_response():
    print(True)


def display_num_hosts():
    num_hosts = vcdb.get_number_of_hosts()
    text_color = ColorKey.YELLOW if num_hosts == 0 else ColorKey.GREEN
    print_text("There are {}{}{} hosts connected to vCenter.".format(text_color, num_hosts, ColorKey.NORMAL))

    if num_hosts == 0:
        print_text_error("Hosts not detected on the system")
    print("\n")


def get_hosts():
    hosts_str = vcdb.get_hosts()

    if hosts_str == "":
        print_text("No hosts available")
        return []

    hosts = []
    for host_info in hosts_str:
        host_info = host_info.strip()
        cluster_id = host_info.split("|")[0].strip()
        name = host_info.split("|")[1].strip()
        ip = host_info.split("|")[2].strip()
        host = [cluster_id, name, ip]
        hosts.append(host)
    return hosts


def get_host_password(pass_str):
    password = ""
    while password == "":
        password = MenuInput(pass_str, masked=True, case_insensitive=False).get_input()
    print()
    return password


def get_host_details(hosts):
    host_detail = ""
    while host_detail == "":
        host_detail = MenuInput('Enter FQDN or IP of the ESXi host: ',
                                allow_empty_input=False, case_insensitive=False).get_input()

        logger.info("The entered FQDN or IP is : {}".format(host_detail))
        if host_detail == "":
            print_text("Please enter valid input")
            continue
        for cluster_id, name, ip in hosts:
            if host_detail == name or host_detail == ip:
                print()
                return [name, ip]

        host_detail = ""
        print_text("Please enter valid input from below list")
        print(flush=True)
        for cluster_id, name, ip in hosts:
            print_text("Host name : {}      Host ip : {}".format(name, ip))
            print(flush=True)

    print()
    return []


def get_host_name_or_ip(host_name, host_ip):
    if host_name == "":
        return host_ip
    else:
        return host_name


def get_certificate_management_mode():
    return vcdb.get_certificate_management_mode()


def view_certificate_for_all_esxi_hosts():
    hosts = get_hosts()
    print("\n")
    password = get_host_password("Enter root password for all ESXi hosts: ")
    certificate_management_mode = get_certificate_management_mode()
    print_text("Certificate Management Mode = {}{}{}\n".format(ColorKey.GREEN, certificate_management_mode, ColorKey.NORMAL))
    for cluster_id, name, ip in hosts:
        print_text("Host : {}{}{}".format(ColorKey.CYAN, get_host_name_or_ip(name, ip), ColorKey.NORMAL))
        view_esxi_certificate_trust(get_host_name_or_ip(name, ip), certificate_management_mode, password)
    print("\n\n")


def view_esxi_certificate_for_specific_host():
    host_name, host_ip = get_host_details(get_hosts())
    host_name_or_ip = get_host_name_or_ip(host_name, host_ip)
    password = get_host_password("Enter root password for ESXi host {}: ".format(host_name_or_ip))
    certificate_management_mode = get_certificate_management_mode()
    print_text("Certificate Management Mode = {}{}{}".format(ColorKey.GREEN, certificate_management_mode, ColorKey.NORMAL))
    print_text("\nHost : {}{}{}".format(ColorKey.CYAN, host_name_or_ip, ColorKey.NORMAL))
    view_esxi_certificate_trust(host_name_or_ip, certificate_management_mode, password)
    print("\n\n")


def get_host_and_cluster():
    host_and_cluster_id = vcdb.get_host_and_cluster_id()

    if host_and_cluster_id == "":
        print_text("No hosts or Clusters available")
        return {}

    host_and_cluster_id_dict = {}

    for host_and_cluster_id_info in host_and_cluster_id:
        host_info = host_and_cluster_id_info.strip()
        host_id = host_info.split("|")[0].strip()
        cluster_id = host_info.split("|")[1].strip()
        host_and_cluster_id_dict[host_id] = cluster_id

    return host_and_cluster_id_dict


def find_hosts_in_cluster(input_cluster_id, hosts, host_and_cluster):
    hosts_in_cluster = []

    for host_id, name, ip in hosts:
        if host_and_cluster[host_id] == input_cluster_id:
            host_in_cluster = [host_id, name, ip]
            hosts_in_cluster.append(host_in_cluster)

    if not hosts_in_cluster:
        print_text("No hosts were found in cluster : {} ".format(input_cluster_id))
        return []

    return hosts_in_cluster


def get_input_cluster_id(cluster_no_dict, cluster_dict):
    input_cluster_id = ""
    while input_cluster_id == "":
        try:
            input_cluster_id = MenuInput('Select custer: ',
                                         allow_empty_input=False, case_insensitive=False).get_input()
            logger.info("The entered cluster id is: {}".format(input_cluster_id))

            if input_cluster_id not in cluster_no_dict:
                print_text("Please enter a valid cluster id from below list : \n")
                for id_no, cluster_id in cluster_no_dict.items():
                    print_text("cluster_id : {} cluster : {} ".format(id_no, cluster_dict[cluster_id]))
                input_cluster_id = ""
        except ValueError:
            print("Invalid input. Please enter appropriate entry")
            for id_no, cluster_id in cluster_no_dict.items():
                print_text("cluster id : {} cluster name : {} ".format(id_no, cluster_dict[cluster_id]))
            continue
        except IndexError:
            print_text("Please enter a valid cluster id from below list : \n")
            for id_no, cluster_id in cluster_no_dict.items():
                print_text("cluster id : {} cluster name : {} ".format(id_no, cluster_dict[cluster_id]))
            continue
    print("\n")
    return cluster_no_dict[input_cluster_id]


def get_clusters():
    clusters = vcdb.get_clusters()
    print_text("\nCompute clusters:")

    if clusters == "":
        print_text("There are no clusters present ")
        return {}

    cluster_no = 1
    cluster_dict = {}
    cluster_no_dict = {}
    for cluster_details in clusters:
        cluster_id = cluster_details.split("|")[0].strip()
        cluster_name = cluster_details.split("|")[1].strip()
        cluster_no_dict["{}".format(cluster_no)] = cluster_id
        cluster_dict[cluster_id] = cluster_name
        print_text(" {}. {}".format(cluster_no, cluster_name))
        cluster_no += 1
    print_text("\n")
    return cluster_no_dict, cluster_dict


def view_esxi_for_all_cluster():
    cluster_no_dict, cluster_dict = get_clusters()
    if not cluster_dict:
        return

    input_cluster_id = get_input_cluster_id(cluster_no_dict, cluster_dict)

    hosts_list = get_hosts()
    host_and_cluster_id_dict = get_host_and_cluster()
    hosts_in_cluster = find_hosts_in_cluster(input_cluster_id, hosts_list, host_and_cluster_id_dict)

    if hosts_in_cluster:
        password = get_host_password("Enter root password for all ESXi hosts in cluster: ")
        certificate_management_mode = get_certificate_management_mode()
        print_text("Certificate Management Mode = {}{}{}".format(ColorKey.GREEN, certificate_management_mode, ColorKey.NORMAL))
        for cluster_id, name, ip in hosts_in_cluster:
            print_text("\nHost : {}{}{}".format(ColorKey.CYAN, get_host_name_or_ip(name, ip), ColorKey.NORMAL))
            view_esxi_certificate_trust(get_host_name_or_ip(name, ip), certificate_management_mode, password)


def delete_and_validate_vecs_entry(store, alias):
    vecs.delete_entry(store, alias)
    # This is to check if pem_cert has been deleted
    vecs_cert = vecs.get_certificate(store, alias)
    if not vecs_cert:
        return True
    else:
        return False


def create_vecs_certificate(access_string, cert_file, vecs_store, vecs_alias):
    pem_certs = get_certificate_from_host(access_string, 443)
    if pem_certs:
        for cert in pem_certs:
            # Get and write x509 certificates to TEMP_DIR
            save_text_to_file(cert, cert_file)

        vecs.add_entry(vecs_store, vecs_alias, cert_file)
        updated_vecs_certs = vecs.get_certificate(vecs_store, vecs_alias)
        if updated_vecs_certs:
            print_text("{:<6}IOFILTER provider certificate created!".format(SPACE))
            logger.info("vecs certificate Created")
        else:
            print_text_warning("Unable to re-create the IOFILTER provider certificate in VECS!")
            logger.info("Unable to create vecs certificate")
        return True
    else:
        print_text_warning("Unable to obtain host's {} SSL certificate on port 443!".format(access_string))
        logger.info("Unable to obtain host's {} SSL certificate on port 443!".format(access_string))

    return False


def display_host_certificate_details(host_hash):
    output_format = '%b %e %H:%M:%S %Y GMT'

    x509_cert = get_x509_certificate(host_hash)
    host_cert_subject, host_cert_issuer = get_subject_and_issuer_dn(x509_cert)
    host_cert_valid_start = get_certificate_start_date(x509_cert).strftime(output_format)
    host_cert_valid_end = get_certificate_end_date(x509_cert).strftime(output_format)
    host_cert_fingerprint = get_certificate_fingerprint(x509_cert, 'sha1')
    host_cert_algorithm = x509_cert.get_signature_algorithm().decode('utf-8')
    host_cert_san = get_subject_alternative_names(x509_cert)

    host_cert_list = []
    for certificate in split_certificates_from_pem(host_hash):
        x509_certificate = get_x509_certificate(certificate)
        host_cert_subject, host_cert_issuer = get_subject_and_issuer_dn(x509_certificate)
        host_cert_list.append([host_cert_subject, host_cert_issuer])

    print_text("{:<3}Issuer: {}".format(SPACE, host_cert_issuer))
    print_text("{:<3}Subject: {}".format(SPACE, host_cert_subject))
    print_text("{:<6}Not Before: {}".format(SPACE, host_cert_valid_start))
    print_text("{:<6}Not After: {}".format(SPACE, host_cert_valid_end))
    print_text("{:<6}SHA1 Fingerprint: {}".format(SPACE, host_cert_fingerprint))
    print_text("{:<6}Signature Algorithm: {}".format(SPACE, host_cert_algorithm))
    print_text("{:<6}Subject Alternative Name entries:".format(SPACE))
    if host_cert_san:
        for entry in host_cert_san.split(', '):
            print_text("{:<9}|_{}".format(SPACE, entry))

    print_text("{:<6}Certificates in the rui.crt file:".format(SPACE))
    if host_cert_list:
        i=1
        for subject, issuer in host_cert_list:
            if i > 1:
                print_text('{:<9}|'.format(SPACE))
            print_text("{:<9}|_Subject={} ".format(SPACE, subject))
            print_text("{:<9}|_Issuer={} ".format(SPACE, issuer))
            i += 1

    return host_cert_fingerprint


def display_host_certificate_for_cert_management_thumbprint(access_string, host_cert_fingerprint):
    env = Environment.get_environment()

    store = "SMS"
    alias = "https:/{}:9080/version.xml".format(access_string)
    pem_cert = vecs.get_certificate(store, alias)
    current_host_sms_thumbprint = get_certificate_fingerprint(get_x509_certificate(pem_cert))
    cert_file = "{}/{}.crt".format(env.get_value('TEMP_DIR'), access_string)

    if current_host_sms_thumbprint:
        print_text("{:<6}Host IOFILTER provider found in VECS, checking certificate...".format(SPACE))
        print(flush=True)
        if current_host_sms_thumbprint != host_cert_fingerprint:
            print_task_status_warning("Mismatch found, re-creating entry...")

            if delete_and_validate_vecs_entry(store, alias):
                logger.info("vecs cert deleted. Will recreate.")
                create_vecs_certificate(access_string, cert_file, store, alias)
            else:
                print_task_status_warning("Unable to delete the IOFILTER provider certificate from VECS!")
        else:
            print_task_status("Certificates match. No need to update")
    else:
        print_text("{:<3}Host IOFILTER provider certificate not found in VECS. Creating entry...".format(SPACE))
        print(flush=True)
        logger.info("Attempting to create vecs certificate")
        create_vecs_certificate(access_string, cert_file, store, alias)


def url_request(method, url, username=None, password=None, data=None):
    # we use plain curl instead of requests library for automatic replay support in CommandRunner
    env = Environment.get_environment()
    temp_dir = env.get_value('TEMP_DIR')
    output_file = "{}/url_request_{}_{}_output.dat".format(temp_dir, method, get_timestamp())
    args = ['curl', '-k', '-X', method, url, '-o', output_file, '-s', '-w', '%{http_code}']
    if username and password:
        args.extend(['-u', "{}:{}".format(username, password)])
    if data:
        data_file = "{}/url_request_{}_{}_data.dat".format(temp_dir, method, get_timestamp())
        save_text_to_file(data, data_file)
        args.extend(['--data-binary', '@{}'.format(data_file)])
    status_code = CommandRunner(*args).run_and_get_output()
    output = get_file_contents(output_file)
    return status_code, output


def update_ca_store(access_string, password, vcenter_machine_ssl_cert, sps_cert):
    env = Environment.get_environment()
    url_text = "https://{}/host/castore".format(access_string)
    status_code, content = url_request('GET', url_text, 'root', password)

    logger.info("Getting castore.pem file from host {}".format(access_string))
    logger.info("Response from host {} - HTTP status code: {}".format(access_string, status_code))

    if status_code == '200':
        save_text_to_file(content, '{}/{}-castore.pem'.format(env.get_value('TEMP_DIR'), access_string))
        cert_list = split_certificates_from_pem(content)

        print_task("{:<6}vCenter Machine SSL cert: ".format(SPACE))
        if cert_list:
            if check_for_ca_certs(vcenter_machine_ssl_cert, cert_list):
                print_task_status("Trusted by host")
            else:
                print_task_status("Not trusted by host")

            print_task("{:<6}SPS service connection: ".format(SPACE))
            if check_for_ca_certs(sps_cert, cert_list):
                print_task_status("Trusted by host")
            else:
                print_task_status("Not trusted by host (maybe)")
        else:
            print_task_status_warning(" No CA certs in /etc/vmware/ssl/castore.pem")
        print("\n")
        return True
    elif status_code == '401':
        print_task("{:<6}vCenter Machine SSL cert:".format(SPACE))
        print_task_status_warning("unknown (possible bad ESXi root password)")
        print_task("{:<6}SPS service connection: ".format(SPACE))
        print_task_status_warning("unknown (possible bad ESXi root password)")
    else:
        print_task("{:<6}vCenter Machine SSL cert:".format(SPACE))
        print_task_status_warning(" unknown")
        print_task("{:<6}SPS service connection: ".format(SPACE))
        print_task_status_warning("unknown")

    print("\n")
    return False


def view_esxi_reverse_proxy_cert_status(host_rhttpproxy_cert, host_iofilterrvp_cert):
    input_search_cert_list = find_files("/etc/vmware-vpx/docRoot/certs/*")

    search_cert_list = []
    for cert_file in input_search_cert_list:
        pattern = re.compile(r".*\.r[0-9]*")
        if not pattern.match(cert_file):
            search_cert_list.append(cert_file)

    print_task("{:<6}Reverse Proxy cert (port 443): ".format(SPACE))
    certificate_list = []
    for search_cert in search_cert_list:
        certificate_list.append(get_file_contents(search_cert))
    if check_for_ca_certs(host_rhttpproxy_cert, certificate_list):
        print_task_status("Trusted by vCenter")
    else:
        print_task_status("Not trusted by vCenter")

    print_task("{:<6}IOFilter VASA provider cert (port 9080): ".format(SPACE))
    if host_iofilterrvp_cert:
        certificate_list = []
        for search_cert in search_cert_list:
            certificate_list.append(get_file_contents(search_cert))

        if check_for_ca_certs(host_iofilterrvp_cert, certificate_list):
            print_task_status("Trusted by vCenter")
        else:
            print_task_status("Not trusted by vCenter")
    else:
        print_task_status_warning("unknown")


def view_esxi_certificate_trust(access_string, certificate_management_mode, password):

    host_hash = get_certificate_from_host(access_string, 443)

    if host_hash:
        host_cert_fingerprint = display_host_certificate_details(host_hash)

        print_text("\n{:<3}Certificate Trusts:".format(SPACE))
        if certificate_management_mode == "thumbprint":
            display_host_certificate_for_cert_management_thumbprint(access_string, host_cert_fingerprint)
        else:
            host_rhttpproxy_cert = get_certificate_from_host(access_string, 443)
            host_iofilterrvp_cert = get_certificate_from_host(access_string, 9080)
            vcenter_machine_ssl_cert = vecs.get_certificate("MACHINE_SSL_CERT", "__MACHINE_CERT")
            sps_cert = vecs.get_certificate("SMS", "sms_self_signed")

            view_esxi_reverse_proxy_cert_status(host_rhttpproxy_cert, host_iofilterrvp_cert)
            update_ca_store(access_string, password, vcenter_machine_ssl_cert, sps_cert)
    else:
        print_task_status_warning("Unable to obtain SSL certificate from host {}".format(access_string))


def check_for_ca_certs(cert, search_cert_list):
    subject_keyids, fetcher = get_certificate_fetcher_from_list(search_cert_list)

    cert_path = build_certification_path(cert, subject_keyids, fetcher)
    if cert_path:
        return True

    return False


def check_esxi_certificate_against_vcdb():
    # Entry point for checking esxi vcenter certificate trust against VCDB

    num_hosts = vcdb.get_number_of_hosts()

    title = "Checking ESXi SSL Thumbprints Against vCenter Database"
    text_color = ColorKey.YELLOW if num_hosts == 0 else ColorKey.GREEN
    sub_title = "There are {}{}{} hosts connected to vCenter.\n".format(text_color, num_hosts, ColorKey.NORMAL)

    menu = Menu()
    if not get_hosts():
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=False, key='R',
                           is_default=True)
    else:
        menu.set_menu_options(title, sub_title, input_text='Select an option [Return to the previous menu]: ')
        menu.add_menu_item("Perform check on all hosts", check_certificate_for_all_esxi_hosts_against_vcdb)
        menu.add_menu_item("Perform check on all hosts in a cluster", check_clustered_esxi_against_vcdb)
        menu.add_menu_item("Perform check on single host", check_specific_esxi_certificate_against_vcdb)
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=True, key='R',
                           is_default=True)

    menu.run()


def check_certificate_for_all_esxi_hosts_against_vcdb():
    hosts = get_hosts()
    if hosts:
        certificate_management_mode = get_certificate_management_mode()
        access_strings = []
        for cluster_id, name, ip in hosts:
            access_strings.append(get_host_name_or_ip(name, ip))
        check_esxi_against_vcdb(access_strings, certificate_management_mode)


def check_clustered_esxi_against_vcdb():
    cluster_no_dict, cluster_dict = get_clusters()
    input_cluster_id = get_input_cluster_id(cluster_no_dict, cluster_dict)

    hosts_list = get_hosts()
    host_and_cluster_id_dict = get_host_and_cluster()
    hosts_in_cluster = find_hosts_in_cluster(input_cluster_id, hosts_list, host_and_cluster_id_dict)

    if hosts_in_cluster:
        certificate_management_mode = get_certificate_management_mode()
        access_strings = []
        for cluster_id, name, ip in hosts_in_cluster:
            access_strings.append(get_host_name_or_ip(name, ip))
        check_esxi_against_vcdb(access_strings, certificate_management_mode)


def check_specific_esxi_certificate_against_vcdb():
    certificate_management_mode = get_certificate_management_mode()
    host_name, host_ip = get_host_details(get_hosts())
    host_name_or_ip = get_host_name_or_ip(host_name, host_ip)
    check_esxi_against_vcdb([host_name_or_ip], certificate_management_mode)


def check_esxi_against_vcdb(access_strings, certificate_management_mode):
    if certificate_management_mode == "thumbprint":
        print_task_status_warning("The Certificate Management mode has been set to thumbprint")
    else:
        for access_string in access_strings:
            print_text("\n{}{}{}".format(ColorKey.CYAN, access_string, ColorKey.NORMAL))
            view_esxi_against_vcdb(access_string)


def get_ssl_thumbprint(access_string):
    ssl_thumbprint_str = vcdb.get_ssl_thumbprint_from_vcdb(access_string)
    if ssl_thumbprint_str == "":
        print_text_warning("No ssl thumbprints available")
        return ['', '']

    ssl_thumbprint = []
    for thumbprint_info in ssl_thumbprint_str:
        expected_ssl_thumbprint = thumbprint_info.split("|")[0].strip()
        host_ssl_thumbprint = thumbprint_info.split("|")[1].strip()
        ssl_thumbprint = [expected_ssl_thumbprint, host_ssl_thumbprint]
    return ssl_thumbprint


def view_esxi_against_vcdb(access_string):
    expected_ssl_thumbprint, host_ssl_thumbprint = get_ssl_thumbprint(access_string)
    pem_certs = get_certificate_from_host(access_string, 443)
    certs = ""
    if pem_certs:
        certs = split_certificates_from_pem(pem_certs)

    actual_ssl_thumbprint = get_certificate_fingerprint(get_x509_certificate(certs[0]))

    if expected_ssl_thumbprint:
        print_text("{:<3}Expected Thumbprint (VCDB)  :   {}".format(SPACE, expected_ssl_thumbprint))
    else:
        print_task_status_warning("Expected Thumbprint missing")

    if host_ssl_thumbprint:
        print_text("{:<3}Host SSL Thumbprint (VCDB)  :   {}".format(SPACE, host_ssl_thumbprint))
    else:
        print_task_status_warning("Host SSL Thumbprint missing")

    if actual_ssl_thumbprint:
        print_text("{:<3}Actual Thumbprint (openssl) :   {} ".format(SPACE, actual_ssl_thumbprint))
        if expected_ssl_thumbprint != actual_ssl_thumbprint and host_ssl_thumbprint != actual_ssl_thumbprint \
                and expected_ssl_thumbprint != host_ssl_thumbprint:
            print_text("{:<3}Status : {}MISMATCH{}".format(SPACE, ColorKey.YELLOW, ColorKey.NORMAL))
        else:
            print_text("{:<3}Status : {}MATCH{}".format(SPACE, ColorKey.GREEN, ColorKey.NORMAL))
    else:
        print_text(
            "{:<3}Actual Thumbprint (openssl) : {}Cannot connect to host{}".format(SPACE, ColorKey.YELLOW, ColorKey.NORMAL))
        print_text("{:<3}Status : {}UNKNOWN{}".format(SPACE, ColorKey.YELLOW, ColorKey.NORMAL))


def replace_esxi_certificate():
    """
        Entry point for checking esxi vcenter certificate trust
    """
    num_hosts = vcdb.get_number_of_hosts()

    title = "Replace ESXi certificate"
    text_color = ColorKey.YELLOW if num_hosts == 0 else ColorKey.GREEN
    sub_title = "There are {}{}{} hosts connected to vCenter.\n".format(text_color, num_hosts, ColorKey.NORMAL)

    menu = Menu()

    if not get_hosts():
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=False, key='R',
                           is_default=True)
    else:
        menu.set_menu_options(title, sub_title, input_text='Select an option [Return to the previous menu]: ')
        menu.add_menu_item("Generate Certificate Signing Request and Private Key",
                           generate_cert_signing_request_non_custom)
        menu.add_menu_item("Generate Certificate Signing Request and Private Key from custom OpenSSL configuration "
                           "file", generate_cert_signing_request_with_custom_openssl)
        menu.add_menu_item("Import CA-signed certificate and key", import_ca_signed_cert)
        menu.add_menu_item('Return to the previous menu', Menu.run_navigation_return, is_hidden=True, key='R',
                           is_default=True)
    menu.run()


def get_esxi_cn_input():
    esxi_cn_input = ""
    while not esxi_cn_input:
        esxi_cn_input = MenuInput("Enter a value for the {}CommonName{} of the certificate: ".format(
            ColorKey.CYAN, ColorKey.NORMAL),  allow_empty_input=False, case_insensitive=False).get_input()

        logger.info("The entered esxi cn input : {}".format(esxi_cn_input))
        if not esxi_cn_input:
            print_text("Please enter valid input")
            continue
    print()
    return esxi_cn_input


def generate_cert_signing_request_non_custom():
    generate_cert_signing_request(True)


def generate_cert_signing_request_with_custom_openssl():
    generate_cert_signing_request(False)


def generate_csr_and_private_key(esxi_cn_input, custom_openssl_config=False):
    """
    Entry point for CSR generation
    :param esxi_cn_input: esxi cn input
    :param custom_openssl_config: True if a custom OpenSSL config is used
    """

    clear_csr_info()

    env = Environment.get_environment()
    request_dir = env.get_value('REQUEST_DIR')
    timestamp = get_timestamp()
    csr_file = "{}/{}-{}.csr".format(request_dir, esxi_cn_input, timestamp)
    key_file = "{}/{}-{}.key".format(request_dir, esxi_cn_input, timestamp)
    if custom_openssl_config:
        logger.info('User has chosen to generate the ESXi SSL private key and CSR from a custom OpenSSL '
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
        logger.info('User has chosen to generate the Esxi SSL private key and CSR')
        hostname = env.get_value('HOSTNAME')
        config_file = "{}/{}.cfg".format(request_dir, esxi_cn_input)

        csr_info = get_csr_info(esxi_cn_input)
        san_entries = get_san_entries('ESXi', csr_info, esxi_cn_input)
        generate_openssl_config(config_file, csr_info, esxi_cn_input, san_entries)

    try:
        print_header("Replace ESXi Certificate")
        print_task("Generating Certificate Signing Request")
        generate_csr(config_file, csr_file, key_file)
        # OpenSSL 1.0 on VC 7.x doesn't set the file permission correctly
        set_file_mode(key_file, stat.S_IRUSR | stat.S_IWUSR)
    except CommandExecutionError as e:
        error_message = "Unable to generate Certificate Signing Request and Private Key: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)

    print_task_status("OK")
    print()
    print_text("Certificate Signing Request generated at {}{}{}".format(ColorKey.CYAN, csr_file, ColorKey.NORMAL))
    print_text("Private Key generated at {}{}{}".format(ColorKey.CYAN, key_file, ColorKey.NORMAL))
    print("\n")


def generate_cert_signing_request(generate_csr_and_private_key_option):
    clear_csr_info()

    esxi_cn_input = get_esxi_cn_input()

    if generate_csr_and_private_key_option:
        generate_csr_and_private_key(esxi_cn_input, False)
    else:
        generate_csr_and_private_key(esxi_cn_input, True)


def path_to_new_esxi_cert():
    file_path = ""
    while file_path == "":
        file_path = MenuInput("Enter path to new ESXi certificate:  ",
                              allow_empty_input=False, case_insensitive=False).get_input()

        logger.info("Entered path to new ESXi certificate: {}".format(file_path))

        if file_path == "" or not is_file_exists(file_path):
            file_path = ""
            print_text("Please enter valid input. File not found, enter path to new ESXi certificate:")

    return file_path


def get_valid_new_cert():
    cert_file = path_to_new_esxi_cert()

    pem_cert, pem_cert_key = detect_and_convert_to_pem(cert_file, allow_input=True)

    while is_ca_certificate(get_x509_certificate(pem_cert)):
        print_task_status_warning("Provided certificate is designated as a Certificate Authority, and is "
                                  "not an appropriate replacement.")
        cert_file = path_to_new_esxi_cert()
        pem_cert, pem_cert_key = detect_and_convert_to_pem(cert_file, allow_input=True)

    env = Environment.get_environment()
    temp_dir = env.get_value('TEMP_DIR')

    pem_cert_file_name = "{}/{}-converted.pem".format(temp_dir, os.path.basename(cert_file[:cert_file.rfind('.')]))

    save_text_to_file(pem_cert, pem_cert_file_name)
    logger.info("Provided new certificate file : {}".format(pem_cert_file_name))

    pem_key_file_name = "{}/{}-converted.key".format(temp_dir, os.path.basename(cert_file[:cert_file.rfind('.')]))
    logger.info("Provided new key file : {}".format(pem_key_file_name))

    if not pem_cert_key:
        cert_modulus = get_key_modulus_from_pem_text(pem_cert)
        pem_cert_key = find_matched_private_key(cert_modulus, cert_file)

    if not pem_cert_key:
        raise OperationFailed('Failed to obtain key file')
    save_text_to_file(pem_cert_key, pem_key_file_name)
    logger.info("Provided new certificate key file : {}".format(pem_key_file_name))

    return pem_cert_file_name, pem_key_file_name, cert_file, pem_cert, pem_cert_key


def import_ca_signed_cert():
    logger.info("User has chosen to import a CA-signed ESXi SSL certificate and key")
    host_name, host_ip = get_host_details(get_hosts())

    host_name_or_ip = get_host_name_or_ip(host_name, host_ip)
    password = get_host_password("Enter root password for ESXi host {}: ".format(host_name_or_ip))

    pem_cert_file_name, pem_key_file_name, cert_file, pem_cert, pem_cert_key = get_valid_new_cert()

    verify_certificate_and_key(pem_cert_file_name, pem_key_file_name, pem_cert_file_name, None)

    ca_pem, ca_certs_pem, cert_pem_updated = obtain_ca_chain(pem_cert)

    env = Environment.get_environment()
    temp_dir = env.get_value('TEMP_DIR')
    pem_ca_file_name = "{}/{}-ca_file.pem".format(temp_dir, os.path.basename(cert_file[:cert_file.rfind('.')]))

    if cert_pem_updated is not None:
        cert_pem = cert_pem_updated
        save_text_to_file(cert_pem, pem_cert_file_name)
    save_text_to_file(ca_pem, pem_ca_file_name)

    print_header("Replace ESXi Certificate")

    print_task('Publish CA signing certificates')
    vmdir.publish_trusted_certificate(pem_ca_file_name)
    try:
        vecs.force_refresh()
        print_task_status('OK')
    except CommandExecutionError as e:
        error_message = "Unable to perform a force-refresh of CA certificates to VECS: {}".format(str(e))
        logger.error(error_message)
        raise OperationFailed(error_message)

    input_search_cert_list = find_files("/etc/vmware-vpx/docRoot/certs/*")
    search_cert_list = []
    pattern = re.compile(r".*\.r[0-9]*")
    for cert_file in input_search_cert_list:
        if not pattern.match(cert_file):
            search_cert_list.append(cert_file)

    env = Environment.get_environment()
    temp_dir = env.get_value('TEMP_DIR')
    overwrite_file = '{}/{}-castore.pem'.format(temp_dir, host_name_or_ip)
    if find_files(overwrite_file):
        save_text_to_file("", overwrite_file)

    certs_pem, aliases = vecs.get_all_ca_certificates()

    cert_text = ""
    for cert_pem in certs_pem:
        if is_ca_certificate(get_x509_certificate(cert_pem)):
            cert_text += cert_pem
            cert_text += '\n'

    cert_text += vecs.get_certificate('SMS', 'sms_self_signed')

    save_text_to_file(cert_text, overwrite_file)

    print_task("Replace ESXi certificate")
    logger.info("Replacing ESXi certificate with {}".format(overwrite_file))
    url_text = "https://{}/host/ssl_cert".format(host_name_or_ip)
    status_code, _ = url_request('PUT', url_text, 'root', password, data=pem_cert)

    if status_code == '200':
        print_task_status("OK")
    else:
        error_message = "Unable to replace certificate, HTTP return code: {}".format(status_code)
        print_task_status_error(error_message)
        logger.error(error_message)
        raise OperationFailed(error_message)

    print_task("Replace ESXi private key")
    logger.info("Replacing ESXi private key with {}".format(pem_key_file_name))
    url_text = "https://{}/host/ssl_key".format(host_name_or_ip)
    status_code, _ = url_request('PUT', url_text, 'root', password, data=pem_cert_key)
    if status_code == '200':
        print_task_status("OK")
    else:
        error_message = "Unable to replace private key, HTTP return code: {}".format(status_code)
        print_task_status_error(error_message)
        logger.error(error_message)
        raise OperationFailed(error_message)

    print_task("Replace castore.pem")
    logger.info("Replacing ESXi private key with {}".format(pem_key_file_name))
    url_text = "https://{}/host/castore".format(host_name_or_ip)
    status_code, _ = url_request('PUT', url_text, 'root', password, data=cert_text)
    if status_code == '200':
        print_task_status("OK")
    else:
        error_message = "Unable to replace castore.pem, HTTP return code: {}\n".format(status_code)
        print_task_status_error(error_message)
        logger.error(error_message)
        raise OperationFailed(error_message)

    addition_steps_text = """\nAdditional steps are necessary to complete this process:
    1. Run the following command on the ESXi host to save
        the new certificate and key to the bootbank:   /bin/auto-backup.sh
    2. Either reboot the ESXi host, or restart the Management Agents (rhttpproxy, hostd, vpxa, etc.)
    3. Disconnect and Re-connect the host in vCenter to update certificate information in the vCenter database


    """

    print_text_warning(addition_steps_text)
