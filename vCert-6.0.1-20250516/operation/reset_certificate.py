# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import os
import datetime
import stat

from lib import vmdir
from lib.certificate_utils import is_cert_file_expired, CERTOOL_CLI
from lib.command_runner import CommandRunner
from lib.console import (
    print_task, print_task_status, print_text_error, print_task_status_error, print_task_status_warning,
    print_header, print_text, set_text_color, ColorKey
)
from lib.constants import (VMCA_CERT_FILE_PATH, VMCA_KEY_FILE_PATH, VMCA_SSO_FILE_PATH)
from lib.environment import Environment
from lib.exceptions import OperationFailed, CommandExecutionError

from lib.host_utils import (VcVersion, get_node_type, NodeType, is_service_running, save_text_to_file, is_file_exists)


from lib.menu import Menu, MenuInput
from lib.vmdir import update_solution_user_certificate_in_vmdir, replace_service_principal_certificates
from operation.manage_certificate import (get_csr_info, update_vc_ext_thumbprints, 
                                          update_auto_deploy_db, restart_vmware_services,
                                          backup_vecs_cert_key, update_vecs,
                                          generate_csr_and_private_key, verify_certificate_and_key,
                                          publish_ca_signing_certificate, obtain_ca_chain,
                                          replace_machine_ssl_certificate_with_vmca_signed,
                                          update_ssl_trust_anchors, clear_csr_info, get_san_entries,
                                          get_timestamp, get_custom_ca_signed_certificate_files,
                                          generate_openssl_config, is_file_exists, generate_csr, 
                                          set_file_mode, get_cert_usage_value,
                                          verify_certification_path,
                                          set_default_csr_input,
                                          replace_sts_signing_certificate_with_vmca_signed,
                                          generate_certool_config, backup_filesystem_cert_key)


logger = logging.getLogger(__name__)

def reset_all_certificates():
    """
    Entry point for reset certificates with VMCA-signed
    """
    if is_cert_file_expired(VMCA_CERT_FILE_PATH):
        print_text_error('The VMCA certificate is expired and will first need to be replaced.')
        menu = Menu()
        menu.set_menu_options('Replace VMCA Certificate', run_once=True)
        menu.add_menu_item('Replace VMCA with self-signed certificate', replace_vmca_cert, is_default=True)
        menu.add_menu_item('Replace VMCA with CA-signed certificate', import_custom_ca_signed_vmca_certificate)
        menu.run()

    # to get initial csr info input wrt vCert.sh
    get_csr_info()
    machine_ssl_cert_file = replace_machine_ssl_certificate_with_vmca_signed()
    replace_solution_user_certificates_vmca_signed()
    # update the rest settings
    update_vc_ext_thumbprints()
    update_auto_deploy_db()
    replace_sts_signing_certificate_with_vmca_signed()
    update_ssl_trust_anchors(machine_ssl_cert_file)
    #todo: need to add additional methods in reset after closing current MR.

    # restart services
    restart_vmware_services()


def manage_solution_user_certificate_with_vmca_signed():
    replace_solution_user_certificates_vmca_signed()
    update_vc_ext_thumbprints()
    # restart services
    restart_vmware_services()
    clear_csr_info()


def replace_solution_user_certificates_vmca_signed():
    env = Environment.get_environment()
    output_dir = env.get_value('TEMP_DIR')
    solution_users = env.get_value('SOLUTION_USERS')
    print_header('Replace Solution User Certificates')
    set_default_csr_input()
    vmdir.verify_service_principals()
    print('Generate new certificates and keys:')
    for soluser in solution_users:
        print_task(f"   {soluser}")
        privkey_arg = "--privkey={}/{}.key".format(output_dir, soluser)
        pubkey_arg = "--pubkey={}/{}.pub".format(output_dir, soluser)
        cert_arg = "--cert={}/{}.crt".format(output_dir, soluser)
        client = CommandRunner(CERTOOL_CLI, '--genkey', privkey_arg, pubkey_arg)
        return_code, stdout, stderr = client.run()
        if return_code != 0:
            print_text_error(f"Unable to generate a key pair for {soluser}")
        args = [CERTOOL_CLI, '--gencert', '--server', 
                                   "localhost", '--Name', soluser, '--genCIScert', 
                                   privkey_arg, cert_arg, '--config=/dev/null', '--Country',
                                   env.get_value('CSR_COUNTRY_DEFAULT'), '--State',
                                   env.get_value('CSR_STATE_DEFAULT'), '--Locality',
                                   env.get_value('CSR_LOCALITY_DEFAULT'), '--Organization',
                                   env.get_value('CSR_ORG_DEFAULT'),
                                   '--OrgUnit',
                                   "mID-{}".format(env.get_value('MACHINE_ID'))]
        if soluser == 'wcp':
            args.extend('--dataencipherment')
        else:
            args.extend(['--FQDN', env.get_value('PNID')])
        client = CommandRunner(*args)
        return_code, stdout, stderr = client.run()
        if return_code != 0:
            print_text_error(f"Unable to generate a VMCA-signed cert for {soluser}")
        else:
            print_task_status("OK")
    
    print('\nBackup certificate and private key:')
    for soluser in solution_users:
        backup_vecs_cert_key(soluser)

    print('\nUpdating certificates and keys in VECS:')
    for soluser in solution_users:
        cert_file = "{}/{}.crt".format(output_dir, soluser)
        key_file = "{}/{}.key".format(output_dir, soluser)
        update_vecs(soluser, cert_file, key_file)
    
    if is_file_exists('/storage/vsan-health/vpxd-extension.cert') and is_file_exists('/storage/vsan-health/vpxd-extension.key'):
        print('\nUpdating vpxd-extension certificate for vSAN Health')
        try:
            CommandRunner('cp', '{}/vpxd-extension.crt'.format(output_dir), '/storage/vsan-health/vpxd-extension.cert').run()
            CommandRunner('cp', '{}/vpxd-extension.key'.format(output_dir), '/storage/vsan-health/vpxd-extension.key').run()
        except CommandExecutionError as e:
            error_message = "Unable to update vpxd-extension cert and key for vSAN Health: {}".format(str(e))
            logger.error(error_message)
            raise OperationFailed(error_message)

    print('\nUpdating solution user certificates in VMware Directory:')
    for soluser in solution_users:
        cert_file = "{}/{}.crt".format(output_dir, soluser)
        replace_service_principal_certificates(soluser, cert_file)


def generate_csr_and_private_key_of_soluser(custom_openssl_config=False):
    """
    Entry point for generating csr and private key of solution users
    """
    env = Environment.get_environment()
    request_dir = env.get_value('REQUEST_DIR')
    timestamp = get_timestamp()
    solution_users = env.get_value('SOLUTION_USERS')
    hostname = env.get_value('HOSTNAME')
    if custom_openssl_config:
        #san_entries = get_san_entries('soluser', get_csr_info(), hostname)
        for soluser in solution_users:
            csr_file = "{}/{}-{}.csr".format(request_dir, soluser, timestamp)
            key_file = "{}/{}-{}.key".format(request_dir, soluser, timestamp)
            logger.info('User has chosen to generate the {} private key and CSR from a custom OpenSSL configuration file'.format(soluser))
            user_input = MenuInput('Enter path to custom OpenSSL configuration file for {}{}{}: '
                                   .format('{COLORS[CYAN]}', soluser, '{COLORS[NORMAL]}'), 
                                   allow_empty_input=False, case_insensitive=False)
            config_file = "{}/{}-{}.cfg".format(request_dir, soluser, timestamp)
            while True:
                config_file = user_input.get_input()
                if not is_file_exists(config_file):
                    print_text_error('Error: file not found, enter path to custom OpenSSL configuration file for {}: '.format(soluser))
                    continue
                break
            try:
                generate_csr(config_file, csr_file, key_file)
                # OpenSSL 1.0 on VC 7.x doesn't set the file permission correctly
                set_file_mode(key_file, stat.S_IRUSR | stat.S_IWUSR)
            except CommandExecutionError as e:
                error_message = "Unable to generate Certificate Signing Request and Private Key: {}".format(str(e))
                logger.error(error_message)
                raise OperationFailed(error_message)
    else:
        csr_info = get_csr_info('soluser')
        san_entries = get_san_entries('soluser', csr_info, hostname)
        for soluser in solution_users:
            config_file = "{}/{}-{}.cfg".format(request_dir, soluser, timestamp)
            csr_file = "{}/{}-{}.csr".format(request_dir, soluser, timestamp)
            key_file = "{}/{}-{}.key".format(request_dir, soluser, timestamp)
            cn = "{}-{}".format(soluser, env.get_value('MACHINE_ID'))
            generate_openssl_config(config_file, csr_info, cn, san_entries)
            try:
                generate_csr(config_file, csr_file, key_file)
                # OpenSSL 1.0 on VC 7.x doesn't set the file permission correctly
                set_file_mode(key_file, stat.S_IRUSR | stat.S_IWUSR)
            except CommandExecutionError as e:
                error_message = "Unable to generate Certificate Signing Request and Private Key: {}".format(str(e))
                logger.error(error_message)
                raise OperationFailed(error_message)
    print_text("Certificate Signing Request generated at:")
    for soluser in solution_users:
        csr_file = "{}/{}-{}.csr".format(request_dir, soluser, timestamp)
        set_text_color(ColorKey.CYAN)
        print_text("{}".format(csr_file))
        set_text_color(ColorKey.NORMAL)
    print_text("Private Keys generated at:")
    for soluser in solution_users:
        key_file = "{}/{}-{}.key".format(request_dir, soluser, timestamp)
        set_text_color(ColorKey.CYAN)
        print_text("{}".format(key_file))
        set_text_color(ColorKey.NORMAL)


def import_custom_ca_signed_vmca_certificate():
    cert_pem_file, key_pem_file, ca_pem_file, cert_pem, ca_pem = get_custom_ca_signed_certificate_files('vmca', False)
    backup_filesystem_cert_key(VMCA_CERT_FILE_PATH, VMCA_KEY_FILE_PATH, 'VMCA')
    reconfigure_vmca(cert_pem_file, key_pem_file)
    publish_ca_signing_certificate(ca_pem_file)
    update_vmca_cert_in_filesystem(VMCA_CERT_FILE_PATH)
    return True


def import_custom_ca_signed_vmca_certificate_and_reset_all():
    if import_custom_ca_signed_vmca_certificate():
        reset_all_certificates()


def replace_vmca_cert():
    logger.info("User selected to replace VMCA certificate with a SELF-SIGNED certificate")
    logger.info("Certificates will NOT be regenerated")
    env = Environment.get_environment()
    csr_info = get_csr_info()
    vmca_cn_default = env.get_value('VMCA_CN_DEFAULT')
    output_dir = env.get_value('TEMP_DIR')
    vmca_cn_input = MenuInput('Enter a value for the {}CommonName{} of the certificate [{}]: '
                                   .format('{COLORS[CYAN]}', '{COLORS[NORMAL]}', vmca_cn_default), 
                                   default_input=vmca_cn_default).get_input()
    print_header('Replace VMCA Certificate')
    generate_certool_config(output_dir, 'vmca', csr_info, vmca_cn_input)
    print_task('Generate VMCA certificate')
    
    config_arg = "--config={}/vmca.cfg".format(output_dir)
    outcert_arg = "--outcert={}/vmca.crt".format(output_dir)
    outprivkey_arg = "--outprivkey={}/vmca.key".format(output_dir)
    try:
        CommandRunner(CERTOOL_CLI, '--genselfcacert', outcert_arg, outprivkey_arg, config_arg, expected_return_code=0).run_and_get_output()
        print_task_status('OK')
    except CommandExecutionError as e:
        print_task_status('FAILED')
        error_message = "Unable to generate new VMCA certificate"
        logger.error(error_message)
        raise OperationFailed(error_message)

    backup_filesystem_cert_key(VMCA_CERT_FILE_PATH, VMCA_KEY_FILE_PATH, 'VMCA')
    reconfigure_vmca("{}/vmca.crt".format(output_dir), "{}/vmca.key".format(output_dir) )
    update_vmca_cert_in_filesystem(VMCA_CERT_FILE_PATH)
    return True


def update_vmca_cert_in_filesystem(vmca_cert):
    if is_file_exists(VMCA_SSO_FILE_PATH):
        print_task('Update VMCA certificate on filesystem')
        try:
            CommandRunner('mv', VMCA_SSO_FILE_PATH, '/etc/vmware-sso/keys/ssoserverRoot.crt.old', expected_return_code=0).run_and_get_output()
        except CommandExecutionError as e:
            print_task_status_warning('FAILED')
            error_message = 'Unable to backup old SSO server root certificate'
            logger.error(error_message)
            raise OperationFailed(error_message)
        try:
            CommandRunner('cp', vmca_cert, VMCA_SSO_FILE_PATH, expected_return_code=0).run_and_get_output()
        except CommandExecutionError as e:
            print_task_status_warning('FAILED')
            error_message = 'Unable to update SSO server root certificate'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')


def reconfigure_vmca(new_vmca_cert, new_vmca_key):
    print_task('Reconfigure VMCA')
    cert_arg = '--cert={}'.format(new_vmca_cert)
    privkey_arg = '--privkey={}'.format(new_vmca_key)
    try:
        CommandRunner(CERTOOL_CLI, '--rootca', cert_arg, privkey_arg, expected_return_code=0).run_and_get_output()
    except CommandExecutionError as e:
        print_task_status_warning('FAILED')
        error_message = 'Unable to reconfigure the VMCA with the new certificate'
        logger.error(error_message)
        raise OperationFailed(error_message)
    print_task_status('OK')


def replace_vmca_cert_and_regenerate_all():
    if replace_vmca_cert():
        reset_all_certificates()