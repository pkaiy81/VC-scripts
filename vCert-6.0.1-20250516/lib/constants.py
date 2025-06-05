# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

VCERT_PROGRAM = 'vCert.py'
VCERT_NAME = 'VCF/VVF Certificate Management Utility'
VCERT_VERSION = '6.0.1'
VCERT_DESC = "{} (version {})".format(VCERT_NAME, VCERT_VERSION)

TOP_DIR = '/storage/vCert'
LOG_DIR = '/var/log/vmware/vCert'
REPORT_FILE_PATH = "{}/vcenter-certificate-report.txt".format(LOG_DIR)
VMCA_CERT_FILE_PATH = '/var/lib/vmware/vmca/root.cer'
VMCA_KEY_FILE_PATH = '/var/lib/vmware/vmca/privatekey.pem'
VMCA_SSO_FILE_PATH = '/etc/vmware-sso/keys/ssoserverRoot.crt'
VMCAM_CERT_FILE_PATH = '/var/lib/vmware/vmcam/ssl/vmcamcert.pem'
RBD_CERT_FILE_PATH = '/etc/vmware-rbd/ssl/rbd-ca.crt'
AUTH_PROXY_CERT_FILE_PATH = '/var/lib/vmware/vmcam/ssl/rui.crt'
RHTTPPROXY_CONFIG_FILE_PATH = '/etc/vmware-rhttpproxy/config.xml'
STS_SERVER_CONFIG_FILE_PATH = '/usr/lib/vmware-sso/vmware-sts/conf/server.xml'
LOCALHOST = 'localhost'
READ = 'read'
WRITE = 'write'
SPACE = " "
WARNING_TEXT = """
{COLORS[YELLOW]}------------------------!!! Attention !!!------------------------{COLORS[NORMAL]}

This script is intended to be used at the direction of Broadcom Global Support.

Changes made could render this system inoperable. Please ensure you have a valid
VAMI-based backup or offline snapshots of {COLORS[UNDER_LINE]}{COLORS[YELLOW]}ALL{COLORS[NORMAL]} vCenter/PSC nodes in the SSO domain
before continuing. Please refer to the following Knowledge Base article:
{COLORS[UNDER_LINE]}{COLORS[YELLOW]}https://knowledge.broadcom.com/external/article?legacyId=85662{COLORS[NORMAL]}

Do you acknowledge the risks and wish to continue? [y/n]: """
VMWARE_DEPOT_HOST = 'hostupdate.vmware.com'
VMWARE_DEPOT_CERT_ISSUER = 'DigiCert TLS RSA SHA256 2020 CA1'
