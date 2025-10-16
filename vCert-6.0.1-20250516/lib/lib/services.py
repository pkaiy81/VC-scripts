# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging
import sys

from lib.command_runner import CommandRunner
from lib.console import print_text_warning
from lib.host_utils import get_file_contents
from lib.text_utils import TextFilter
from lib.vmdir import get_vmdir_state

SERVICE_CONTROL_CLI = '/usr/bin/service-control'
VMON_CLI = '/usr/sbin/vmon-cli'

logger = logging.getLogger(__name__)

def get_vmon_service_profile():
    """
    Get vmon service profile
    """
    vmon_service_profile = get_file_contents('/storage/vmware-vmon/defaultStartProfile')
    return ['--vmon-profile', 'HAActive'] if 'HACore' in vmon_service_profile else ['--all']


def list_vmware_services():
    """
    Get a list of services present in the VC
    :param:
    :return: List of services 
    """
    output = CommandRunner(SERVICE_CONTROL_CLI, '--list-services').run_and_get_output().strip()
    services = TextFilter(output).cut(fields=[0]).get_lines()
    return services


def start_vmware_services(service=None):
    """
    Start VMware services
    :param service: to be started. If it's None, all service will be restarted
    :return: True if service(s) are started successfully. Otherwise, False
    """
    if service is None:
        service_profile = get_vmon_service_profile()
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--start', *service_profile).run()
    else:
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--start', service).run()

    if ret_code != 0:
        logger.error("Failed to start VMware services: {}".format(stderr))
        return False
    return True


def stop_vmware_services(service=None):
    """
    Stop VMware service
    :param service: to be stopped. If it's None, all service will be stopped
    :return: True if service(s) are started successfully. Otherwise, False
    """
    if service is None:
        service_profile = get_vmon_service_profile()
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--stop', *service_profile).run()
    else:
        ret_code, _, stderr = CommandRunner(SERVICE_CONTROL_CLI, '--stop', service).run()

    if ret_code != 0:
        logger.error("Failed to stop VMware services: {}".format(stderr))
        return False
    return True


def check_services_status():
    services = [['envoy', True, True],
                ['rhttpproxy', True, True],
                ['vmafdd', False, True],
                ['vmdird', False, True],
                ['vmware-vpostgres', True, False]]
    for service_info in services:
        service_name = service_info[0]
        managed_by_vmon = service_info[1]
        exit_if_stopped = service_info[2]
        if not is_service_running(service_name, managed_by_vmon):
            if exit_if_stopped:
                print_text_warning('The {} service is not running, the script cannot continue. Exiting...'.format(service_name))
                sys.exit(1)
            else:
                print_text_warning('\n-------------------------!!! Warning !!!-------------------------')
                print_text_warning('The {} service is not running, which may impact certain script operations.'.format(service_name))
                print_text_warning('For best results, please start the {} service.'.format(service_name))
        elif service_name == 'vmdird':
            vmdir_state = get_vmdir_state()
            logger.info('The VMware Directory service state is: {}'.format(vmdir_state))
            if vmdir_state not in  ['Normal', 'Standalone']:
                print_text_warning('The VMware Directory service is in the following state: {}. The script cannot continue. Exiting...'.format(vmdir_state))
                sys.exit(1)
    return


def is_service_running(service, managed_by_vmon=True):
    if managed_by_vmon:
        # determining status of services managed by vMon is quicker using vmon-cli as oppsed to service-control
        service_output = CommandRunner(VMON_CLI, '-s', '{}'.format(service)).run_and_get_output()
        run_state = TextFilter(service_output).start_with('RunState').cut(':', [1]).get_text().strip()
        logger.info('Service {} running state: {}'.format(service, run_state))
        if run_state == 'STARTED':
            return True
        else:
            return False
    else:
        # determining status of services managed by systemd is quicker using systemctl as oppsed to service-control
        service_output = CommandRunner('systemctl', 'status', '{}'.format(service)).run_and_get_output()
        run_state = TextFilter(service_output).contain('Active:').cut(':', [1]).cut(' ', [1]).get_text()
        logger.info('Service {} running state: {}'.format(service, run_state))
        if run_state == 'active':
            return True
        else:
            return False