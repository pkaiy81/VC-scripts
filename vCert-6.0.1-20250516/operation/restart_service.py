# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import logging

from lib.exceptions import OperationFailed, CommandExecutionError, MenuExitException
from lib.menu import Menu, MenuInput
from lib.host_utils import (
    list_vmware_services, start_vmware_services, stop_vmware_services
)

from lib.console import (
    print_task, print_task_status, print_task_status_warning, print_header, print_text_error
)

logger = logging.getLogger(__name__)

def restart_vmware_services(services=None):
    """
    Restart VMware services
    """
    print()
    acceptable_inputs = ['Y', 'N']

    services = [services] if type(services) == str else services
    if services is None:
        user_input = MenuInput('Restart VMware services [N]: ', acceptable_inputs=acceptable_inputs,
                               default_input='N')
    else:
        user_input = MenuInput("Restart service(s) {}{}{} [N]: "
                               .format('{COLORS[CYAN]}', ', '.join(services), '{COLORS[NORMAL]}'),
                               acceptable_inputs=acceptable_inputs, default_input='N')
    if user_input.get_input() == 'N':
        return

    print_header('Restarting Services')
    if services is None:
        print_task('Stopping VMware services')
        if not stop_vmware_services():
            print_task_status_warning('FAILED')
            error_message = 'Unable to stop all VMware services, check log for details'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')

        print_task('Starting VMware services')
        if not start_vmware_services():
            print_task_status_warning('FAILED')
            error_message = 'Unable to start all VMware services, check log for details'
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')
        return

    for service in services:
        print_task("Stopping {}".format(service))
        if not stop_vmware_services(service):
            print_task_status_warning('FAILED')
            error_message = "Unable to stop service {}, check log for details".format(service)
            print_text_error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')

        print_task("Starting {}".format(service))
        if not start_vmware_services(service):
            print_task_status_warning('FAILED')
            error_message = "Unable to start service {}, check log for details".format(service)
            logger.error(error_message)
            raise OperationFailed(error_message)
        print_task_status('OK')


def restart_specific_vmware_service():
    vmware_services = list_vmware_services()
    print()
    print('VMware services:')
    print(*vmware_services)
    service_to_restart = input('\nEnter VMware service to restart from the list above: ')

    while not service_to_restart:
        service_to_restart = input('\nEnter VMware service to restart: ')

    if service_to_restart in vmware_services:
        restart_vmware_services(service_to_restart)
    else:
        print_text_error(f'Error: Unknown service: {service_to_restart}')
