# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

class BaseScriptException(Exception):
    def __init__(self, error_msg):
        super().__init__(error_msg)


class LdapException(BaseScriptException):
    """
    Base Exception class for all the Exception in ldap functionality
    """
    def __init__(self, error_code, description):
        self.error_msg = "LDAP exception error code {} ({})".format(error_code, description)
        super().__init__(self.error_msg)

    def __str__(self):
        return self.error_msg


class MenuExitException(BaseScriptException):
    pass


class CommandExecutionError(BaseScriptException):
    pass


class CommandExecutionTimeout(BaseScriptException):
    pass


class ReplayEntryNotFound(BaseScriptException):
    pass


class OperationFailed(BaseScriptException):
    pass
