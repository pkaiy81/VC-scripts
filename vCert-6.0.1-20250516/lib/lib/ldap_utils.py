# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import copy
import hashlib
import json
import logging
import ldap3 as ldap

from lib.environment import Environment
from lib.exceptions import LdapException
from lib.execution_replay import ReplayContext

logger = logging.getLogger(__name__)


class Ldap:

    @staticmethod
    def open_ldap_connection(node, user_dn, password):
        """
        Open ldap connection to the ldap server provided with
        ldap admin user credentials.
        :param node: hostname of the ldap server
        :param user_dn: User DN for authentication
        :param password: Password for authentication
        :return:
        """
        logger.info("Opening connection to {} with user {}".format(node, user_dn))
        server = ldap.Server(get_uri_from_hostname(node), get_info=ldap.ALL)

        env = Environment.get_environment()
        is_remote_exec = env.get_value('VCERT_REMOTE_EXEC') is True
        is_replay = env.get_value('VCERT_REMOTE_EXEC_REPLAY') is True
        is_capture = env.get_value('VCERT_REMOTE_EXEC_CAPTURE') is True
        if is_remote_exec and (is_replay or is_capture):
            context = ReplayContext.get_replay_context()
            ldap_connection = LdapConnectionReplay(context, server, user_dn, password)
        else:
            ldap_connection = ldap.Connection(server, user=user_dn, password=password)

        if not ldap_connection.bind():
            logger.error("Failed to do LDAP bind with host %s with %s error",
                         node, ldap_connection.result['description'])
            raise LdapException(ldap_connection.result['result'], ldap_connection.result['description'])
        return ldap_connection

    @staticmethod
    def close_ldap_connection(ldap_connection) -> None:
        """
        Close the ldap bind connection
        :param ldap_connection:ldap connection to be closed
        :return:
        """
        logger.info("Closing LDAP connection")
        ldap_connection.unbind()
        if not ldap_connection.closed:
            logger.error("Error closing connection. Error Msg: %s", ldap_connection.result["message"])

    @staticmethod
    def ldap_search(ldap_connection, base_dn, ldap_filter, ldap_scope, ldap_attributes) -> bool:
        """
        This method takes the ldap connection, base dn, filter , scope
        and list of ldap attributes to be returned.
        :param ldap_connection  connection to ldap server
        :param base_dn dn where the search starts
        :param ldap_filter to filter the search the results
        :param ldap_scope scope of the search
        :param ldap_attributes list of ldap attributes to be returned
        """
        logger.info("LDAP search with\n  base DN:%s\n  filter: %s\n  scope: %s\n  attributes: %s",
                    base_dn, ldap_filter, str(ldap_scope), str(" ".join(ldap_attributes)))
        if ldap_connection is None:
            raise LdapException("-1", "No LDAP connection")
        else:
            if not ldap_connection.bind():
                raise LdapException(ldap_connection.result['result'], ldap_connection.result['description'])
            result = ldap_connection.search(base_dn, ldap_filter, ldap_scope, attributes=ldap_attributes)
            # When a filter doesn't match any entry result will be false
            if result or (ldap_connection.result and ldap_connection.result['result'] == 0):
                return True
        logger.error("LDAP search failed. Error message: %s", ldap_connection.result["message"])
        return False

    @staticmethod
    def get_attribute(ldap_entry, attribute) -> str:
        """
        get the attribute value for a given ldap entry
        This function can only be used for single value attributes.
        :param ldap_entry: ldap entry
        :param attribute: attribute to be returned
        :return: value which is string
        """
        val = ldap_entry['attributes'][attribute]
        if isinstance(val, str):
            return val
        return val[0]

    @staticmethod
    def ldap_delete(ldap_connection, entry_dn):
        """
        This method takes ldap connection and deletes a given entry
        :param ldap_connection: LDAP connection
        :param entry_dn: entry DN to be delete
        :return:
        """
        logger.info("LDAP delete with DN: %s", entry_dn)
        if ldap_connection is None:
            logger.debug("No ldap connection")
            raise LdapException("-1", "No LDAP connection")
        else:
            if not ldap_connection.bind():
                raise LdapException(ldap_connection.result['result'], ldap_connection.result['description'])
            if ldap_connection.delete(entry_dn):
                logger.debug("Deleted entry DN: %s", entry_dn)
                return True
            else:
                if ldap_connection.result['result'] == 32:
                    logger.debug("Entry to be deleted %s doesn't exist", entry_dn)
                    return True
                logger.error("Error deleting entry DN: %s, error code %s error msg %s",
                             entry_dn, ldap_connection.result['result'],
                             ldap_connection.result['description'])
                return False

    @staticmethod
    def ldap_modify(ldap_connection, dn, attribute, operation, value=None):
        """
        This method takes ldap connection, DN and single attribute modification
        for that particular DN
        :param ldap_connection:
        :param dn:
        :param attribute:
        :param operation:
        :param value:
        :return:
        """
        logger.info("LDAP modify for DN %s with\n  attribute: %s\n  operation: %s\n  value: %s",
                    dn, attribute, operation, value)
        if ldap_connection is None:
            logger.debug("No ldap connection")
            raise LdapException("-1", "No Ldap connection")
        if not ldap_connection.bind():
            raise LdapException(ldap_connection.result['result'], ldap_connection.result['description'])
        if value is None:
            value = []
        changes = [(operation, value)] if type(value) is list else [(operation, [value])]
        result = ldap_connection.modify(dn, {attribute: changes})
        if result:
            logger.info("Modified DN:%s", dn)
            return True

        logger.error("Modifying entry %s failed with error code %s, description %s",
                     dn, ldap_connection.result['result'], ldap_connection.result['description'])
        return False

    @staticmethod
    def ldap_add(ldap_connection, dn, object_class, attributes):
        """
        Add new LDAP entry with DN and attributes {attributes}
        :param ldap_connection: LDAP connection
        :param dn: DN to add
        :param attributes: attributes
        """
        logger.info("LDAP add for DN %s with\n attributes: %s\n", dn, str(attributes))
        if ldap_connection is None:
            logger.debug("No ldap connection")
            raise LdapException("-1", "No Ldap connection")
        if not ldap_connection.bind():
            raise LdapException(ldap_connection.result['result'], ldap_connection.result['description'])
        result = ldap_connection.add(dn, object_class, attributes)
        if result:
            logger.info("Added DN:%s", dn)
            return True

        logger.error("Adding entry %s failed with error code %s, description %s",
                     dn, ldap_connection.result['result'], ldap_connection.result['description'])
        return False


class LdapConnectionReplay(object):
    """
    Class for capturing and replaying the previous LDAP operation results
    """
    def __init__(self, context: ReplayContext, server, user_dn, password):
        self.context = context
        self.server = server
        self.user_dn = user_dn
        self.password = password
        self.credential_hash = hashlib.sha1("{}:{}".format(user_dn, password).encode('utf-8')).hexdigest()
        self.ldap_connection = ldap.Connection(server, user_dn, password) if self.context.is_capturing else None
        self.closed = True
        self.result = None
        self.response = None

    def operation_wrapper(self, name, func, args, pass_connection=True):
        final_args = [name]
        final_args.extend(args)
        if self.context.is_replaying:
            prev_result = self.context.get_execution_result('ldap', final_args, self.credential_hash)
            if prev_result is not None:
                return_value, result_text, _ = prev_result
                result = ReplayContext.decode_bytes(json.loads(result_text))
                self.result = result['_result_']
                self.response = result['_response_']
                self.closed = result['_closed_']
                if self.ldap_connection and func == self.ldap_connection.unbind:
                    self.ldap_connection.unbind()
                return return_value

        return_value = func(self.ldap_connection, *args) if pass_connection else func(*args)
        self.result = self.ldap_connection.result
        self.response = self.ldap_connection.response
        self.closed = self.ldap_connection.closed
        result = dict()
        result['_result_'] = ReplayContext.encode_bytes(copy.deepcopy(self.result))
        result['_response_'] = ReplayContext.encode_bytes(copy.deepcopy(self.response))
        result['_closed_'] = self.closed
        try:
            result_text = json.dumps(result, skipkeys=True)
        except TypeError as te:
            raise LdapException("Unserializable object: {}".format(result), str(te))
        self.context.store_result('ldap', final_args, self.credential_hash, return_value, result_text, None)
        return return_value

    def bind(self):
        func = self.ldap_connection.bind if self.ldap_connection else None
        return self.operation_wrapper('bind', func, [], False)

    def unbind(self):
        func = self.ldap_connection.unbind if self.ldap_connection else None
        return self.operation_wrapper('unbind', func, [], False)

    def search(self, search_base, search_filter, search_scope, attributes):
        args = [search_base, search_filter, search_scope, attributes]
        return self.operation_wrapper('search', Ldap.ldap_search, args)

    def modify(self, dn, changes):
        attribute = list(changes.keys())[0]
        operation, values = changes[attribute][0]
        args = [dn, attribute, operation, values]
        return self.operation_wrapper('modify', Ldap.ldap_modify, args)

    def delete(self, dn):
        return self.operation_wrapper('delete', Ldap.ldap_delete, [dn])

    def add(self, dn, object_class, attributes):
        return self.operation_wrapper('add', Ldap.ldap_add, [dn, object_class, attributes])


def get_uri_from_hostname(hostname):
    return "ldap://{}".format(hostname)


def get_domain_dn(domain):
    if '@' in domain:
        domain = domain.split('@', 2)[1]
    domain_parts = domain.split('.')
    return "dc={}".format(",dc=".join(domain_parts))


def get_user_dn(user_upn: str):
    username, domain = tuple(user_upn.split('@'))
    domain_dn = get_domain_dn(domain)
    return "cn={},cn=users,{}".format(username, domain_dn)
