# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import getpass

from lib.console import ColorKey, print_text
from lib.environment import Environment
from lib.text_utils import translate_text


class MenuInput(object):
    """
    Class for getting user input. This class is separated from the rest of menu
    related classes due to a circular module dependency.
    """

    def __init__(self, text, acceptable_inputs=None, default_input=None, allow_empty_input=False,
                 case_insensitive=True, masked=False):
        """
        MenuInput constructor

        :param text: Text to be displayed on console before obtaining the user input
        :param acceptable_inputs: All acceptable input user can enter
        :param default_input: The default input to be shown and to be used when the user entered an empty input
        :param allow_empty_input: If this parameter is True, the input can return empty string when
            no default_input was specified
        :param case_insensitive: Ignore text case. If this option is True, MenuInput will return input with
            upper case
        :param masked: If this is True, user typed characters will not be shown on the console (e.g. for password
            input
        """
        self.text = text
        if acceptable_inputs and case_insensitive:
            self.acceptable_inputs = [s.upper() for s in acceptable_inputs]
        else:
            self.acceptable_inputs = acceptable_inputs
        self.default_input = default_input
        self.allow_empty_input = allow_empty_input
        self.case_insensitive = case_insensitive
        self.masked = masked

    def get_acceptable_input_str(self) -> str:
        """
        Return acceptable input is a simplified text

        This method expects that the acceptable_inputs will be in the following order:
        1, 2, ..., <num>, X, Y
        For above case, this method will return string like '1-<num>, X, Y'

        :return: Returns acceptable input text
        """
        keys = [s for s in self.acceptable_inputs if not s.isnumeric()]
        numeric_keys_count = len(self.acceptable_inputs) - len(keys)
        if numeric_keys_count == 1:
            keys.insert(0, '1')
        elif numeric_keys_count > 1:
            keys.insert(0, "{}-{}".format(1, numeric_keys_count))
        return ", ".join(keys)

    @staticmethod
    def builtin_input_wrapper(text, masked):
        """
        A wrapper method for the builtin method 'input'. This method is used to simplify
        mocking user input for the unit testing
        """
        if masked:
            return getpass.getpass(text)
        return input(text)

    def get_input(self) -> str:
        """
        Executing MenuInput: show the text, obtain and validate the user input
        """
        if self.default_input is not None:
            env = Environment.get_environment()
            env.set_value('CURRENT_MENU', {'__DEFAULT__': self.default_input})
        while True:
            text = translate_text(self.text)
            input_text = self.builtin_input_wrapper(text, self.masked)
            if self.case_insensitive:
                input_text = input_text.upper()
            if not input_text:
                if self.default_input is not None:
                    return self.default_input
                if self.allow_empty_input:
                    return ''
                else:
                    print_text('{}Invalid input.{}'.format(ColorKey.YELLOW, ColorKey.NORMAL))
                    continue
            elif self.acceptable_inputs:
                if input_text in self.acceptable_inputs:
                    return input_text
                else:
                    print_text("\n{}Invalid input. The acceptable inputs: {}{}\n".format(ColorKey.YELLOW, self.get_acceptable_input_str(), ColorKey.NORMAL))
            else:
                return input_text
