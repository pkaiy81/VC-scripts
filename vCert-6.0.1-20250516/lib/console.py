# Copyright (c) 2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import sys
import tempfile

from lib.environment import Environment, DefaultDict
from lib.text_utils import translate_text


class ColorKey(object):
    """
    Class for holding color mapping to its terminal escape sequence
    """
    RED = '{COLORS[RED]}'
    GREEN = '{COLORS[GREEN]}'
    BLUE = '{COLORS[BLUE]}'
    YELLOW = '{COLORS[YELLOW]}'
    CYAN = '{COLORS[CYAN]}'
    LIGHT_BLUE = '{COLORS[LIGHT_BLUE]}'
    UNDER_LINE = '{COLORS[UNDER_LINE]}'
    NORMAL = '{COLORS[NORMAL]}'


def init_env_colormap():
    """
    Initialize color map in the environment
    """
    env = Environment.get_environment()
    color_disabled = env.get_value('COLORS_DISABLED') is True
    if color_disabled:
        color_map = DefaultDict()
    else:
        color_map = {
            'RED': '\033[31m',
            'GREEN': '\033[32m',
            'YELLOW': '\033[33m',
            'BLUE': '\033[34m',
            'CYAN': '\033[36m',
            'LIGHT_BLUE': '\033[94m',
            'UNDER_LINE': '\033[04m',
            'NORMAL': '\033[00m'
        }
    env.set_value('COLORS', color_map)


def set_text_color(color):
    """
    Set the color. The color will affect any normal print() calls following this method call
    :param color: ColorKey object
    """
    print_text(color, end='')


def print_text(*text, max_width=0, sep='', end='\n'):
    """
    Print text with additional preprocessing based

    :param text: Text to be print. The text will be translated first
    :param max_width: if > 0, new line will be added automatically if each line
    :param sep: separator between text
    :param end: add end text after the last of line
    """
    text = translate_text(*text, sep=sep)
    if max_width > 0:
        text_len = len(text)
        idx = 0
        while idx < text_len:
            if idx + max_width < text_len:
                print(text[idx:max_width])
            else:
                print(text[idx:], end=end)
    else:
        print(text, end=end)
    sys.stdout.flush()


def print_text_warning(text, end='\n'):
    """
    Print warning text with yellow color.

    :param text: Text to be print
    :param end: end characters at the end of text
    """
    print_text(ColorKey.YELLOW, text, ColorKey.NORMAL, sep='', end=end)


def print_text_error(text, end='\n'):
    """
    Print error text. By default it's identical to print_text_warning,
    printing text with yellow color.
    """
    print_text_warning(text, end=end)


def print_header(text):
    """
    Print header text
    """
    print()
    print_text("{}{}".format(ColorKey.CYAN, text))
    print_text("{}{}".format('-' * 65, ColorKey.NORMAL))


def print_task(text):
    """
    Print formatted text for task name
    """
    print("{:<52}".format(text), end='', flush=True)


def print_task_status(status_text, color=ColorKey.GREEN):
    """
    Print formatted text for task status
    """
    set_text_color(color)
    print("{:>13}".format(status_text), end='')
    set_text_color(ColorKey.NORMAL)
    print(flush=True)


def print_task_status_warning(result):
    """
    Print warning task status (color: yellow)
    """
    print_task_status(result, ColorKey.YELLOW)


def print_task_status_error(result):
    """
    Print error task status (color: red)
    """
    print_task_status(result, ColorKey.RED)


def capture_method_output(method, *args, **kwargs):
    """
    Invoke the method and capture the stdout output produced by this method

    :param method: method to be invoked
    :return: captured stdout output
    """
    stdout = sys.stdout
    try:
        with tempfile.NamedTemporaryFile('w+') as file:
            sys.stdout = file
            method(*args, **kwargs)
            file.seek(0)
            return file.read()
    finally:
        sys.stdout = stdout


init_env_colormap()
