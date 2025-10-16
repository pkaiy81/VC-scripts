# Copyright (c) 2024 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

import re

from lib.environment import Environment


class TextFilter(object):
    """
    A utility class for filtering multi-line text. The filtering methods in this
    class will return self to allow method chaining

    Example of usage:
    result = TextFilter(text).contain(filter).head(1).remove(unwanted_chars).get_text()
    """

    def __init__(self, text):
        self.lines = text.splitlines()
        self.before_lines = 0
        self.after_lines = 0
        self.invert_match = False

    def get_text(self):
        """
        Return the result as a string, joined by '\n'
        """
        return "\n".join(self.lines)

    def get_lines(self):
        """
        Return the current filtering result as a string list
        """
        return self.lines

    def set_options(self, before_lines=0, after_lines=0, invert_match=False):
        """
        Set the matching option

        :param before_lines: the result will also contain the before_lines lines
            before the matched line
        :param after_lines:  the result will also contain the after_lines lines
            after the matched lines
        :param invert_match: If True, the match operations will return lines that
            that don't match to the search pattern
        """
        self.before_lines = before_lines
        self.after_lines = after_lines
        self.invert_match = invert_match
        return self

    def reset_options(self):
        """
        Reset the matching option
        """
        self.before_lines = self.after_lines = 0
        self.invert_match = False
        return self

    def mod_match_result(self, match_result):
        return not match_result if self.invert_match else match_result

    def get_lines_with_extended_indices(self, indices):
        """
        Extend the matching lines indices by applying before_lines and after_lines
        matching options

        :param indices: indices to extend
        :return: extended indices
        """
        if self.before_lines > 0 or self.after_lines > 0:
            new_indices = []
            for index in indices:
                if self.before_lines > 0:
                    begin_index = index - self.before_lines
                    if begin_index < 0:
                        begin_index = 0
                    new_indices.extend([idx for idx in range(begin_index, index)])
                if self.after_lines > 0:
                    end_index = index + self.after_lines + 1
                    if end_index > len(self.lines):
                        end_index = len(self.lines)
                    new_indices.extend([idx for idx in range(index + 1, end_index)])
            indices.extend(new_indices)
            indices = sorted(set(indices))
        return [line for idx, line in enumerate(self.lines) if idx in indices]

    def match(self, pattern):
        """
        Filter lines using regular expression match

        :param pattern: regular expression pattern for matching the lines
        """
        indices = [idx for idx, line in enumerate(self.lines)
                   if self.mod_match_result(re.match(pattern, line))]
        self.lines = self.get_lines_with_extended_indices(indices)
        return self

    def contain(self, keyword):
        """
        Filter the lines using simple keywords

        :param keyword: keyword for matching the lines
        """
        indices = [idx for idx, line in enumerate(self.lines)
                   if self.mod_match_result(keyword in line)]
        self.lines = self.get_lines_with_extended_indices(indices)
        return self

    def start_with(self, text):
        """
        Filter the lines that started with {text}

        :param text: text for filtering
        """
        indices = [idx for idx, line in enumerate(self.lines)
                   if self.mod_match_result(line.find(text) == 0)]
        self.lines = self.get_lines_with_extended_indices(indices)
        return self

    def head(self, count=1):
        """
        Include only the first {count} lines to be included in the result

        :param count: total of lines to be included in the result. If the value is
            a negative value between -1 and -[number of lines], it will include all
            lines except of the last {count} lines at the end
        """
        if count < 0:
            count += len(self.lines)
            if count < 0:
                count = 0
        self.lines = [line for i, line in enumerate(self.lines) if i < count]
        return self

    def tail(self, count=1):
        """
        Includes only the last {count} lines

        :param count: total of lines to be included. If the value is a negative
            value between -1 and -[#lines], it will include all lines except the
            first {count} lines at the beginning
        :return:
        """
        length = len(self.lines)
        if count < 0:
            count += length
        self.lines = [line for i, line in enumerate(self.lines) if i >= length - count]
        return self

    def match_block(self, pattern_begin, pattern_end, concatenate=False):
        """
        Filter the lines using begin and end pattern

        :param pattern_begin: the pattern for starting the matching block
        :param pattern_end: the pattern for stopping the matching block
        :param concatenate: if True, the matching block will be concatenated
            as a single string joined using `\n' character
        """
        lines = []
        block = []
        matching = False
        for line in self.lines:
            if not matching and re.match(pattern_begin, line):
                matching = True
                block = []
            if matching:
                block.append(line)
            if matching and re.match(pattern_end, line):
                matching = False
                if concatenate:
                    lines.append('\n'.join(block))
                else:
                    lines.extend(block)
        self.lines = lines
        return self

    def apply(self, method):
        """
        Apply method on all lines. The lines will be replaced using the values returned
        by the method

        :param method:  method to be applied
        """
        self.lines = [method(line) for line in self.lines]
        return self

    def replace(self, keyword1, keyword2):
        """
        Update the lines by replacing keywords

        :param keyword1: keyword to be replaced
        :param keyword2: keyword to be used for replacing
        """
        self.lines = [line.replace(keyword1, keyword2) for line in self.lines]
        return self

    def remove(self, keyword):
        """
        Update all lines by removing {keyword}

        :param keyword: text to be removed
        """
        return self.replace(keyword, '')

    def remove_white_spaces(self):
        """
        Remove white spaces in all lines
        """
        return self.apply(remove_white_spaces_method)

    def cut(self, delimiter=' ', fields=None, new_delimiter=' ', include_empty=False):
        """
        Split the line using delimiter and include only the required fields.
        This method tries to mimics cut(1) command

        :param delimiter: The delimiter to be used for split the line
        :param fields: list of indices to be included (0 based index)
        :param new_delimiter: If specified, the result will be concenated back
            using the new_delimiter
        :param include_empty: If True, the result may also contain empty lines
            when the request fields are not available (default: False)
        """
        lines = []
        if fields is None:
            fields = []
        for line in self.lines:
            result = []
            words = line.split(delimiter)
            for idx in fields:
                if idx == -1:
                    idx = len(words) - 1
                if idx < len(words):
                    result.append(words[idx])
            if result or include_empty:
                lines.append(new_delimiter.join(result))
        self.lines = lines
        return self

    def get_count(self):
        """
        Get the count of lines in the current result
        """
        return len(self.lines)

    def dump(self):
        """
        Dump the current contents. This can be use for debugging purpose
        """
        print('Contents:', '\n'.join(self.lines), sep='\n')
        return self


def remove_white_spaces_method(text):
    """
    Method for removing white spaces to be specified to TextUtil.apply
    """
    return re.sub(r'\s+', '', text)


def translate_text(*text, sep=''):
    """
    Reformat text using mapping in the environment variables

    :param text: String parameters
    :param sep: Separator if the text contains multiple string parameters
    :return: reformatted text
    """
    text = sep.join(text)
    if text and '{' in text:
        env_map = Environment.get_environment().get_map()
        text = text.format_map(env_map)
    return text
