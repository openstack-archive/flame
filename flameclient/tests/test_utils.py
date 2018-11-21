# -*- coding: utf-8 -*-

# This software is released under the MIT License.
#
# Copyright (c) 2018 Orange Cloud for Business / Cloudwatt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from flameclient.tests import unittest
from flameclient import utils


class TestUtils(unittest.TestCase):
    def test_camel_to_snake(self):
        for inp, outp in (
            ('camelcase', 'camelcase'),
            ('Camelcase', 'camelcase'),
            ('camelCase', 'camel_case'),
            ('CamelCase', 'camel_case'),
            ('camelCCase', 'camel_c_case'),
            ('CCamelCase', 'c_camel_case'),
            ('CCCCamelCase', 'ccc_camel_case'),
            ('CCCcamelCase', 'cc_ccamel_case'),
            ('Camel123case', 'camel_123case'),
            ('Camel123Case', 'camel_123_case'),
        ):
            self.assertEqual(utils.camel_to_snake(inp), outp)

    def test_format_option(self):
        for option, formated in (
            ('--foo-bar', 'foo_bar'),
            ('--this-is-a-long-option', 'this_is_a_long_option')
        ):
            self.assertEqual(
                formated, utils.format_option(option)
            )

    def test_format_option_kwargs(self):
        self.assertEqual(
            {'foo_bar': 'value'}, utils.format_option_kwargs(
                {'--foo-bar': 'value'}
            )
        )
