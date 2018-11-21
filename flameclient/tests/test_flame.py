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

import os

from flameclient import flame
from flameclient.tests.fixtures import FIXTURES_DIR
from flameclient.tests import unittest
from flameclient.tests.utils import get_mocked_openstackcloud


class TestFlame(unittest.TestCase):
    def setUp(self):
        self.conn = get_mocked_openstackcloud()

    def test_flame(self):
        res_file = os.path.join(FIXTURES_DIR, 'results/flame.yaml')
        generator = flame.TemplateGenerator(
            connection=self.conn,
            options=dict(
                no_threads=True
            )
        )
        generator.extract_data()
        with open(res_file) as fp:
            result = fp.read()
        self.assertEqual(generator.heat_template_and_data(), result)

    def test_flame_adoption_data(self):
        res_file = os.path.join(
            FIXTURES_DIR, 'results/flame_adoption_data.yaml'
        )
        generator = flame.TemplateGenerator(
            connection=self.conn,
            options=dict(
                no_threads=True,
                generate_adoption_data=True
            )
        )
        generator.extract_data()
        with open(res_file) as fp:
            result = fp.read()
        self.assertEqual(generator.heat_template_and_data(), result)

    def test_flame_constraints(self):
        res_file = os.path.join(FIXTURES_DIR, 'results/flame_constraints.yaml')
        generator = flame.TemplateGenerator(
            connection=self.conn,
            options=dict(
                no_threads=True,
                include_constraints=True
            )
        )
        generator.extract_data()
        with open(res_file) as fp:
            result = fp.read()
        self.assertEqual(generator.heat_template_and_data(), result)

    def test_flame_extract_ports(self):
        res_file = os.path.join(
            FIXTURES_DIR, 'results/flame_extract_ports.yaml'
        )
        generator = flame.TemplateGenerator(
            connection=self.conn,
            options=dict(
                no_threads=True,
                extract_ports=True
            )
        )
        generator.extract_data()
        with open(res_file) as fp:
            result = fp.read()
        self.assertEqual(generator.heat_template_and_data(), result)

    def test_flame_constraints_extract_ports(self):
        res_file = os.path.join(
            FIXTURES_DIR, 'results/flame_constraints_extract_ports.yaml'
        )
        generator = flame.TemplateGenerator(
            connection=self.conn,
            options=dict(
                no_threads=True,
                extract_ports=True,
                include_constraints=True
            )
        )
        generator.extract_data()
        with open(res_file) as fp:
            result = fp.read()
        self.assertEqual(generator.heat_template_and_data(), result)
