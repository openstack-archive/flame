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
from pprint import pformat

import six

from flameclient.utils import get_deep_attr
from flameclient.utils import munchify


def get_licence():
    import flameclient
    licence_filename = os.path.join(
        os.path.realpath(os.path.dirname(flameclient.__file__)),
        'LICENSE.txt'
    )
    with open(licence_filename) as fp:
        return fp.read()


def get_python_header():
    top = '# -*- coding: utf-8 -*-'
    lines = get_licence().strip().split('\n')
    commented_lines = ['# %s' % line.strip() for line in lines]
    commented_lines = [line.strip() for line in commented_lines]
    commented_licence = '\n'.join(commented_lines)
    return '%s\n\n%s\n' % (top, commented_licence)


def write_openstackcloud_fixture_data(filename, attr_name, data):
    """Write a fixtures file with given data

    :param str filename: filename holding the fixtures.
    :param str attr_name: attribute name of the `connection` parameter.

    :param list data: a python list of data which needs to be returned

    """
    fixtures = [vars(munchify(element)) for element in data]

    openstackcloud_dir = os.path.join(
        os.path.realpath(os.path.dirname(__file__)),
        'openstackcloud'
    )

    if not filename.startswith('/'):
        filename = os.path.join(openstackcloud_dir, filename)

    head = get_python_header()

    file_str = "%s\n\nNAME = '%s'\n\nFIXTURES = %s\n" % (
        head, attr_name, pformat(fixtures, indent=1)
    )
    with open(filename, 'w') as fp:
        fp.write(file_str)


def write_openstackcloud_fixture(filename, attr_name, connection):
    """Write a fixtures API call file

    :param str filename: filename holding the fixtures.
    :param str attr_name: attribute name of the `connection` parameter.

    :param openstack.connection.Connection connection:
        An `openstack.connection.Connection` instance (`openstacksdk`).
        Since `shade.openstackcloud.OpenStackCloud` (`shade`) is a subclass
        you can also use shade instances.

    ex. to write connection.network.security_groups to a fixtures file:

        write_openstackcloud_fixture(
            'flameclient/tests/fixtures/openstackcloud/security_groups.py',
            'network.security_groups',
            connection
        )

    """
    method = get_deep_attr(connection, attr_name)
    write_openstackcloud_fixture_data(filename, attr_name, method())


def rewrite_all_openstackcloud_fixtures(connection):
    """Rewrite all fixtures in flameclient.tests.fixtures

    This function rewrites all fixture files present in
    flameclient.tests.fixtures from an existing openstack session.

    :param openstack.connection.Connection connection:
        An `openstack.connection.Connection` instance (`openstacksdk`).
        Since `shade.openstackcloud.OpenStackCloud` (`shade`) is a subclass
        you can also use shade instances.

    DANGEROUS! You can break everything!!!
    """
    from flameclient.tests.fixtures import openstackcloud
    for fixture_module in six.itervalues(openstackcloud.FIXTURES):
        write_openstackcloud_fixture(
            fixture_module.__file__,
            fixture_module.NAME,
            connection
        )
