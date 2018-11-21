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

import six

from flameclient import resources as base_resources
from flameclient.utils import data_list_to_dict
from flameclient.utils import memoized_property


class KeyPair(base_resources.AdvancedHotResource):
    type = 'OS::Nova::KeyPair'
    property_keys = ('name', 'public_key',)


class KeypairsManager(base_resources.ResourceManager):

    def add_resource_keypair(self, resource):
        data = resource.data
        manager = resource.manager

        if data.key_name:
            if (
                self.options.exclude_keypairs or
                data.key_name not in self.api.keypairs
            ):
                key_parameter_name = "%s_key" % resource.name
                description = (
                    "Key for %s %s" % (manager.singular_name, resource.name)

                )
                constraints = [{'custom_constraint': "nova.keypair"}]
                resource.add_parameter(key_parameter_name, description,
                                       default=data.key_name,
                                       constraints=constraints)
                resource.properties['key_name'] = {
                    'get_param': key_parameter_name
                }
            else:
                resource.properties['key_name'] = {
                    'get_resource': self.get_resource_name(data.key_name)
                }

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument('--exclude-keypairs', action='store_true',
                            default=False,
                            help="Do not export key pair resources."
                            )
        return parser

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.compute.keypairs)
        )

    def get_hot_resources(self):
        if not self.options.exclude_keypairs:
            return [
                KeyPair(self, self.get_resource_name(resource.id), resource)
                for resource in six.itervalues(self.api.keypairs)
            ]
        return []
