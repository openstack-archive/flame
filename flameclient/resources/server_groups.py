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


class ServerGroup(base_resources.AdvancedHotResource):
    type = 'OS::Nova::ServerGroup'
    property_keys = ('name', 'policies')


class ServerGroupsManager(base_resources.ResourceManager):

    def add_resource_server_groups(self, resource):
        server = resource.data
        for servergroup in self.api_resources.values():
            if server.id in servergroup.members:
                hint = {
                    'group': {
                        'get_resource':
                        self.get_resource_name(servergroup.id)
                    }
                }
                resource.properties['scheduler_hints'] = hint

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.compute.server_groups)
        )

    def get_hot_resources(self):
        return [
            ServerGroup(self, self.get_resource_name(sg.id), sg)
            for sg in six.itervalues(self.api_resources)
        ]
