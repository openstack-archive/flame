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


class Subnet(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::Subnet'
    property_keys = (
        'name',
        'allocation_pools',
        'cidr',
        'dns_nameservers',
        'enable_dhcp',
        'host_routes',
        'ip_version',
    )

    def __init__(self, manager, name, data, properties=None):
        super(Subnet, self).__init__(manager, name, data, properties)
        net_name = self.managers.networks.get_resource_name(self['network_id'])
        self.properties['network_id'] = {'get_resource': net_name}


class SubnetsManager(base_resources.ResourceManager):

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.subnets)
        )

    def get_hot_resources(self):
        return [
            Subnet(self, self.get_resource_name(subnet.id), subnet)
            for subnet in six.itervalues(self.api.subnets)
            if subnet['network_id'] in self.managers.networks.internal_networks
        ]
