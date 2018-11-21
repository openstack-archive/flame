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

import netaddr

from flameclient import resources as base_resources
from flameclient.utils import data_list_to_dict
from flameclient.utils import memoized_property


class Network(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::Net'
    property_keys = ('name', 'admin_state_up', 'shared')


class NetworksManager(base_resources.ResourceManager):

    def add_resource_networks(self, resource):
        addresses = resource.data.addresses
        networks = []
        for net_name in addresses:
            ip = addresses[net_name][0]['addr']
            for subnet in six.itervalues(self.api.subnets):
                if netaddr.IPAddress(ip) in netaddr.IPNetwork(subnet['cidr']):
                    for network in six.itervalues(self.api.networks):
                        if (network['name'] == net_name and
                                network['id'] == subnet['network_id']):
                            net = self.get_resource_name(subnet['network_id'])
                            networks.append({'network': {'get_resource': net}})
        if networks:
            resource.properties['networks'] = networks

    @memoized_property
    def all_networks(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.networks)
        )

    @property
    def api_resources(self):
        return self.all_networks

    @memoized_property
    def external_networks(self):
        return data_list_to_dict(
            (
                network for network in six.itervalues(self.all_networks)
                if network['router:external']
            ),
            enum=False  # Do not overwrite enumeration done in all_networks
        )

    @memoized_property
    def internal_networks(self):
        return data_list_to_dict(
            (
                network for network in six.itervalues(self.all_networks)
                if network.id not in self.external_networks
            ),
            enum=False  # Do not overwrite enumeration done in all_networks
        )

    def get_hot_resources(self):
        return [
            Network(self, self.get_resource_name(network.id), network)
            for network in six.itervalues(self.internal_networks)
        ]
