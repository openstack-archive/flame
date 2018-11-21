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


class FloatingIP(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::FloatingIP'

    def __init__(self, manager, name, floating_ip, properties=None):
        super(FloatingIP, self).__init__(
            manager, name, floating_ip, properties
        )
        net_param_name = "external_network_for_%s" % self.name
        self.properties['floating_network_id'] = {'get_param': net_param_name}
        description = "Network to allocate floating IP from"
        constraints = [{'custom_constraint': "neutron.network"}]
        default = self.data['floating_network_id']
        self.add_parameter(net_param_name, description,
                           constraints=constraints,
                           default=default)

    @property
    def association(self):
        return self.managers.ports.get_fip_association(self) \
            or self.managers.servers.get_fip_association(self)


class FloatingIpsManager(base_resources.ResourceManager):

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.ips)
        )

    def get_hot_resources(self):
        floating_ips = [
            FloatingIP(self, self.get_resource_name(fip_id), floating_ip)
            for fip_id, floating_ip in six.iteritems(self.api.floating_ips)
        ]
        floating_ip_associations = [
            fip.association for fip in floating_ips
            if fip.association
        ]
        return floating_ips + floating_ip_associations
