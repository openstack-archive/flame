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


class Port(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::Port'
    property_keys = ('admin_state_up', 'mac_address', 'device_owner')

    def __init__(self, manager, name, port, properties=None):
        super(Port, self).__init__(manager, name, port, properties)

        fixed_ips = []

        for fixed_ip_dict in port['fixed_ips']:
            subnet_id = fixed_ip_dict['subnet_id']
            subnet_resource_name = self.managers.subnets.get_resource_name(
                subnet_id
            )
            fixed_ip_resource = {
                u'subnet_id': {'get_resource': subnet_resource_name},
                u'ip_address': fixed_ip_dict['ip_address']
            }
            fixed_ips.append(fixed_ip_resource)

        net_resource_name = self.managers.networks.get_resource_name(
            port['network_id']
        )
        self.properties.update(
            {'network_id': {'get_resource': net_resource_name},
             'fixed_ips': fixed_ips}
        )
        if port['name'] != '':
            # This port has a name
            self.properties['name'] = port['name']

        self.managers.security_groups.add_resource_secgrp_props_and_params(
            self
        )


class NeutronFloatingIpAssociation(base_resources.TypedHotResource):
    type = 'OS::Neutron::FloatingIPAssociation'


class PortsManager(base_resources.ResourceManager):

    def get_fip_association(self, resource):
        ip = resource.data
        manager = resource.manager
        if ip['port_id'] and self.options.extract_ports:
            port_resource_name = self.get_resource_name(ip['port_id'])
            properties = {
                'floatingip_id': {'get_resource': resource.name},
                'port_id': {'get_resource': port_resource_name}
            }
            resource_num = manager.get_resource_num(resource.id)
            fip_assoc_id = ("%s:%s" % (ip['id'], ip['port_id']))
            return NeutronFloatingIpAssociation(
                manager,
                "floatingip_association_%d" % resource_num,
                fip_assoc_id,
                properties
            )

    def get_ports_for_resource(self, resource):
        ports = []
        for port in six.itervalues(self.api.ports):
            if port['device_id'] == resource.data.id:
                ports.append(self.get_resource_name(port.id))
        return ports

    def add_resource_ports_or_secgroups_and_networks(self, resource):
        if self.options.extract_ports:
            ports = [{"port": {"get_resource": port}}
                     for port in self.get_ports_for_resource(resource)]
            if ports:
                resource.properties['networks'] = ports
        else:
            self.managers.security_groups \
                .add_resource_secgrp_props_and_params(resource)

            self.managers.networks.add_resource_networks(resource)

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument('--extract-ports', action='store_true',
                            default=False,
                            help="Export the tenant network ports.")
        return parser

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.ports)
        )

    @memoized_property
    def port_resources(self):
        return [
            Port(self, self.get_resource_name(port.id), port)
            for port in six.itervalues(self.api.ports)
        ]

    def get_hot_resources(self):
        if self.options.extract_ports:
            return [
                port for port in self.port_resources
                if port['device_owner'].startswith('compute:')
            ]
        return []
