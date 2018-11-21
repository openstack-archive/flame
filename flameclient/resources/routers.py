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
from flameclient.utils import munchify


class RouterInterface(base_resources.TypedHotResource):
    type = 'OS::Neutron::RouterInterface'


class RouterGateway(base_resources.TypedHotResource):
    type = 'OS::Neutron::RouterGateway'


class Router(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::Router'
    property_keys = ('name', 'admin_state_up')

    @memoized_property
    def os_ports(self):
        return munchify(self.generator_memoize(
            self.conn.network.ports, device_id=self['id']
        ))

    @memoized_property
    def router_interfaces(self):
        router_interfaces = []
        for n, port in enumerate(self.os_ports):
            if port['device_owner'] != "network:router_interface":
                continue
            resource_name = "%s_interface_%d" % (self.name, n)
            subnet_resource_name = self.managers.subnets.get_resource_name(
                port['fixed_ips'][0]['subnet_id']
            )
            resource_id = ("%s:subnet_id=%s" %
                           (port['device_id'],
                            port['fixed_ips'][0]['subnet_id']))
            properties = {
                'subnet_id': {'get_resource': subnet_resource_name},
                'router_id': {'get_resource': self.name}
            }
            router_interfaces.append(
                RouterInterface(
                    self.manager, resource_name, resource_id, properties)
            )
        return router_interfaces

    @memoized_property
    def router_gateway(self):
        if self['external_gateway_info']:
            router_external_network_name = ("%s_external_network" % self.name)
            external_network = self['external_gateway_info']['network_id']
            properties = {
                'router_id': {'get_resource': self.name},
                'network_id': {'get_param': router_external_network_name}
            }
            gateway = RouterGateway(self.manager, "%s_gateway" % self.name,
                                    "%s:%s" % (self['id'], external_network),
                                    properties)
            description = "Router external network"
            constraints = [{'custom_constraint': "neutron.network"}]
            gateway.add_parameter(router_external_network_name, description,
                                  constraints=constraints,
                                  default=external_network)
            return gateway


class RoutersManager(base_resources.ResourceManager):

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.routers)
        )

    routers = api_resources

    def get_hot_resources(self):
        resources = []
        for rid, router in six.iteritems(self.api.routers):
            resource = Router(self, self.get_resource_name(rid), router)
            resources.append(resource)
            resources.extend(resource.router_interfaces)
            if resource.router_gateway:
                resources.append(resource.router_gateway)
        return resources
