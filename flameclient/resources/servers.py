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


class Server(base_resources.AdvancedHotResource):
    type = 'OS::Nova::Server'
    property_keys = ('name',)

    def __init__(self, manager, name, server, properties=None):
        super(Server, self).__init__(manager, name, server, properties)
        for property_name in ('config_drive', 'metadata'):
            if server[property_name]:
                self.properties[property_name] = server[property_name]
        self.managers.flavors.add_resource_flavor(self)
        self.managers.images.add_resource_image(self)
        self.managers.keypairs.add_resource_keypair(self)
        self.managers.ports.add_resource_ports_or_secgroups_and_networks(self)
        self.managers.volumes.add_resource_attached_volumes(self)
        self.managers.server_groups.add_resource_server_groups(self)


class NovaFloatingIpAssociation(base_resources.TypedHotResource):
    type = 'OS::Nova::FloatingIPAssociation'


class ServersManager(base_resources.ResourceManager):

    def get_fip_association(self, resource):
        ip = resource.data
        manager = resource.manager
        if not self.options.exclude_servers and ip['port_id']:
            server_id = self.api.ports[ip['port_id']]['device_id']
            if server_id and server_id in self.api.servers:
                server_resource_name = self.get_resource_name(server_id)
                resource_num = manager.get_resource_num(resource.id)
                properties = {
                    'floating_ip': {'get_resource': resource.name},
                    'server_id': {'get_resource': server_resource_name}
                }
                return NovaFloatingIpAssociation(
                    manager,
                    "floatingip_association_%d" % resource_num,
                    None,
                    properties
                )

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument('--exclude-servers', action='store_true',
                            default=False,
                            help="Do not export in template server resources.")
        return parser

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.compute.servers)
        )

    def get_hot_resources(self):
        if not self.options.exclude_servers:
            return [
                Server(self, self.get_resource_name(server.id), server)
                for server in six.itervalues(self.api.servers)
            ]
        return []
