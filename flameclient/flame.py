# -*- coding: utf-8 -*-

# This software is released under the MIT License.
#
# Copyright (c) 2014 Cloudwatt
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

import logging

import netaddr
import yaml

from flameclient import managers


logging.basicConfig(level=logging.ERROR)

template_skeleton = '''
heat_template_version: 2013-05-23
description: Generated template
parameters:
resources:
'''

stack_data_skeleton = '''
status: 'COMPLETE'
action: 'CREATE'
resources:
'''


class TemplateGenerator(object):
    template = None
    stack_data = None

    def __init__(self, username, password, tenant_name, auth_url, insecure):
        self.generate_data = False
        self._setup_templates()
        self._setup_managers(username, password, tenant_name, auth_url,
                             insecure)

    def _setup_templates(self):
        self.template = yaml.load(template_skeleton)
        self.template['resources'] = {}
        self.template['parameters'] = {}

        self.stack_data = yaml.load(stack_data_skeleton)
        self.stack_data['resources'] = {}

    def _setup_managers(self, username, password, tenant_name, auth_url,
                        insecure):
        self.neutron = managers.NeutronManager(username, password, tenant_name,
                                               auth_url, insecure)
        self.nova = managers.NovaManager(username, password, tenant_name,
                                         auth_url, insecure)
        self.cinder = managers.CinderManager(username, password, tenant_name,
                                             auth_url, insecure)

    def extract_vm_details(self, exclude_servers, exclude_volumes,
                           generate_data):
        self.exclude_servers = exclude_servers
        self.exclude_volumes = exclude_volumes
        self.generate_data = generate_data

        self.subnets = self.build_data(self.neutron.subnet_list())
        self.networks = self.build_data(self.neutron.network_list())
        self.routers = self.neutron.router_list()
        self.secgroups = self.build_data(self.neutron.secgroup_list())
        self.floatingips = self.neutron.floatingip_list()
        self.ports = self.build_data(self.neutron.port_list())
        self.external_networks = []

        self.keys = dict(
            (key.name, (index, key))
            for index, key in enumerate(self.nova.keypair_list()))

        if not exclude_servers:
            self.flavors = self.build_data(self.nova.flavor_list())
            self.servers = self.build_data(self.nova.server_list())

        if (not exclude_volumes or
                (exclude_volumes and not exclude_servers)):
            self.volumes = self.build_data(self.cinder.volume_list())

    def build_data(self, data):
        if not data:
            return {}

        if isinstance(data[0], dict):
            return dict((element['id'], (index, element))
                        for index, element in enumerate(data))
        else:
            return dict((element.id, (index, element))
                        for index, element in enumerate(data))

    @staticmethod
    def print_generated(filename):
        print(yaml.safe_dump(filename, default_flow_style=False))

    def add_resource(self, name, status, resource_id, resource_type):
        resource = {
            name: {
                'status': status,
                'name': name,
                'resource_data': {},
                'resource_id': resource_id,
                'action': 'CREATE',
                'type': resource_type,
                'metadata': {}
            }
        }
        self.stack_data['resources'].update(resource)

    def add_parameter(self, name, description, parameter_type,
                      constraints=None, default=None):
        parameter = {
            name: {
                'type': parameter_type,
                'description': description,
            }
        }
        # (arezmerita) disable cause heat bug #1314240
        # if constraints:
        #    parameter[name]['constraints'] = constraints
        if default:
            parameter[name]['default'] = default
        self.template['parameters'].update(parameter)

    def add_router_gateway_resource(self, router_resource_name, router):
        router_external_network_name = ("%s_external_network" %
                                        router_resource_name)
        router_gateway_name = "%s_gateway" % router_resource_name
        resource_type = 'OS::Neutron::RouterGateway'
        description = "Router external network"
        constraints = [{'custom_constraint': "neutron.network"}]
        external_network = router['external_gateway_info']['network_id']
        self.add_parameter(router_external_network_name, description,
                           'string', constraints=constraints,
                           default=external_network)

        if self.generate_data:
            resource_id = "%s:%s" % (router['id'], external_network)
            self.add_resource(router_gateway_name,
                              'COMPLETE',
                              resource_id,
                              resource_type)

        resource = {
            router_gateway_name: {
                'type': resource_type,
                'properties': {
                    'router_id': {'get_resource': router_resource_name},
                    'network_id': {'get_param': router_external_network_name}
                }
            }
        }
        self.template['resources'].update(resource)

    def add_router_interface_resources(self, router_resource_name, ports):
        for n, port in enumerate(ports):
            if port['device_owner'] == "network:router_interface":
                port_resource_name = ("%s_interface_%d" %
                                      (router_resource_name, n))
                resource_type = 'OS::Neutron::RouterInterface'
                subnet_resource_name = self.get_subnet_resource_name(
                    port['fixed_ips'][0]['subnet_id'])

                if self.generate_data:
                    resource_id = ("%s:subnet_id=%s" %
                                   (port['device_id'],
                                    port['fixed_ips'][0]['subnet_id']))
                    self.add_resource(port_resource_name, 'COMPLETE',
                                      resource_id, resource_type)

                resource = {
                    port_resource_name: {
                        'type': resource_type,
                        'properties': {
                            'subnet_id': {
                                'get_resource': subnet_resource_name},
                            'router_id': {
                                'get_resource': router_resource_name}
                        }
                    }
                }
                self.template['resources'].update(resource)

    def _extract_routers(self):
        for n, router in enumerate(self.routers):
            router_resource_name = "router_%d" % n
            resource_type = 'OS::Neutron::Router'
            resource = {
                router_resource_name: {
                    'type': resource_type,
                    'properties': {
                        'name': router['name'],
                        'admin_state_up': router['admin_state_up'],
                    }
                }
            }

            if self.generate_data:
                self.add_resource(router_resource_name,
                                  'COMPLETE',
                                  router['id'],
                                  resource_type)

            self.template['resources'].update(resource)
            self.add_router_interface_resources(
                router_resource_name,
                self.neutron.router_interfaces_list(router))
            if router['external_gateway_info']:
                self.add_router_gateway_resource(router_resource_name,
                                                 router)

    def _extract_networks(self):
        for n, network in self.networks.values():
            if network['router:external']:
                self.external_networks.append(network['id'])
                continue
            network_resource_name = "network_%d" % n
            resource_type = 'OS::Neutron::Net'

            if self.generate_data:
                self.add_resource(network_resource_name,
                                  'COMPLETE',
                                  network['id'],
                                  resource_type)

            resource = {
                network_resource_name: {
                    'type': resource_type,
                    'properties': {
                        'name': network['name'],
                        'admin_state_up': network['admin_state_up'],
                        'shared': network['shared']
                    }
                }
            }
            self.template['resources'].update(resource)

    def get_network_resource_name(self, network_id):
        return "network_%d" % self.networks[network_id][0]

    def get_subnet_resource_name(self, subnet_id):
        return "subnet_%d" % self.subnets[subnet_id][0]

    def _extract_subnets(self):
        for n, subnet in self.subnets.values():
            if subnet['network_id'] in self.external_networks:
                continue
            subnet_resource_name = "subnet_%d" % n
            resource_type = 'OS::Neutron::Subnet'

            if self.generate_data:
                self.add_resource(subnet_resource_name,
                                  'COMPLETE',
                                  subnet['id'],
                                  resource_type)
            net_name = self.get_network_resource_name(subnet['network_id'])
            resource = {
                subnet_resource_name: {
                    'type': resource_type,
                    'properties': {
                        'name': subnet['name'],
                        'allocation_pools': subnet['allocation_pools'],
                        'cidr': subnet['cidr'],
                        'dns_nameservers': subnet['dns_nameservers'],
                        'enable_dhcp': subnet['enable_dhcp'],
                        'host_routes': subnet['host_routes'],
                        'ip_version': subnet['ip_version'],
                        'network_id': {'get_resource': net_name}
                    }
                }
            }
            self.template['resources'].update(resource)

    def _build_rules(self, rules):
        brules = []
        for rule in rules:
            if rule['protocol'] == 'any':
                del rule['protocol']
            rg_id = rule['remote_group_id']
            if rg_id is not None:
                rule['remote_mode'] = "remote_group_id"
                resource_name = "security_group_%d" % self.secgroups[rg_id][0]
                if rg_id == rule['security_group_id']:
                    del rule['remote_group_id']
                else:
                    rule['remote_group_id'] = {'get_resource': resource_name}
            del rule['tenant_id']
            del rule['id']
            del rule['security_group_id']
            rule = dict((k, v) for k, v in rule.iteritems() if v is not None)
            brules.append(rule)
        return brules

    def _extract_secgroups(self):
        for n, secgroup in self.secgroups.values():

            resource_name = "security_group_%d" % n
            resource_type = 'OS::Neutron::SecurityGroup'

            if secgroup['name'] == 'default' and self.generate_data:
                continue

            if secgroup['name'] == "default":
                secgroup['name'] = "_default"

            if self.generate_data:
                self.add_resource(resource_name, 'COMPLETE',
                                  secgroup['id'], resource_type)

            rules = self._build_rules(secgroup['security_group_rules'])
            resource = {
                resource_name: {
                    'type': resource_type,
                    'properties': {
                        'description': secgroup['description'],
                        'name': secgroup['name'],
                        'rules': rules,
                    }
                }
            }
            self.template['resources'].update(resource)

    def _extract_keys(self):
        for n, key in self.keys.values():
            key_resource_name = "key_%d" % n
            resource_type = 'OS::Nova::KeyPair'

            if self.generate_data:
                self.add_resource(key_resource_name,
                                  'COMPLETE',
                                  key.id,
                                  resource_type)

            resource = {
                key_resource_name: {
                    'type': resource_type,
                    'properties': {
                        'name': key.name,
                        'public_key': key.public_key
                    }
                }
            }
            self.template['resources'].update(resource)

    def build_secgroups(self, server):
        security_groups = []
        server_secgroups = set(self.nova.server_security_group_list(server))

        secgroup_default_parameter = None
        for secgr in server_secgroups:
            if secgr.name == 'default' and self.generate_data:
                if not secgroup_default_parameter:
                    server_res_name = 'server_%d' % self.servers[server.id][0]
                    param_name = "%s_default_security_group" % server_res_name
                    description = ("Default security group for server %s" %
                                   server.name)
                    default = secgr.id
                    self.add_parameter(param_name, description,
                                       'string', default=default)
                    secgroup_default_parameter = {'get_param': param_name}
                security_groups.append(secgroup_default_parameter)
            else:
                resource_name = ("security_group_%d" %
                                 self.secgroups[secgr.id][0])
                security_groups.append({'get_resource': resource_name})

        return security_groups

    def build_networks(self, addresses):
        networks = []
        for net_name in addresses:
            ip = addresses[net_name][0]['addr']
            for s, subnet in self.subnets.values():
                if netaddr.IPAddress(ip) in netaddr.IPNetwork(subnet['cidr']):
                    for n, network in self.networks.values():
                        if (network['name'] == net_name and
                                network['id'] == subnet['network_id']):
                            net = self.get_network_resource_name(
                                subnet['network_id'])
                            networks.append({'network': {'get_resource': net}})
        return networks

    def _extract_servers(self):
        for n, server in self.servers.values():
            resource_name = "server_%d" % n
            resource_type = 'OS::Nova::Server'

            if self.generate_data:
                self.add_resource(resource_name,
                                  'COMPLETE',
                                  server.id,
                                  resource_type)

            properties = {
                'name': server.name,
                'diskConfig': getattr(server, 'OS-DCF:diskConfig')
            }

            if server.config_drive:
                properties['config_drive'] = server.config_drive

            # Flavor
            flavor_parameter_name = "%s_flavor" % resource_name
            description = "Flavor to use for server %s" % resource_name
            default = self.flavors[server.flavor['id']][1].name
            self.add_parameter(flavor_parameter_name, description, 'string',
                               default=default)
            properties['flavor'] = {'get_param': flavor_parameter_name}

            # Image
            if server.image:
                image_parameter_name = "%s_image" % resource_name
                description = (
                    "Image to use to boot server %s" % resource_name)
                constraints = [{'custom_constraint': "glance.image"}]
                self.add_parameter(
                    image_parameter_name, description, 'string',
                    default=server.image['id'], constraints=constraints)
                properties['image'] = {'get_param': image_parameter_name}

            # Keypair
            if server.key_name and server.key_name in self.keys:
                resource_key = "key_%d" % self.keys[server.key_name][0]
                properties['key_name'] = {'get_resource': resource_key}

            security_groups = self.build_secgroups(server)
            if security_groups:
                properties['security_groups'] = security_groups

            networks = self.build_networks(server.addresses)
            if networks:
                properties['networks'] = networks

            if server.metadata:
                properties['metadata'] = server.metadata

            server_volumes = []
            key = 'os-extended-volumes:volumes_attached'
            for server_volume in getattr(server, key):
                volume = self.volumes[server_volume['id']]
                volume_resource_name = "volume_%d" % volume[0]
                device = volume[1].attachments[0]['device']
                if not self.exclude_volumes:
                    server_volumes.append(
                        {'volume_id': {'get_resource': volume_resource_name},
                         'device_name': device})
                else:
                    volume_parameter_name = ("volume_%s_%d" %
                                             (server.name, volume[0]))
                    description = ("Volume for server %s, device %s" %
                                   (server.name, device))
                    server_volumes.append(
                        {'volume_id': {'get_param': volume_parameter_name},
                         'device_name': device})
                    self.add_parameter(volume_parameter_name, description,
                                       'string', default=server_volume['id'])
            if server_volumes:
                properties['block_device_mapping'] = server_volumes

            resource = {
                resource_name: {
                    'type': resource_type,
                    'properties': properties
                }
            }
            self.template['resources'].update(resource)

    def _extract_floating(self):
        for n, ip in enumerate(self.floatingips):
            ip_resource_name = "floatingip_%d" % n
            net_param_name = "external_network_for_floating_ip_%d" % n
            resource_type = 'OS::Neutron::FloatingIP'

            if self.generate_data:
                self.add_resource(ip_resource_name,
                                  'COMPLETE',
                                  ip['id'],
                                  resource_type)

            floating_resource = {
                ip_resource_name: {
                    'type': resource_type,
                    'properties': {
                        'floating_network_id': {'get_param': net_param_name}
                    }
                }
            }
            description = "Network to allocate floating IP from"
            constraints = [{'custom_constraint': "neutron.network"}]
            default = ip['floating_network_id']
            self.add_parameter(net_param_name, description, 'string',
                               constraints=constraints, default=default)
            if not self.exclude_servers and ip['port_id']:
                device = self.ports[ip['port_id']][1]['device_id']
                if device and self.servers[device]:
                    server = self.servers[device]
                    resource_name = "floatingip_association_%d" % n
                    server_resource_name = "server_%d" % server[0]
                    resource_type = 'OS::Nova::FloatingIPAssociation'
                    resource = {
                        resource_name: {
                            'type': resource_type,
                            'properties': {
                                'floating_ip': {
                                    'get_resource': ip_resource_name
                                },
                                'server_id': {
                                    'get_resource': server_resource_name
                                }
                            }
                        }
                    }
                    self.template['resources'].update(resource)
            self.template['resources'].update(floating_resource)

    def _extract_volumes(self):
        for n, volume in self.volumes.values():
            resource_name = "volume_%d" % n
            resource_type = 'OS::Cinder::Volume'

            if self.generate_data:
                self.add_resource(resource_name, 'COMPLETE',
                                  volume.id, resource_type)

            properties = {
                'size': volume.size
            }
            if volume.source_volid:
                if volume.source_volid in self.volumes:
                    key = "volume_%d" % self.volumes[volume.source_volid][0]
                    properties['source_volid'] = {'get_resource': key}
                else:
                    key = "%s_source_volid" % resource_name
                    description = (
                        "Volume to create volume %s from" % resource_name)
                    self.add_parameter(key, description, 'string')
                    properties['source_volid'] = {'get_param': key}
            if volume.bootable == 'true' and not volume.snapshot_id:
                key = "%s_image" % resource_name
                description = "Image to create volume %s from" % resource_name
                constraints = [{'custom_constraint': "glance.image"}]
                default = volume.volume_image_metadata['image_id']
                self.add_parameter(key, description, 'string',
                                   constraints=constraints,
                                   default=default)
                properties['image'] = {'get_param': key}
            if volume.snapshot_id:
                key = "%s_snapshot_id" % resource_name
                properties['snapshot_id'] = {'get_param': key}
                description = (
                    "Snapshot to create volume %s from" % resource_name)
                self.add_parameter(key, description, 'string',
                                   default=volume.snapshot_id)
            if volume.display_name:
                properties['name'] = volume.display_name
            if volume.display_description:
                properties['description'] = volume.display_description
            if volume.volume_type and volume.volume_type != 'None':
                key = "%s_volume_type" % resource_name
                description = (
                    "Volume type for volume %s" % resource_name)
                default = volume.volume_type
                self.add_parameter(key, description, 'string', default=default)
                properties['volume_type'] = {'get_param': key}
            if volume.metadata:
                properties['metadata'] = volume.metadata
            resource = {
                resource_name: {
                    'type': resource_type,
                    'properties': properties
                }
            }
            self.template['resources'].update(resource)

    def extract_data(self):
        self._extract_routers()
        self._extract_networks()
        self._extract_subnets()
        self._extract_secgroups()
        self._extract_floating()
        self._extract_keys()
        if not self.exclude_servers:
            self._extract_servers()
        if not self.exclude_volumes:
            self._extract_volumes()

    def heat_template(self):
        return self.print_generated(self.template)

    def stack_data_template(self):
        return self.print_generated(self.stack_data)
