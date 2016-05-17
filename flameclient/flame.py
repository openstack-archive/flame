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


class Resource(object):
    """Describes an OpenStack resource."""

    def __init__(self, name, type, id=None, properties=None):
        self.name = name
        self.type = type
        self.id = id
        self.status = 'COMPLETE'
        self.properties = properties or {}
        self.parameters = {}

    def add_parameter(self, name, description, parameter_type='string',
                      constraints=None, default=None):
        data = {
            'type': parameter_type,
            'description': description,
        }

        # (arezmerita) disable cause heat bug #1314240
        # if constraints:
        #    data['constraints'] = constraints
        if default:
            data['default'] = default

        self.parameters[name] = data

    @property
    def template_resource(self):
        return {
            self.name: {
                'type': self.type,
                'properties': self.properties
            }
        }

    @property
    def template_parameter(self):
        return self.parameters

    @property
    def stack_resource(self):
        if self.id is None:
            return {}
        return {
            self.name: {
                'status': self.status,
                'name': self.name,
                'resource_data': {},
                'resource_id': self.id,
                'action': 'CREATE',
                'type': self.type,
                'metadata': {}
            }
        }


class TemplateGenerator(object):

    def __init__(self, username, password, tenant_name, auth_url,
                 auth_token=None, insecure=False, endpoint_type='publicURL',
                 region_name=None):
        self.generate_data = False
        self._setup_templates()
        self._setup_managers(username, password, tenant_name, auth_url,
                             insecure, endpoint_type, region_name, auth_token)

    def _setup_templates(self):
        self.template = yaml.load(template_skeleton)
        self.template['resources'] = {}
        self.template['parameters'] = {}

        self.stack_data = yaml.load(stack_data_skeleton)
        self.stack_data['resources'] = {}

    def _setup_managers(self, username, password, tenant_name, auth_url,
                        insecure, endpoint_type, region_name=None,
                        auth_token=None):
        self.keystone = managers.KeystoneManager(
            username, password,
            tenant_name,
            auth_url, insecure,
            endpoint_type,
            region_name=region_name,
            auth_token=auth_token
        )
        self.keystone.authenticate()
        self.neutron = managers.NeutronManager(self.keystone)
        self.nova = managers.NovaManager(self.keystone)
        self.cinder = managers.CinderManager(self.keystone)

    def extract_vm_details(self, exclude_servers, exclude_volumes,
                           exclude_keypairs, generate_data):
        self.exclude_servers = exclude_servers
        self.exclude_volumes = exclude_volumes
        self.exclude_keypairs = exclude_keypairs
        self.generate_data = generate_data

        self.subnets = self.build_data(self.neutron.subnet_list())
        self.networks = self.build_data(self.neutron.network_list())
        self.routers = self.neutron.router_list()
        self.secgroups = self.build_data(self.neutron.secgroup_list())
        self.floatingips = self.neutron.floatingip_list()
        self.ports = self.build_data(self.neutron.port_list())
        self.external_networks = []

        if not exclude_keypairs:
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
    def format_template(filename):
        return yaml.safe_dump(filename, default_flow_style=False)

    def _extract_router_gateway(self, router_resource_name, router):
        router_external_network_name = ("%s_external_network" %
                                        router_resource_name)
        external_network = router['external_gateway_info']['network_id']
        properties = {
            'router_id': {'get_resource': router_resource_name},
            'network_id': {'get_param': router_external_network_name}
        }
        resource = Resource("%s_gateway" % router_resource_name,
                            'OS::Neutron::RouterGateway',
                            "%s:%s" % (router['id'], external_network),
                            properties)

        description = "Router external network"
        constraints = [{'custom_constraint': "neutron.network"}]
        resource.add_parameter(router_external_network_name, description,
                               constraints=constraints,
                               default=external_network)

        return resource

    def _extract_router_interfaces(self, router_resource_name, ports):
        resources = []
        for n, port in enumerate(ports):
            if port['device_owner'] != "network:router_interface":
                continue

            resource_name = "%s_interface_%d" % (router_resource_name, n)
            subnet_resource_name = self.get_subnet_resource_name(
                port['fixed_ips'][0]['subnet_id'])
            resource_id = ("%s:subnet_id=%s" %
                           (port['device_id'],
                            port['fixed_ips'][0]['subnet_id']))
            properties = {
                'subnet_id': {'get_resource': subnet_resource_name},
                'router_id': {'get_resource': router_resource_name}
            }
            resource = Resource(resource_name, 'OS::Neutron::RouterInterface',
                                resource_id, properties)
            resources.append(resource)
        return resources

    def _extract_routers(self):
        resources = []
        for n, router in enumerate(self.routers):
            name = "router_%d" % n
            properties = {
                'name': router['name'],
                'admin_state_up': router['admin_state_up'],
            }
            resource = Resource(name, 'OS::Neutron::Router',
                                router['id'], properties)
            resources.append(resource)

            ports = self.neutron.router_interfaces_list(router)
            resources += self._extract_router_interfaces(name, ports)

            if router['external_gateway_info']:
                resources.append(self._extract_router_gateway(name, router))
        return resources

    def _extract_networks(self):
        resources = []
        for n, network in self.networks.values():
            if network['router:external']:
                self.external_networks.append(network['id'])
                continue

            properties = {
                'name': network['name'],
                'admin_state_up': network['admin_state_up'],
                'shared': network['shared']
            }
            resource = Resource("network_%d" % n, 'OS::Neutron::Net',
                                network['id'], properties)
            resources.append(resource)
        return resources

    def get_network_resource_name(self, network_id):
        return "network_%d" % self.networks[network_id][0]

    def get_subnet_resource_name(self, subnet_id):
        return "subnet_%d" % self.subnets[subnet_id][0]

    def _extract_subnets(self):
        resources = []
        for n, subnet in self.subnets.values():
            if subnet['network_id'] in self.external_networks:
                continue

            net_name = self.get_network_resource_name(subnet['network_id'])
            properties = {
                'name': subnet['name'],
                'allocation_pools': subnet['allocation_pools'],
                'cidr': subnet['cidr'],
                'dns_nameservers': subnet['dns_nameservers'],
                'enable_dhcp': subnet['enable_dhcp'],
                'host_routes': subnet['host_routes'],
                'ip_version': subnet['ip_version'],
                'network_id': {'get_resource': net_name}
            }
            resource = Resource("subnet_%d" % n, 'OS::Neutron::Subnet',
                                subnet['id'], properties)
            resources.append(resource)
        return resources

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
            rule = dict((k, v) for k, v in rule.items() if v is not None)
            brules.append(rule)
        return brules

    def _extract_secgroups(self):
        resources = []
        for n, secgroup in self.secgroups.values():
            if secgroup['name'] == 'default' and self.generate_data:
                continue

            if secgroup['name'] == "default":
                secgroup['name'] = "_default"

            rules = self._build_rules(secgroup['security_group_rules'])
            properties = {
                'description': secgroup['description'],
                'name': secgroup['name'],
                'rules': rules,
            }
            resource = Resource("security_group_%d" % n,
                                'OS::Neutron::SecurityGroup',
                                secgroup['id'],
                                properties)
            resources.append(resource)
        return resources

    def _extract_keys(self):
        resources = []
        for n, key in self.keys.values():
            properties = {'name': key.name, 'public_key': key.public_key}
            resource = Resource("key_%d" % n, 'OS::Nova::KeyPair',
                                key.id, properties)
            resources.append(resource)
        return resources

    def build_secgroups(self, resource, server):
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
                    resource.add_parameter(param_name, description,
                                           default=default)
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
        resources = []
        for n, server in self.servers.values():
            resource_name = "server_%d" % n
            properties = {
                'name': server.name,
                'diskConfig': getattr(server, 'OS-DCF:diskConfig')
            }
            resource = Resource(resource_name, 'OS::Nova::Server',
                                server.id, properties)

            if server.config_drive:
                properties['config_drive'] = server.config_drive

            # Flavor
            flavor_parameter_name = "%s_flavor" % resource_name
            description = "Flavor to use for server %s" % resource_name
            default = self.flavors[server.flavor['id']][1].name
            resource.add_parameter(flavor_parameter_name, description,
                                   default=default)
            properties['flavor'] = {'get_param': flavor_parameter_name}

            # Image
            if server.image:
                image_parameter_name = "%s_image" % resource_name
                description = (
                    "Image to use to boot server %s" % resource_name)
                constraints = [{'custom_constraint': "glance.image"}]
                resource.add_parameter(image_parameter_name, description,
                                       default=server.image['id'],
                                       constraints=constraints)
                properties['image'] = {'get_param': image_parameter_name}

            # Keypair
            if server.key_name:
                if self.exclude_keypairs or server.key_name not in self.keys:
                    key_parameter_name = "%s_key" % resource_name
                    description = ("Key for server %s" % resource_name)
                    constraints = [{'custom_constraint': "nova.keypair"}]
                    resource.add_parameter(key_parameter_name, description,
                                           default=server.key_name,
                                           constraints=constraints)
                    properties['key_name'] = {'get_param': key_parameter_name}
                else:
                    resource_key = "key_%d" % self.keys[server.key_name][0]
                    properties['key_name'] = {'get_resource': resource_key}

            security_groups = self.build_secgroups(resource, server)
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
                    resource.add_parameter(volume_parameter_name, description,
                                           default=server_volume['id'])
            if server_volumes:
                # block_device_mapping_v2 is the new way of associating
                # block devices to an instance
                properties['block_device_mapping_v2'] = server_volumes

            resources.append(resource)
        return resources

    def _extract_floating(self):
        resources = []
        for n, ip in enumerate(self.floatingips):
            ip_resource_name = "floatingip_%d" % n
            net_param_name = "external_network_for_floating_ip_%d" % n
            ip_properties = {
                'floating_network_id': {'get_param': net_param_name}}
            resource = Resource(ip_resource_name, 'OS::Neutron::FloatingIP',
                                ip['id'], ip_properties)

            description = "Network to allocate floating IP from"
            constraints = [{'custom_constraint': "neutron.network"}]
            default = ip['floating_network_id']
            resource.add_parameter(net_param_name, description,
                                   constraints=constraints,
                                   default=default)
            resources.append(resource)

            if not self.exclude_servers and ip['port_id']:
                device = self.ports[ip['port_id']][1]['device_id']
                if device and self.servers[device]:
                    server = self.servers[device]
                    server_resource_name = "server_%d" % server[0]
                    properties = {
                        'floating_ip': {'get_resource': ip_resource_name},
                        'server_id': {'get_resource': server_resource_name}
                    }
                    resource = Resource("floatingip_association_%d" % n,
                                        'OS::Nova::FloatingIPAssociation',
                                        None,
                                        properties)
                    resources.append(resource)
        return resources

    def _extract_volumes(self):
        resources = []
        for n, volume in self.volumes.values():
            resource_name = "volume_%d" % n
            properties = {'size': volume.size}
            resource = Resource(resource_name, 'OS::Cinder::Volume',
                                volume.id, properties)
            if volume.source_volid:
                if volume.source_volid in self.volumes:
                    key = "volume_%d" % self.volumes[volume.source_volid][0]
                    properties['source_volid'] = {'get_resource': key}
                else:
                    key = "%s_source_volid" % resource_name
                    description = (
                        "Volume to create volume %s from" % resource_name)
                    resource.add_parameter(key, description)
                    properties['source_volid'] = {'get_param': key}
            if volume.bootable == 'true' and not volume.snapshot_id:
                key = "%s_image" % resource_name
                description = "Image to create volume %s from" % resource_name
                constraints = [{'custom_constraint': "glance.image"}]
                default = volume.volume_image_metadata['image_id']
                resource.add_parameter(key, description,
                                       constraints=constraints,
                                       default=default)
                properties['image'] = {'get_param': key}
            if volume.snapshot_id:
                key = "%s_snapshot_id" % resource_name
                properties['snapshot_id'] = {'get_param': key}
                description = (
                    "Snapshot to create volume %s from" % resource_name)
                resource.add_parameter(key, description,
                                       default=volume.snapshot_id)
            if hasattr(volume, 'display_name') and volume.display_name:
                properties['name'] = volume.display_name
            if (hasattr(volume, 'display_description') and
               volume.display_description):
                properties['description'] = volume.display_description
            if volume.volume_type and volume.volume_type != 'None':
                key = "%s_volume_type" % resource_name
                description = (
                    "Volume type for volume %s" % resource_name)
                default = volume.volume_type
                resource.add_parameter(key, description, default=default)
                properties['volume_type'] = {'get_param': key}
            if volume.metadata:
                properties['metadata'] = volume.metadata

            resources.append(resource)
        return resources

    def extract_data(self):
        resources = self._extract_routers()
        resources += self._extract_networks()
        resources += self._extract_subnets()
        resources += self._extract_secgroups()
        resources += self._extract_floating()

        if not self.exclude_keypairs:
            resources += self._extract_keys()
        if not self.exclude_servers:
            resources += self._extract_servers()
        if not self.exclude_volumes:
            resources += self._extract_volumes()

        for resource in resources:
            self.template['resources'].update(resource.template_resource)
            self.template['parameters'].update(resource.template_parameter)
            if self.generate_data:
                self.stack_data['resources'].update(resource.stack_resource)

    def heat_template(self):
        return self.format_template(self.template)

    def stack_data_template(self):
        return self.format_template(self.stack_data)
