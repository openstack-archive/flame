import argparse
import ipaddr
import logging
import os
import yaml

import managers

logging.basicConfig(level=logging.ERROR)

template_skeleton = '''
heat_template_version: 2013-05-23
description: Generated template
parameters:
resources:
'''


class TemplateGenerator(object):

    neutron_manager = managers.NeutronManager
    nova_manager = managers.NovaManager
    cinder_manager = managers.CinderManager

    def __init__(self, exclude_servers, exclude_volumes, *arguments):
        self.exclude_servers = exclude_servers
        self.exclude_volumes = exclude_volumes

        self.template = yaml.load(template_skeleton)
        self.template['resources'] = {}
        self.template['parameters'] = {}

        self.neutron = self.neutron_manager(*arguments)
        self.subnets = dict(
            (subnet['id'], (index, subnet))
            for index, subnet in enumerate(self.neutron.subnet_list()))

        self.networks = dict(
            (network['id'], (index, network))
            for index, network in enumerate(self.neutron.network_list()))

        self.routers = self.neutron.router_list()
        self.secgroups = self.neutron.secgroup_list()
        self.secgroups_resources_names = {}
        self.floatingips = self.neutron.floatingip_list()
        self.external_networks = []

        self.nova = self.nova_manager(*arguments)
        self.keys = dict(
            (key.name, (index, key))
            for index, key in enumerate(self.nova.keypair_list()))

        if not self.exclude_servers:
            self.flavors = dict(
                (flavor.id, flavor) for flavor in self.nova.flavor_list())
            self.servers = self.nova.server_list()

        if (not self.exclude_volumes or
                (self.exclude_volumes and not self.exclude_servers)):
            self.cinder = self.cinder_manager(*arguments)
            self.volumes = dict(
                (volume.id, (index, volume))
                for index, volume in enumerate(self.cinder.volume_list()))

    def print_template(self):
        print(yaml.safe_dump(self.template, default_flow_style=False))

    def add_parameter(self, name, description, parameter_type,
                      constraints=None, default=None):
        parameter = {
            name: {
                'type': parameter_type,
                'description': description,
            }
        }
        # (arezmerita) disable cause heat bug #1314240
        #if constraints:
        #    parameter[name]['constraints'] = constraints
        if default:
            parameter[name]['default'] = default
        self.template['parameters'].update(parameter)

    def add_router_gateway_resource(self, router_resource_name):
        router_external_network_name = "%s_external_network" % \
                                       router_resource_name
        router_gateway_name = "%s_gateway" % router_resource_name
        description = "Router external network"
        constraints = [{'custom_constraint': "neutron.network"}]
        self.add_parameter(router_external_network_name, description,
                           'string', constraints=constraints)
        resource = {
            router_gateway_name: {
                'type': 'OS::Neutron::RouterGateway',
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
                port_resource_name = "%s_interface_%d" % \
                                     (router_resource_name, n)
                subnet_resource_name = self.get_subnet_resource_name(
                    port['fixed_ips'][0]['subnet_id'])
                resource = {
                    port_resource_name: {
                        'type': 'OS::Neutron::RouterInterface',
                        'properties': {
                        'subnet_id': {'get_resource': subnet_resource_name},
                        'router_id': {'get_resource': router_resource_name}
                        }
                    }
                }
                self.template['resources'].update(resource)

    def extract_routers(self):
        for n, router in enumerate(self.routers):
            router_resource_name = "router_%d" % n
            resource = {
                router_resource_name: {
                    'type': 'OS::Neutron::Router',
                    'properties': {
                        'name': router['name'],
                        'admin_state_up': router['admin_state_up'],
                    }
                }
            }
            self.template['resources'].update(resource)
            self.add_router_interface_resources(
                router_resource_name,
                self.neutron.router_interfaces_list(router))
            if router['external_gateway_info']:
                self.add_router_gateway_resource(router_resource_name)

    def extract_networks(self):
        for n, network in self.networks.itervalues():
            if network['router:external']:
                self.external_networks.append(network['id'])
                continue
            network_resource_name = "network_%d" % n
            resource = {
                network_resource_name: {
                    'type': 'OS::Neutron::Net',
                    'properties': {
                        'name': network['name'],
                        'admin_state_up': network['admin_state_up'],
                        'shared': network['shared']
                    }
                }
            }
            self.template['resources'].update(resource)

    def get_network_resource_name(self, id):
        return "network_%d" % self.networks[id][0]

    def get_subnet_resource_name(self, id):
        return "subnet_%d" % self.subnets[id][0]

    def extract_subnets(self):
        for n, subnet in self.subnets.itervalues():
            if subnet['network_id'] in self.external_networks:
                continue
            subnet_resource_name = "subnet_%d" % n
            net_name = self.get_network_resource_name(subnet['network_id'])
            resource = {
                subnet_resource_name: {
                    'type': 'OS::Neutron::Subnet',
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

    def _prepare_secgoup_rules(self, rules):
        prepared_rules = []
        for rule in rules:
            rg_id = rule['remote_group_id']
            if rg_id is not None:
                rule['remote_mode'] = "remote_group_id"
                res_secgr = self.secgroups_resources_names[rg_id]
                if rg_id == rule['security_group_id']:
                    del rule['remote_group_id']
                else:
                    rule['remote_group_id'] = {'get_resource': res_secgr}
            del rule['tenant_id']
            del rule['id']
            del rule['security_group_id']
            rule = dict((k, v) for k, v in rule.iteritems() if v is not None)
            prepared_rules.append(rule)
        return prepared_rules

    def extract_secgroups(self):
        for n, secgroup in enumerate(self.secgroups):
            if secgroup['name'] == "default":
                secgroup['name'] = "_default"
            resource_name = "security_group_%d" % n
            self.secgroups_resources_names[secgroup['id']] = resource_name
        for secgroup in self.secgroups:
            rules = self._prepare_secgoup_rules(secgroup[
                'security_group_rules'])
            resource = {
                self.secgroups_resources_names[secgroup['id']]: {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'description': secgroup['description'],
                        'name': secgroup['name'],
                        'rules': rules,
                    }
                }
            }
            self.template['resources'].update(resource)

    def extract_keys(self):
        for n, key in self.keys.itervalues():
            key_resource_name = "key_%d" % n
            resource = {
                key_resource_name: {
                    'type': 'OS::Nova::KeyPair',
                    'properties': {
                        'name': key.name,
                        'public_key': key.public_key
                    }
                }
            }
            self.template['resources'].update(resource)

    def build_secgroups(self, server):
        security_groups = []
        server_secgroups = []
        for i in self.nova.server_security_group_list(server):
            if i not in server_secgroups:
                server_secgroups.append(i)

        for secgr in server_secgroups:
            resource = self.secgroups_resources_names[secgr.id]
            security_groups.append({'get_resource': resource})
        return security_groups

    def build_networks(self, addresses):
        networks = []
        for net_name in addresses:
            ip = addresses[net_name][0]['addr']
            for s, subnet in self.subnets.itervalues():
                if ipaddr.IPAddress(ip) in ipaddr.IPNetwork(subnet['cidr']):
                    for n, network in self.networks.itervalues():
                        if (network['name'] == net_name and
                                network['id'] == subnet['network_id']):
                            net = self.get_network_resource_name(
                                subnet['network_id'])
                            networks.append({'network': {'get_resource': net}})
        return networks

    def extract_servers(self):
        for n, server in enumerate(self.servers):
            resource_name = "server_%d" % n
            properties = {
                'name': server.name,
                'diskConfig': getattr(server, 'OS-DCF:diskConfig')
            }

            if server.config_drive:
                properties['config_drive'] = server.config_drive

            # Flavor
            flavor_parameter_name = "%s_flavor" % resource_name
            description = "Flavor to use for server %s" % resource_name
            default = self.flavors[server.flavor['id']].name
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
                    default=server.image, constraints=constraints)
                properties['image'] = {'get_param': image_parameter_name}

            # Keypair
            if server.key_name:
                key = self.keys[server.key_name]
                resource_key = "key_%d" % key[0]
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
                    volume_parameter_name = "volume_%s_%d" % \
                                            (server.name, volume[0])
                    description = "Volume for server %s, device %s" % \
                                  (server.name, device)
                    server_volumes.append(
                        {'volume_id': {'get_param': volume_parameter_name},
                         'device_name': device})
                    self.add_parameter(volume_parameter_name, description,
                                       'string')
            if server_volumes:
                properties['block_device_mapping'] = server_volumes

            resource = {
                resource_name: {
                    'type': 'OS::Nova::Server',
                    'properties': properties
                }
            }
            self.template['resources'].update(resource)

    def extract_floating(self):
        for n, ip in enumerate(self.floatingips):
            ip_resource_name = "floatingip_%d" % n
            net_param_name = "external_network_for_floating_ip_%d" % n
            resource = {
                ip_resource_name: {
                    'type': 'OS::Neutron::FloatingIP',
                    'properties': {
                        'floating_network_id': {'get_param': net_param_name}
                    }
                }
            }
            description = "Network to allocate floating IP from"
            constraints = [{'custom_constraint': "neutron.network"}]
            self.add_parameter(net_param_name, description, 'string',
                               constraints=constraints)
            self.template['resources'].update(resource)

    def extract_volumes(self):
        for n, volume in self.volumes.itervalues():
            resource_name = "volume_%d" % n
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
                self.add_parameter(
                    key, description, 'string', constraints=constraints)
                properties['image'] = {'get_param': key}
            if volume.snapshot_id:
                key = "%s_snapshot_id" % resource_name
                properties['snapshot_id'] = {'get_param': key}
                description = (
                    "Snapshot to create volume %s from" % resource_name)
                self.add_parameter(key, description, 'string')
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
                    'type': 'OS::Cinder::Volume',
                    'properties': properties
                }
            }
            self.template['resources'].update(resource)

    def run(self):
        self.extract_routers()
        self.extract_networks()
        self.extract_subnets()
        self.extract_secgroups()
        self.extract_floating()
        self.extract_keys()

        if not self.exclude_servers:
            self.extract_servers()

        if not self.exclude_volumes:
            self.extract_volumes()

        self.print_template()


def main():
    desc = "Generate Heat Template"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--username", type=str,
                        default=os.environ.get("OS_USERNAME"),
                        help="A user name with access to the project. "
                             "Defaults to env[OS_USERNAME]")
    parser.add_argument("--password", type=str,
                        default=os.environ.get("OS_PASSWORD"),
                        help="The user's password. "
                             "Defaults to env[OS_PASSWORD]")
    parser.add_argument("--project", type=str,
                        default=os.environ.get("OS_TENANT_NAME"),
                        help="Name of project. "
                             "Defaults to env[OS_TENANT_NAME]")
    parser.add_argument("--auth_url", type=str,
                        default=os.environ.get("OS_AUTH_URL"),
                        help="Authentication URL. "
                             "Defaults to env[OS_AUTH_URL].")
    parser.add_argument('--insecure', action='store_true', default=False,
                        help="Explicitly allow clients to perform"
                             "\"insecure\" SSL (https) requests. The "
                             "server's certificate will not be verified "
                             "against any certificate authorities. This "
                             "option should be used with caution.")
    parser.add_argument('--exclude_servers', action='store_true',
                        default=False,
                        help="Do not export in template server resources")
    parser.add_argument('--exclude_volumes', action='store_true',
                        default=False,
                        help="Do not export in template volume resources")

    args = parser.parse_args()
    arguments = (args.username, args.password, args.project, args.auth_url,
                 args.insecure)
    TemplateGenerator(args.exclude_servers, args.exclude_volumes, *arguments)\
        .run()

if __name__ == "__main__":
    main()
