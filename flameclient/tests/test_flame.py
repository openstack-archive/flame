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

import datetime

from flameclient.flame import TemplateGenerator  # noqa
from flameclient.tests import base


class FakeBase(object):

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeVolume(FakeBase):
    id = 1234
    size = 1
    source_volid = None
    bootable = 'false'
    snapshot_id = None
    display_name = 'vol1'
    display_description = 'Description'
    volume_type = None
    metadata = None


class FakeServer(FakeBase):
    id = '1234'
    name = 'server1'
    config_drive = None
    flavor = {'id': '2'}
    image = {'id': '3333',
             'links': [{'href': 'http://p/7777/images/3333',
                        'rel': 'bookmark'}]}
    key_name = None
    addresses = []
    metadata = None

    def __init__(self, **kwargs):
        kwargs.setdefault('OS-DCF:diskConfig', 'MANUAL')
        kwargs.setdefault('os-extended-volumes:volumes_attached', [])
        super(FakeServer, self).__init__(**kwargs)


class FakeFlavor(FakeBase):
    name = 'm1.tiny'
    id = '1'


class FakeKeypair(FakeBase):
    name = 'key'
    id = 'key'
    public_key = 'ssh-rsa AAAAB3NzaC'


class FakeSecurityGroup(FakeBase):
    id = '1'
    name = 'name'


class FakeNeutronManager(object):
    groups = []
    routers = []
    ports = []
    subnets = []
    networks = []
    floatingips = []

    def subnet_list(self):
        return self.subnets

    def network_list(self):
        return self.networks

    def port_list(self):
        return self.ports

    def router_list(self):
        return self.routers

    def router_interfaces_list(self, router):
        return self.ports

    def secgroup_list(self):
        return self.groups

    def floatingip_list(self):
        return self.floatingips


class FakeNovaManager(object):

    servers = []
    flavors = [FakeFlavor(id='2', name='m1.small')]
    groups = {}
    keypairs = [FakeKeypair(name='testkey', public_key='ssh-rsa XXXX')]

    def keypair_list(self):
        return self.keypairs

    def flavor_list(self):
        return self.flavors

    def server_list(self):
        return self.servers

    def server_security_group_list(self, server):
        return self.groups.get(server.name, [])


class FakeCinderManager(object):

    volumes = []

    def volume_list(self):
        return self.volumes


class StackDataTests(base.TestCase):
    def setUp(self):
        super(StackDataTests, self).setUp()
        self.neutron_manager = FakeNeutronManager()
        TemplateGenerator.neutron_manager = (lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        TemplateGenerator.nova_manager = (lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        TemplateGenerator.cinder_manager = (lambda x: self.cinder_manager)

    def test_keypair(self):
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'key_0': {
                    'type': 'OS::Nova::KeyPair',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'key_0',
                    'resource_data': {},
                    'resource_id': 'key',
                    'status': 'COMPLETE'
                }
            }
        }
        generator.extract_keys()
        self.assertEqual(expected, generator.stack_data)

    def test_router(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': None
        }
        self.neutron_manager.routers = [router]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'router_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                }
            }
        }
        generator.extract_routers()
        self.assertEqual(expected, generator.stack_data)

    def test_router_with_external_gateway(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': {
                'network_id': '8765',
                'enable_snat': 'true'
            }
        }
        self.neutron_manager.routers = [router]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'router_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                },
                'router_0_gateway': {
                    'type': 'OS::Neutron::RouterGateway',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'router_0_gateway',
                    'resource_data': {},
                    'resource_id': '1234:8765',
                    'status': 'COMPLETE'
                }
            }
        }

        generator.extract_routers()
        self.assertEqual(expected, generator.stack_data)

    def test_router_with_ports(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': None
        }
        port = {
            'status': 'ACTIVE',
            'name': '',
            'allowed_address_pairs': [],
            'admin_state_up': True,
            'network_id': '4444',
            'extra_dhcp_opts': [],
            'binding:vnic_type': 'normal',
            'device_owner': 'network:router_interface',
            'mac_address': 'fa:16:3e:4b:8c:98',
            'fixed_ips': [{'subnet_id': '1111', 'ip_address': '10.123.2.3'}],
            'id': '1234567',
            'security_groups': [],
            'device_id': '1234'
        }
        subnet = {
            'name': 'subnet_1111',
            'enable_dhcp': True,
            'network_id': '1234',
            'dns_nameservers': [],
            'allocation_pools': [{'start': '10.123.2.2',
                                  'end': '10.123.2.30'}],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.123.2.1',
            'cidr': '10.123.2.0/27',
            'id': '1111'
        }

        self.neutron_manager.ports = [port]
        self.neutron_manager.subnets = [subnet]
        self.neutron_manager.routers = [router]

        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'router_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                },
                'router_0_interface_0': {
                    'type': 'OS::Neutron::RouterInterface',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'router_0_interface_0',
                    'resource_data': {},
                    'resource_id': '1234:subnet_id=1111',
                    'status': 'COMPLETE'
                }
            }
        }
        generator.extract_routers()
        self.assertEqual(expected, generator.stack_data)

    def test_network(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'mynetwork',
            'router:external': False,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        self.neutron_manager.networks = [network]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'network_0': {
                    'type': 'OS::Neutron::Net',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'network_0',
                    'resource_data': {},
                    'resource_id': '2222',
                    'status': 'COMPLETE'
                }
            }
        }
        generator.extract_networks()
        self.assertEqual(expected, generator.stack_data)

    def test_external_network(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'internet',
            'router:external': True,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        self.neutron_manager.networks = [network]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {}
        }
        generator.extract_networks()
        self.assertEqual(expected, generator.stack_data)

    def test_subnet(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'mynetwork',
            'router:external': False,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        subnet = {
            'name': 'subnet_1111',
            'enable_dhcp': True,
            'network_id': '2222',
            'dns_nameservers': [],
            'allocation_pools': [{'start': '10.123.2.2',
                                  'end': '10.123.2.30'}],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.123.2.1',
            'cidr': '10.123.2.0/27',
            'id': '1111'
        }
        self.neutron_manager.networks = [network]
        self.neutron_manager.subnets = [subnet]

        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'subnet_0': {
                    'type': 'OS::Neutron::Subnet',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'subnet_0',
                    'resource_data': {},
                    'resource_id': '1111',
                    'status': 'COMPLETE'
                }
            }

        }
        generator.extract_subnets()
        self.assertEqual(expected, generator.stack_data)

    def test_floatingip(self):
        ip = {
            'router_id': '1111',
            'status': 'ACTIVE',
            'floating_network_id': '1234',
            'fixed_ip_address': '10.0.48.251',
            'floating_ip_address': '84.39.33.60',
            'port_id': '4321',
            'id': '2222'
        }
        self.neutron_manager.floatingips = [ip]
        generator = TemplateGenerator(True, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'floatingip_0': {
                    'type': 'OS::Neutron::FloatingIP',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'floatingip_0',
                    'resource_data': {},
                    'resource_id': '2222',
                    'status': 'COMPLETE'
                }
            }

        }
        generator.extract_floating()
        self.assertEqual(expected, generator.stack_data)

    def test_security_group(self):
        rules = [
            {
                'remote_group_id': None,
                'direction': 'ingress',
                'remote_ip_prefix': '0.0.0.0/0',
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 22,
                'port_range_min': 22,
                'id': '8901',
                'security_group_id': '1234'
            },
        ]
        group = {
            'tenant_id': '7777',
            'name': 'somename',
            'description': 'description',
            'security_group_rules': rules,
            'id': '1234'
        }

        self.neutron_manager.groups = [group]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'security_group_0': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'security_group_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                }
            }
        }
        generator.extract_secgroups()
        self.assertEqual(expected, generator.stack_data)

    def test_default_security_group(self):
        rules = [
            {
                'remote_group_id': None,
                'direction': 'ingress',
                'remote_ip_prefix': '0.0.0.0/0',
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 22,
                'port_range_min': 22,
                'id': '8901',
                'security_group_id': '1234'
            },
        ]
        group = {
            'tenant_id': '7777',
            'name': 'default',
            'description': 'default',
            'security_group_rules': rules,
            'id': '1234'
        }

        self.neutron_manager.groups = [group]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {}
        }
        generator.extract_secgroups()
        self.assertEqual(expected, generator.stack_data)

    def test_volume(self):
        self.cinder_manager.volumes = [FakeVolume()]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'volume_0',
                    'resource_data': {},
                    'resource_id': 1234,
                    'status': 'COMPLETE'
                }
            }

        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.stack_data)

    def test_server(self):
        self.nova_manager.servers = [FakeServer()]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'server_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                }
            }

        }
        generator.extract_servers()
        self.assertEqual(expected, generator.stack_data)

    def test_server_with_default_security_group(self):
        self.neutron_manager.groups = [
            {
                "name": "default",
                "id": "1",
                "security_group_rules": [],
                "description": "default"
            }
        ]
        self.nova_manager.groups = {'server1': [FakeSecurityGroup(
            name='default', description='default')]}
        self.nova_manager.servers = [FakeServer()]
        generator = TemplateGenerator(False, False, True)
        expected = {
            'action': 'CREATE',
            'status': 'COMPLETE',
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'action': 'CREATE',
                    'metadata': {},
                    'name': 'server_0',
                    'resource_data': {},
                    'resource_id': '1234',
                    'status': 'COMPLETE'
                }
            }

        }
        template_expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                },
                'server_0_default_security_group': {
                    'default': '1',
                    'type': 'string',
                    'description': 'Default security group for server server1'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'security_groups': [
                            {
                                'get_param': 'server_0_default_security_group'
                            }
                        ],
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'}
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.stack_data)
        self.assertEqual(template_expected, generator.template)


class NetworkTests(base.TestCase):

    def setUp(self):
        super(NetworkTests, self).setUp()
        self.neutron_manager = FakeNeutronManager()
        TemplateGenerator.neutron_manager = (lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        TemplateGenerator.nova_manager = (lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        TemplateGenerator.cinder_manager = (lambda x: self.cinder_manager)

    def test_keypair(self):
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'key_0': {
                    'type': 'OS::Nova::KeyPair',
                    'properties': {
                        'public_key': 'ssh-rsa XXXX',
                        'name': 'testkey'
                    }
                }
            }
        }
        generator.extract_keys()
        self.assertEqual(expected, generator.template)

    def test_router(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': None
        }
        self.neutron_manager.routers = [router]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'properties': {
                        'name': 'myrouter',
                        'admin_state_up': 'true',
                    }
                }
            }
        }
        generator.extract_routers()
        self.assertEqual(expected, generator.template)

    def test_router_with_external_gateway(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': {
                'network_id': '8765',
                'enable_snat': 'true'
            }
        }
        self.neutron_manager.routers = [router]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'router_0_external_network': {
                    'default': '8765',
                    'type': 'string',
                    'description': 'Router external network'
                }
            },
            'resources': {
                'router_0_gateway': {
                    'type': 'OS::Neutron::RouterGateway',
                    'properties': {
                        'router_id': {'get_resource': 'router_0'},
                        'network_id': {
                            'get_param': 'router_0_external_network'
                        }
                    }
                },
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'properties': {
                        'name': 'myrouter',
                        'admin_state_up': 'true',
                    }
                }
            }
        }
        generator.extract_routers()
        self.assertEqual(expected, generator.template)

    def test_router_with_ports(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': None
        }
        port = {
            'status': 'ACTIVE',
            'name': '',
            'allowed_address_pairs': [],
            'admin_state_up': True,
            'network_id': '4444',
            'extra_dhcp_opts': [],
            'binding:vnic_type': 'normal',
            'device_owner': 'network:router_interface',
            'mac_address': 'fa:16:3e:4b:8c:98',
            'fixed_ips': [{'subnet_id': '1111', 'ip_address': '10.123.2.3'}],
            'id': '1234567',
            'security_groups': [],
            'device_id': '1234'
        }
        subnet = {
            'name': 'subnet_1111',
            'enable_dhcp': True,
            'network_id': '1234',
            'dns_nameservers': [],
            'allocation_pools': [{'start': '10.123.2.2',
                                  'end': '10.123.2.30'}],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.123.2.1',
            'cidr': '10.123.2.0/27',
            'id': '1111'
        }

        self.neutron_manager.ports = [port]
        self.neutron_manager.subnets = [subnet]
        self.neutron_manager.routers = [router]

        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'router_0_interface_0': {
                    'type': 'OS::Neutron::RouterInterface',
                    'properties': {
                        'subnet_id': {'get_resource': 'subnet_0'},
                        'router_id': {'get_resource': 'router_0'}
                    }
                },
                'router_0': {
                    'type': 'OS::Neutron::Router',
                    'properties': {
                        'name': 'myrouter',
                        'admin_state_up': 'true',
                    }
                }
            }
        }
        generator.extract_routers()
        self.assertEqual(expected, generator.template)

    def test_network(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'mynetwork',
            'router:external': False,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        self.neutron_manager.networks = [network]
        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'network_0': {
                    'type': 'OS::Neutron::Net',
                    'properties': {
                        'shared': False,
                        'name': 'mynetwork',
                        'admin_state_up': True
                    }
                }
            }
        }
        generator.extract_networks()
        self.assertEqual(expected, generator.template)

    def test_external_network(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'mynetwork',
            'router:external': True,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        self.neutron_manager.networks = [network]
        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {}
        }
        generator.extract_networks()
        self.assertEqual(expected, generator.template)

    def test_subnet(self):
        network = {
            'status': 'ACTIVE',
            'subnets': ['1111'],
            'name': 'mynetwork',
            'router:external': False,
            'admin_state_up': True,
            'shared': False,
            'id': '2222'
        }
        subnet = {
            'name': 'subnet_1111',
            'enable_dhcp': True,
            'network_id': '2222',
            'dns_nameservers': [],
            'allocation_pools': [{'start': '10.123.2.2',
                                  'end': '10.123.2.30'}],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.123.2.1',
            'cidr': '10.123.2.0/27',
            'id': '1111'
        }
        self.neutron_manager.networks = [network]
        self.neutron_manager.subnets = [subnet]

        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'subnet_0': {
                    'type': 'OS::Neutron::Subnet',
                    'properties': {
                        'network_id': {'get_resource': 'network_0'},
                        'allocation_pools': [{'start': '10.123.2.2',
                                              'end': '10.123.2.30'}],
                        'host_routes': [],
                        'name': 'subnet_1111',
                        'enable_dhcp': True,
                        'ip_version': 4,
                        'cidr': '10.123.2.0/27',
                        'dns_nameservers': []
                    }
                }
            }
        }
        generator.extract_subnets()
        self.assertEqual(expected, generator.template)

    def test_floatingip(self):
        ip = {
            'router_id': '1111',
            'status': 'ACTIVE',
            'floating_network_id': '1234',
            'fixed_ip_address': '10.0.48.251',
            'floating_ip_address': '84.39.33.60',
            'port_id': '4321',
            'id': '2222'
        }
        self.neutron_manager.floatingips = [ip]
        generator = TemplateGenerator(True, [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'external_network_for_floating_ip_0': {
                    'default': '1234',
                    'type': 'string',
                    'description': 'Network to allocate floating IP from'
                }
            },
            'resources': {
                'floatingip_0': {
                    'type': 'OS::Neutron::FloatingIP',
                    'properties': {
                        'floating_network_id': {
                            'get_param': 'external_network_for_floating_ip_0'
                        }
                    }
                }
            }
        }
        generator.extract_floating()
        self.assertEqual(expected, generator.template)

    def test_security_group(self):
        rules = [
            {
                'remote_group_id': '1234',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 65535,
                'port_range_min': 1,
                'id': '5678',
                'security_group_id': '1234'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '6789',
                'security_group_id': '1234'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv6',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '7890',
                'security_group_id': '1234'
            },
            {
                'remote_group_id': None,
                'direction': 'ingress',
                'remote_ip_prefix': '0.0.0.0/0',
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 22,
                'port_range_min': 22,
                'id': '8901',
                'security_group_id': '1234'
            },
        ]
        group = {
            'tenant_id': '7777',
            'name': 'toto',
            'description': 'description',
            'security_group_rules': rules,
            'id': '1234'
        }

        self.neutron_manager.groups = [group]
        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'security_group_0': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'rules': [
                            {
                                'direction': 'ingress',
                                'protocol': 'tcp',
                                'ethertype': 'IPv4',
                                'port_range_max': 65535,
                                'port_range_min': 1,
                                'remote_mode': 'remote_group_id'
                            },
                            {
                                'ethertype': 'IPv4',
                                'direction': 'egress'
                            },
                            {
                                'ethertype': 'IPv6',
                                'direction': 'egress'
                            },
                            {
                                'direction': 'ingress',
                                'protocol': 'tcp',
                                'ethertype': 'IPv4',
                                'port_range_max': 22,
                                'port_range_min': 22,
                                'remote_ip_prefix': '0.0.0.0/0'
                            }
                        ],
                        'description': 'description',
                        'name': 'toto'
                    }
                }
            }
        }
        generator.extract_secgroups()
        self.assertEqual(expected, generator.template)

    def test_security_group_default(self):
        rules = [
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv6',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '1234',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': '1111',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv6',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '2345',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': None,
                'direction': 'ingress',
                'remote_ip_prefix': '0.0.0.0/0',
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 22,
                'port_range_min': 22,
                'id': '3456',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '4567',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': '1111',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '5678',
                'security_group_id': '1111'
            }
        ]
        group = {
            'tenant_id': '7777',
            'name': 'default',
            'description': 'default',
            'security_group_rules': rules,
            'id': '1111'
        }

        self.neutron_manager.groups = [group]
        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'security_group_0': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'rules': [
                            {
                                'ethertype': 'IPv6',
                                'direction': 'egress'
                            },
                            {
                                'ethertype': 'IPv6',
                                'direction': 'ingress',
                                'remote_mode': 'remote_group_id'
                            },
                            {
                                'direction': 'ingress',
                                'protocol': 'tcp',
                                'ethertype': 'IPv4',
                                'port_range_max': 22,
                                'port_range_min': 22,
                                'remote_ip_prefix': '0.0.0.0/0'
                            },
                            {
                                'ethertype': 'IPv4',
                                'direction': 'egress'
                            },
                            {
                                'ethertype': 'IPv4',
                                'direction': 'ingress',
                                'remote_mode': 'remote_group_id'
                            }
                        ],
                        'description': 'default',
                        'name': '_default'
                    }
                }
            }
        }
        generator.extract_secgroups()
        self.assertEqual(expected, generator.template)

    def test_security_groups(self):
        rules1 = [
            {
                'remote_group_id': '2222',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '01234',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv6',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '1234',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '2345',
                'security_group_id': '1111'
            },
            {
                'remote_group_id': '2222',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': 'icmp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '3456',
                'security_group_id': '1111'
            }
        ]

        rules2 = [
            {
                'remote_group_id': '1111',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': 'udp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 8888,
                'port_range_min': 7777,
                'id': '4567',
                'security_group_id': '2222'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv6',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '5678',
                'security_group_id': '2222'
            },
            {
                'remote_group_id': None,
                'direction': 'egress',
                'remote_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': None,
                'port_range_min': None,
                'id': '6789',
                'security_group_id': '2222'
            },
            {
                'remote_group_id': '1111',
                'direction': 'ingress',
                'remote_ip_prefix': None,
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': '7777',
                'port_range_max': 65535,
                'port_range_min': 1,
                'id': '7890',
                'security_group_id': '2222'
            }
        ]
        group1 = {
            'tenant_id': '7777',
            'name': 'security_group_1',
            'description': 'security_group_1',
            'security_group_rules': rules1,
            'id': '1111'
        }
        group2 = {
            'tenant_id': '7777',
            'name': 'security_group_2',
            'description': 'security_group_2',
            'security_group_rules': rules2,
            'id': '2222'
        }
        self.neutron_manager.groups = [group1, group2]
        generator = TemplateGenerator([], [], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'security_group_0': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'rules': [
                            {
                                'remote_group_id': {
                                    'get_resource': 'security_group_1'
                                },
                                'direction': 'ingress',
                                'ethertype': 'IPv4',
                                'remote_mode': 'remote_group_id'
                            },
                            {
                                'ethertype': 'IPv6',
                                'direction': 'egress'
                            },
                            {
                                'ethertype': 'IPv4',
                                'direction': 'egress'
                            },
                            {
                                'remote_group_id': {
                                    'get_resource': 'security_group_1'
                                },
                                'direction': 'ingress',
                                'protocol': 'icmp',
                                'ethertype': 'IPv4',
                                'remote_mode': 'remote_group_id'
                            }
                        ],
                        'description': 'security_group_1',
                        'name': 'security_group_1'
                    }
                },
                'security_group_1': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'rules': [
                            {
                                'remote_group_id': {
                                    'get_resource': 'security_group_0'
                                },
                                'direction': 'ingress',
                                'protocol': 'udp',
                                'ethertype': 'IPv4',
                                'port_range_max': 8888,
                                'port_range_min': 7777,
                                'remote_mode': 'remote_group_id'
                            },
                            {
                                'ethertype': 'IPv6',
                                'direction': 'egress'
                            },
                            {
                                'ethertype': 'IPv4',
                                'direction': 'egress'
                            },
                            {
                                'remote_group_id': {
                                    'get_resource': 'security_group_0'
                                },
                                'direction': 'ingress',
                                'protocol': 'tcp',
                                'ethertype': 'IPv4',
                                'port_range_max': 65535,
                                'port_range_min': 1,
                                'remote_mode': 'remote_group_id'
                            }
                        ],
                        'description': 'security_group_2',
                        'name': 'security_group_2'
                    }
                }
            }
        }
        generator.extract_secgroups()
        self.assertEqual(expected, generator.template)


class VolumeTests(base.TestCase):

    def setUp(self):
        super(VolumeTests, self).setUp()
        self.neutron_manager = FakeNeutronManager()
        TemplateGenerator.neutron_manager = (lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        TemplateGenerator.nova_manager = (lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        TemplateGenerator.cinder_manager = (lambda x: self.cinder_manager)

    def test_basic(self):
        self.cinder_manager.volumes = [FakeVolume()]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_source_volid_external(self):
        self.cinder_manager.volumes = [FakeVolume(source_volid=5678)]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_source_volid': {
                    'description': 'Volume to create volume volume_0 from',
                    'type': 'string'
                }
            },
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'source_volid': {'get_param': 'volume_0_source_volid'},
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_source_volid_included(self):
        self.cinder_manager.volumes = [
            FakeVolume(source_volid=5678), FakeVolume(id=5678)]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'source_volid': {'get_resource': 'volume_1'},
                        'size': 1
                    }
                },
                'volume_1': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_image(self):
        metadata = {
            'kernel_id': '9817',
            'container_format': 'bare',
            'min_ram': '0',
            'ramdisk_id': '4ec7',
            'disk_format': 'qcow2',
            'image_name': 'cirros-0.3.1-x86_64-uec',
            'image_id': '5c5c',
            'checksum': 'f8a2e',
            'min_disk': '0',
            'size': '25'}

        self.cinder_manager.volumes = [
            FakeVolume(bootable='true', volume_image_metadata=metadata)
        ]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_image': {
                    'default': '5c5c',
                    'description': 'Image to create volume volume_0 from',
                    'type': 'string'
                }
            },
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'image': {'get_param': 'volume_0_image'},
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_snapshot_id(self):
        self.cinder_manager.volumes = [FakeVolume(snapshot_id=5678)]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_snapshot_id': {
                    'default': 5678,
                    'description': 'Snapshot to create volume volume_0 from',
                    'type': 'string'
                }
            },
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'snapshot_id': {'get_param': 'volume_0_snapshot_id'},
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_volume_type(self):
        self.cinder_manager.volumes = [FakeVolume(volume_type='isci')]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_volume_type': {
                    'description': 'Volume type for volume volume_0',
                    'default': 'isci',
                    'type': 'string'
                }
            },
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'volume_type': {'get_param': 'volume_0_volume_type'},
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)

    def test_metadata(self):
        self.cinder_manager.volumes = [FakeVolume(metadata={'key': 'value'})]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {},
            'resources': {
                'volume_0': {
                    'type': 'OS::Cinder::Volume',
                    'properties': {
                        'name': 'vol1',
                        'description': 'Description',
                        'metadata': {'key': 'value'},
                        'size': 1
                    }
                }
            }
        }
        generator.extract_volumes()
        self.assertEqual(expected, generator.template)


class ServerTests(base.TestCase):

    def setUp(self):
        super(ServerTests, self).setUp()
        self.neutron_manager = FakeNeutronManager()
        TemplateGenerator.neutron_manager = (lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        TemplateGenerator.nova_manager = (lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        TemplateGenerator.cinder_manager = (lambda x: self.cinder_manager)

    def test_basic(self):
        self.nova_manager.servers = [FakeServer()]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_keypair(self):
        self.nova_manager.servers = [FakeServer(key_name='testkey')]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'key_name': {'get_resource': 'key_0'},
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_boot_from_volume(self):
        attachments = [{'device': 'vda',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}]
        self.cinder_manager.volumes = [FakeVolume(id=5678,
                                                  attachments=attachments,
                                                  bootable='true')]
        servers_args = {
            "id": 777,
            "image": None,
            "os-extended-volumes:volumes_attached": [{'id': 5678}]
        }
        server = FakeServer(**servers_args)
        self.nova_manager.servers = [server]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'block_device_mapping': [{'volume_id': {
                            'get_resource': 'volume_0'}, 'device_name': 'vda'}]
                    }
                },
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_volume_attached(self):
        attachments = [{'device': '/dev/vdb',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}]
        self.cinder_manager.volumes = [FakeVolume(id=5678,
                                                  attachments=attachments,
                                                  bootable='false')]
        server_args = {
            "id": 777,
            "os-extended-volumes:volumes_attached": [{'id': 5678}]}
        server = FakeServer(**server_args)
        self.nova_manager.servers = [server]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                        'block_device_mapping': [{'volume_id': {
                            'get_resource': 'volume_0'}, 'device_name':
                            '/dev/vdb'}]
                    }
                },
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_security_groups(self):
        self.neutron_manager.groups = [
            {"name": "group1", "id": "1", "security_group_rules": [],
                "description": "Group"}
        ]
        self.nova_manager.groups = {'server1': [FakeSecurityGroup()]}
        self.nova_manager.servers = [FakeServer()]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'security_group_0': {
                    'type': 'OS::Neutron::SecurityGroup',
                    'properties': {
                        'description': 'Group',
                        'name': 'group1',
                        'rules': []
                    }
                },
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'security_groups': [
                            {
                                'get_resource': 'security_group_0'
                            }
                        ],
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'}
                    }
                }
            }
        }
        generator.extract_secgroups()
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_config_drive(self):
        self.nova_manager.servers = [FakeServer(config_drive="True")]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'config_drive': 'True',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_metadata(self):
        self.nova_manager.servers = [FakeServer(metadata={"key": "value"})]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'metadata': {'key': 'value'},
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_networks(self):
        subnet = {
            "id": "4321",
            "name": "private_subnet",
            "network_id": "1234",
            "allocation_pools": {"start": "10.0.0.2", "end": "10.0.0.254"},
            "cidr": "10.0.0.0/24",
            "dns_nameservers": [],
            "enable_dhcp": True,
            "host_routes": [],
            "ip_version": 4}
        self.neutron_manager.subnets = [subnet]
        network = {
            "id": "1234",
            "name": "private"}
        self.neutron_manager.networks = [network]
        addresses = {"private": [{"addr": "10.0.0.2"}]}
        self.nova_manager.servers = [FakeServer(addresses=addresses)]
        generator = TemplateGenerator(False, False, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'networks': [
                            {'network': {'get_resource': 'network_0'}}],
                        'image': {'get_param': 'server_0_image'},
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)

    def test_excluded_volume_attached(self):
        attachments = [{'device': '/dev/vdb',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}]
        self.cinder_manager.volumes = [FakeVolume(id=5678,
                                                  attachments=attachments,
                                                  bootable='false')]
        server_args = {
            "id": 777,
            "os-extended-volumes:volumes_attached": [{'id': 5678}]}
        server = FakeServer(**server_args)
        self.nova_manager.servers = [server]
        generator = TemplateGenerator(False, True, False)
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'server_0_flavor': {
                    'default': 'm1.small',
                    'description': 'Flavor to use for server server_0',
                    'type': 'string'
                },
                'server_0_image': {
                    'description': 'Image to use to boot server server_0',
                    'default': '3333',
                    'type': 'string'
                },
                'volume_server1_0': {
                    'default': 5678,
                    'description': 'Volume for server server1, device '
                                   '/dev/vdb',
                    'type': 'string'
                }
            },
            'resources': {
                'server_0': {
                    'type': 'OS::Nova::Server',
                    'properties': {
                        'name': 'server1',
                        'diskConfig': 'MANUAL',
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'},
                        'block_device_mapping': [{'volume_id': {
                            'get_param': 'volume_server1_0'}, 'device_name':
                            '/dev/vdb'}]
                    }
                }
            }
        }
        generator.extract_servers()
        self.assertEqual(expected, generator.template)
