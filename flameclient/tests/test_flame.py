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

import mock

from flameclient import client as flame_client
from flameclient import flame
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
    volume_type = 'fast'
    metadata = None


class FakeUnnamedVolume(FakeBase):
    id = 1234
    size = 1
    source_volid = None
    bootable = 'false'
    snapshot_id = None
    volume_type = 'fast'
    metadata = None


class FakeServer(FakeBase):
    id = '1234'
    name = 'server1'
    config_drive = None
    flavor = {'id': '2'}
    image = {'id': '3333',
             'links': [{'href': 'http://p/7777/images/3333',
                        'rel': 'bookmark'}]}
    key_name = 'testkey'
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

    def __init__(self):
        self.groups = []
        self.routers = [{'name': 'myrouter',
                         'id': '1234',
                         'admin_state_up': 'true',
                         'external_gateway_info': None}, ]
        self.ports = []
        self.subnets = []
        self.networks = [{'status': 'ACTIVE',
                          'subnets': ['1111'],
                          'name': 'mynetwork',
                          'router:external': False,
                          'admin_state_up': True,
                          'shared': False,
                          'id': '2222'}, ]
        self.floatingips = []

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

    def __init__(self):
        self.servers = [FakeServer()]
        self.flavors = [FakeFlavor(id='2', name='m1.small')]
        self.groups = {}
        self.keypairs = [FakeKeypair(name='testkey',
                                     public_key='ssh-rsa XXXX')]

    def keypair_list(self):
        return self.keypairs

    def flavor_list(self):
        return self.flavors

    def server_list(self):
        return self.servers

    def server_security_group_list(self, server):
        return self.groups.get(server.name, [])


class FakeCinderManager(object):

    def __init__(self):
        self.volumes = [FakeVolume(), ]

    def volume_list(self):
        return self.volumes


class ResourceTestCase(base.TestCase):

    def test_template_resource(self):
        resource = flame.Resource('my-name',
                                  'my-type',
                                  properties='my-properties')

        expected = {
            'my-name': {
                'type': 'my-type',
                'properties': 'my-properties',
            }
        }
        self.assertEqual(expected, resource.template_resource)

    def test_stack_resource(self):
        resource = flame.Resource('my-name', 'my-type', id='my-id')

        expected = {
            'my-name': {
                'status': 'COMPLETE',
                'name': 'my-name',
                'resource_data': {},
                'resource_id': 'my-id',
                'type': 'my-type',
                'metadata': {},
                'action': 'CREATE'
            }
        }
        self.assertEqual(expected, resource.stack_resource)

    def test_empty_stack_resource(self):
        resource = flame.Resource('my-name', 'my-type')
        self.assertEqual({}, resource.stack_resource)

    def test_add_parameter(self):
        resource = flame.Resource('my-name', 'my-type')
        resource.add_parameter('my-parameter', 'my-description')

        expected = {
            'my-parameter': {
                'type': 'string',
                'description': 'my-description'
            }
        }
        self.assertEqual(expected, resource.template_parameter)

    def test_add_parameter_with_type(self):
        resource = flame.Resource('my-name', 'my-type')
        resource.add_parameter('my-parameter', 'my-description',
                               parameter_type='my-type')

        expected = {
            'my-parameter': {
                'type': 'my-type',
                'description': 'my-description'
            }
        }
        self.assertEqual(expected, resource.template_parameter)

    def test_add_parameter_with_default(self):
        resource = flame.Resource('my-name', 'my-type')
        resource.add_parameter('my-parameter', 'my-description',
                               default='my-default')

        expected = {
            'my-parameter': {
                'type': 'string',
                'description': 'my-description',
                'default': 'my-default'
            }
        }
        self.assertEqual(expected, resource.template_parameter)


class BaseTestCase(base.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.patch_neutron = mock.patch('flameclient.managers.NeutronManager')
        self.mock_neutron = self.patch_neutron.start()
        self.patch_nova = mock.patch('flameclient.managers.NovaManager')
        self.mock_nova = self.patch_nova.start()
        self.patch_cinder = mock.patch('flameclient.managers.CinderManager')
        self.mock_cinder = self.patch_cinder.start()
        self.patch_keystone = mock.patch(
            'flameclient.managers.KeystoneManager'
        )
        self.mock_keystone = self.patch_keystone.start()

    def tearDown(self):
        self.mock_neutron.stop()
        self.mock_nova.stop()
        self.mock_cinder.stop()
        self.mock_keystone.stop()
        super(BaseTestCase, self).tearDown()

    def get_generator(self, exclude_servers, exclude_volumes,
                      exclude_keypairs, generate_data):
        generator = flame.TemplateGenerator('x', 'x', 'x', 'x', True,
                                            'publicURL')
        generator.extract_vm_details(exclude_servers, exclude_volumes,
                                     exclude_keypairs, generate_data)
        return generator

    def check_stackdata(self, resources, expected_resources):
        merged_resources = {}
        for resource in resources:
            merged_resources.update(resource.stack_resource)

        self.assertEqual(expected_resources, merged_resources)

    def check_template(self, resources, expected_resources,
                       expected_parameters=None):

        expected_parameters = expected_parameters or {}
        merged_resources = {}
        merged_parameters = {}
        for resource in resources:
            merged_resources.update(resource.template_resource)
            merged_parameters.update(resource.template_parameter)

        self.assertEqual(expected_resources, merged_resources)
        self.assertEqual(expected_parameters, merged_parameters)


class ClientTest(BaseTestCase):
    def setUp(self):
        super(ClientTest, self).setUp()
        self.c = flame_client.Client('username', 'password', 'tenant_name',
                                     'authUrl', 'auth_token')

    def test_generate(self):
        out = self.c.generate(False, False, False, True)
        self.assertIsInstance(out, tuple)
        self.assertIsNotNone(out[1])

    def test_generate_no_stack_data(self):
        out = self.c.generate(False, False, False, False)
        self.assertIsInstance(out, tuple)
        self.assertIsNotNone(out[0])
        self.assertIsNone(out[1])

    def test_generate_contains_extract(self):
        generator = self.get_generator(False, False, False, True)
        out = self.c.generate(False, False, False, True)
        generator.extract_data()
        stack_data = generator.stack_data_template()
        heat_template = generator.heat_template()
        self.assertEqual(out, (heat_template, stack_data))


class StackDataTests(BaseTestCase):

    def test_keypair(self):
        self.mock_nova.return_value = FakeNovaManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_keys(), expected)

    def test_router(self):
        self.mock_neutron.return_value = FakeNeutronManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_routers(), expected)

    def test_router_with_external_gateway(self):
        fake = FakeNeutronManager()
        fake.routers = [{'name': 'myrouter',
                         'id': '1234',
                         'admin_state_up': 'true',
                         'external_gateway_info': {
                             'network_id': '8765',
                             'enable_snat': 'true'}}, ]
        self.mock_neutron.return_value = fake
        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_routers(), expected)

    def test_router_with_ports(self):
        fake = FakeNeutronManager()
        fake.ports = [{'status': 'ACTIVE',
                       'name': '',
                       'allowed_address_pairs': [],
                       'admin_state_up': True,
                       'network_id': '4444',
                       'extra_dhcp_opts': [],
                       'binding:vnic_type': 'normal',
                       'device_owner': 'network:router_interface',
                       'mac_address': 'fa:16:3e:4b:8c:98',
                       'fixed_ips': [{'subnet_id': '1111',
                                      'ip_address': '10.123.2.3'}],
                       'id': '1234567',
                       'security_groups': [],
                       'device_id': '1234'}, ]
        fake.subnets = [{'name': 'subnet_1111',
                         'enable_dhcp': True,
                         'network_id': '1234',
                         'dns_nameservers': [],
                         'allocation_pools': [{'start': '10.123.2.2',
                                               'end': '10.123.2.30'}],
                         'host_routes': [],
                         'ip_version': 4,
                         'gateway_ip': '10.123.2.1',
                         'cidr': '10.123.2.0/27',
                         'id': '1111'}, ]

        self.mock_neutron.return_value = fake
        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_routers(), expected)

    def test_network(self):
        self.mock_neutron.return_value = FakeNeutronManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_networks(), expected)

    def test_external_network(self):
        fake = FakeNeutronManager()
        fake.networks[0]['router:external'] = True
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        self.check_stackdata(generator._extract_networks(), {})

    def test_subnet(self):
        fake = FakeNeutronManager()
        fake.subnets = [{'name': 'subnet_1111',
                         'enable_dhcp': True,
                         'network_id': '2222',
                         'dns_nameservers': [],
                         'allocation_pools': [{'start': '10.123.2.2',
                                               'end': '10.123.2.30'}],
                         'host_routes': [],
                         'ip_version': 4,
                         'gateway_ip': '10.123.2.1',
                         'cidr': '10.123.2.0/27',
                         'id': '1111'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_subnets(), expected)

    def test_floatingip(self):
        fake = FakeNeutronManager()
        fake.floatingips = [{'router_id': '1111',
                             'status': 'ACTIVE',
                             'floating_network_id': '1234',
                             'fixed_ip_address': '10.0.48.251',
                             'floating_ip_address': '84.39.33.60',
                             'port_id': '4321',
                             'id': '2222'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(True, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_floating(), expected)

    def test_security_group(self):
        rules = [{'remote_group_id': None,
                  'direction': 'ingress',
                  'remote_ip_prefix': '0.0.0.0/0',
                  'protocol': 'tcp',
                  'ethertype': 'IPv4',
                  'tenant_id': '7777',
                  'port_range_max': 22,
                  'port_range_min': 22,
                  'id': '8901',
                  'security_group_id': '1234'}, ]
        fake = FakeNeutronManager()
        fake.groups = [{'tenant_id': '7777',
                        'name': 'somename',
                        'description': 'description',
                        'security_group_rules': rules,
                        'id': '1234'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_secgroups(), expected)

    def test_default_security_group(self):
        rules = [{'remote_group_id': None,
                  'direction': 'ingress',
                  'remote_ip_prefix': '0.0.0.0/0',
                  'protocol': 'tcp',
                  'ethertype': 'IPv4',
                  'tenant_id': '7777',
                  'port_range_max': 22,
                  'port_range_min': 22,
                  'id': '8901',
                  'security_group_id': '1234'}, ]
        fake = FakeNeutronManager()
        fake.groups = [{'tenant_id': '7777',
                        'name': 'default',
                        'description': 'default',
                        'security_group_rules': rules,
                        'id': '1234'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        self.check_stackdata(generator._extract_secgroups(), {})

    def test_volume(self):
        self.mock_cinder.return_value = FakeCinderManager()

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_volumes(), expected)

    def test_server(self):
        self.mock_nova.return_value = FakeNovaManager()

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_servers(), expected)

    def test_server_with_default_security_group(self):
        fake_neutron = FakeNeutronManager()
        fake_nova = FakeNovaManager()
        fake_neutron.groups = [{"name": "default",
                                "id": "1",
                                "security_group_rules": [],
                                "description": "default"}, ]
        fake_nova.groups = {'server1': [FakeSecurityGroup(
            name='default', description='default')]}
        self.mock_neutron.return_value = fake_neutron
        self.mock_nova.return_value = fake_nova

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_stackdata(generator._extract_servers(), expected)


class NetworkTests(BaseTestCase):

    def test_keypair(self):
        self.mock_nova.return_value = FakeNovaManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
            'key_0': {
                'type': 'OS::Nova::KeyPair',
                'properties': {
                    'public_key': 'ssh-rsa XXXX',
                    'name': 'testkey'
                }
            }
        }
        self.check_template(generator._extract_keys(), expected)

    def test_router(self):
        self.mock_neutron.return_value = FakeNeutronManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
            'router_0': {
                'type': 'OS::Neutron::Router',
                'properties': {
                    'name': 'myrouter',
                    'admin_state_up': 'true',
                }
            }
        }
        self.check_template(generator._extract_routers(), expected)

    def test_router_with_external_gateway(self):
        fake = FakeNeutronManager()
        fake.routers = [{'name': 'myrouter',
                         'id': '1234',
                         'admin_state_up': 'true',
                         'external_gateway_info': {
                             'network_id': '8765',
                             'enable_snat': 'true'}}, ]
        self.mock_neutron.return_value = fake
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'router_0_external_network': {
                'default': '8765',
                'type': 'string',
                'description': 'Router external network'
            }
        }
        expected_resources = {
            'router_0': {
                'type': 'OS::Neutron::Router',
                'properties': {
                    'name': 'myrouter',
                    'admin_state_up': 'true',
                }
            },
            'router_0_gateway': {
                'type': 'OS::Neutron::RouterGateway',
                'properties': {
                    'router_id': {'get_resource': 'router_0'},
                    'network_id': {
                        'get_param': 'router_0_external_network'
                    }
                }
            }
        }
        self.check_template(generator._extract_routers(), expected_resources,
                            expected_parameters)

    def test_router_with_ports(self):
        fake = FakeNeutronManager()
        fake.ports = [{'status': 'ACTIVE',
                       'name': '',
                       'allowed_address_pairs': [],
                       'admin_state_up': True,
                       'network_id': '4444',
                       'extra_dhcp_opts': [],
                       'binding:vnic_type': 'normal',
                       'device_owner': 'network:router_interface',
                       'mac_address': 'fa:16:3e:4b:8c:98',
                       'fixed_ips': [{'subnet_id': '1111',
                                      'ip_address': '10.123.2.3'}],
                       'id': '1234567',
                       'security_groups': [],
                       'device_id': '1234'}, ]
        fake.subnets = [{'name': 'subnet_1111',
                         'enable_dhcp': True,
                         'network_id': '1234',
                         'dns_nameservers': [],
                         'allocation_pools': [{'start': '10.123.2.2',
                                               'end': '10.123.2.30'}],
                         'host_routes': [],
                         'ip_version': 4,
                         'gateway_ip': '10.123.2.1',
                         'cidr': '10.123.2.0/27',
                         'id': '1111'}, ]

        self.mock_neutron.return_value = fake
        generator = self.get_generator(False, False, False, True)

        expected = {
            'router_0': {
                'type': 'OS::Neutron::Router',
                'properties': {
                    'name': 'myrouter',
                    'admin_state_up': 'true',
                }
            },
            'router_0_interface_0': {
                'type': 'OS::Neutron::RouterInterface',
                'properties': {
                    'subnet_id': {'get_resource': 'subnet_0'},
                    'router_id': {'get_resource': 'router_0'}
                }
            }
        }
        self.check_template(generator._extract_routers(), expected)

    def test_network(self):
        self.mock_neutron.return_value = FakeNeutronManager()
        generator = self.get_generator(False, False, False, True)

        expected = {
            'network_0': {
                'type': 'OS::Neutron::Net',
                'properties': {
                    'shared': False,
                    'name': 'mynetwork',
                    'admin_state_up': True
                }
            }
        }
        self.check_template(generator._extract_networks(), expected)

    def test_external_network(self):
        fake = FakeNeutronManager()
        fake.networks[0]['router:external'] = True
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        self.check_template(generator._extract_networks(), {})

    def test_subnet(self):
        fake = FakeNeutronManager()
        fake.subnets = [{'name': 'subnet_1111',
                         'enable_dhcp': True,
                         'network_id': '2222',
                         'dns_nameservers': [],
                         'allocation_pools': [{'start': '10.123.2.2',
                                               'end': '10.123.2.30'}],
                         'host_routes': [],
                         'ip_version': 4,
                         'gateway_ip': '10.123.2.1',
                         'cidr': '10.123.2.0/27',
                         'id': '1111'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_template(generator._extract_subnets(), expected)

    def test_floatingip(self):
        fake = FakeNeutronManager()
        fake.floatingips = [{'router_id': '1111',
                             'status': 'ACTIVE',
                             'floating_network_id': '1234',
                             'fixed_ip_address': '10.0.48.251',
                             'floating_ip_address': '84.39.33.60',
                             'port_id': '4321',
                             'id': '2222'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(True, False, False, False)

        expected_parameters = {
            'external_network_for_floating_ip_0': {
                'default': '1234',
                'type': 'string',
                'description': 'Network to allocate floating IP from'
            }
        }
        expected_resources = {
            'floatingip_0': {
                'type': 'OS::Neutron::FloatingIP',
                'properties': {
                    'floating_network_id': {
                        'get_param': 'external_network_for_floating_ip_0'
                    }
                }
            }
        }
        self.check_template(generator._extract_floating(), expected_resources,
                            expected_parameters)

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
        fake = FakeNeutronManager()
        fake.groups = [{'tenant_id': '7777',
                        'name': 'toto',
                        'description': 'description',
                        'security_group_rules': rules,
                        'id': '1234'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, False)

        expected = {
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
        self.check_template(generator._extract_secgroups(), expected)

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
        fake = FakeNeutronManager()
        fake.groups = [{'tenant_id': '7777',
                        'name': 'default',
                        'description': 'default',
                        'security_group_rules': rules,
                        'id': '1111'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, False)

        expected = {
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
        self.check_template(generator._extract_secgroups(), expected)

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
        fake = FakeNeutronManager()
        fake.groups = [{'tenant_id': '7777',
                        'name': 'security_group_1',
                        'description': 'security_group_1',
                        'security_group_rules': rules1,
                        'id': '1111'},
                       {'tenant_id': '7777',
                        'name': 'security_group_2',
                        'description': 'security_group_2',
                        'security_group_rules': rules2,
                        'id': '2222'}, ]
        self.mock_neutron.return_value = fake

        generator = self.get_generator(False, False, False, True)

        expected = {
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
        self.check_template(generator._extract_secgroups(), expected)


class VolumeTests(BaseTestCase):

    def setUp(self):
        super(VolumeTests, self).setUp()
        self.fake = FakeCinderManager()
        self.mock_cinder.return_value = self.fake

    def test_basic(self):
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'}
        }

        expected_resources = {
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
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_basic_unnamed(self):
        self.fake.volumes = [FakeUnnamedVolume(), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'}
        }

        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_source_volid_external(self):
        self.fake.volumes = [FakeVolume(source_volid=5678), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_source_volid': {
                'description': 'Volume to create volume volume_0 from',
                'type': 'string'
            },
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'}
        }
        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'source_volid': {'get_param': 'volume_0_source_volid'},
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_source_volid_included(self):
        self.fake.volumes = [FakeVolume(source_volid=5678),
                             FakeVolume(id=5678)]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            },
            'volume_1_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_1',
                'type': 'string'
            }
        }

        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'source_volid': {'get_resource': 'volume_1'},
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            },
            'volume_1': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'volume_type': {'get_param': 'volume_1_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

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
        self.fake.volumes = [FakeVolume(bootable='true',
                                        volume_image_metadata=metadata), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            },
            'volume_0_image': {
                'default': '5c5c',
                'description': 'Image to create volume volume_0 from',
                'type': 'string'
            }
        }
        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'image': {'get_param': 'volume_0_image'},
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_snapshot_id(self):
        self.fake.volumes = [FakeVolume(snapshot_id=5678), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_snapshot_id': {
                'default': 5678,
                'description': 'Snapshot to create volume volume_0 from',
                'type': 'string'
            },
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'snapshot_id': {'get_param': 'volume_0_snapshot_id'},
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_volume_type(self):
        self.fake.volumes = [FakeVolume(volume_type='isci'), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'description': 'Volume type for volume volume_0',
                'default': 'isci',
                'type': 'string'
            }
        }
        expected_resources = {
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
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)

    def test_metadata(self):
        self.fake.volumes = [FakeVolume(metadata={'key': 'value'}), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'volume_0': {
                'type': 'OS::Cinder::Volume',
                'properties': {
                    'name': 'vol1',
                    'description': 'Description',
                    'metadata': {'key': 'value'},
                    'volume_type': {'get_param': 'volume_0_volume_type'},
                    'size': 1
                }
            }
        }
        self.check_template(generator._extract_volumes(), expected_resources,
                            expected_parameters)


class ServerTests(BaseTestCase):

    def setUp(self):
        super(ServerTests, self).setUp()
        self.fake = FakeNovaManager()
        self.mock_nova.return_value = self.fake

    def test_basic(self):
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_keypair(self):
        self.fake.servers = [FakeServer(key_name='testkey')]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'key_name': {'get_resource': 'key_0'},
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_boot_from_volume(self):
        attachments = [{'device': 'vda',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}, ]
        servers_args = {"id": 777,
                        "image": None,
                        "os-extended-volumes:volumes_attached": [{'id': 5678}]}
        self.fake.servers = [FakeServer(**servers_args), ]
        fake_cinder = FakeCinderManager()
        fake_cinder.volumes = [FakeVolume(id=5678,
                                          attachments=attachments,
                                          bootable='true')]
        self.mock_cinder.return_value = fake_cinder

        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'server_0_flavor': {
                'default': 'm1.small',
                'description': 'Flavor to use for server server_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'key_name': {'get_resource': 'key_0'},
                    'block_device_mapping_v2': [{'volume_id': {
                        'get_resource': 'volume_0'}, 'device_name': 'vda'}]
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_volume_attached(self):
        attachments = [{'device': '/dev/vdb',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}, ]
        fake_cinder = FakeCinderManager()
        fake_cinder.volumes = [FakeVolume(id=5678, attachments=attachments,
                                          bootable='false'), ]
        self.mock_cinder.return_value = fake_cinder
        server_args = {"id": 777,
                       "os-extended-volumes:volumes_attached": [{'id': 5678}]}
        self.fake.servers = [FakeServer(**server_args), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'},
                    'block_device_mapping_v2': [{'volume_id': {
                        'get_resource': 'volume_0'}, 'device_name':
                        '/dev/vdb'}]
                }
            },
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_security_groups(self):
        fake_neutron = FakeNeutronManager()
        fake_neutron.groups = [{"name": "group1",
                                "id": "1",
                                "security_group_rules": [],
                                "description": "Group"}, ]
        self.mock_neutron.return_value = fake_neutron
        self.fake.groups = {'server1': [FakeSecurityGroup(), ]}
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
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
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        generator._extract_secgroups()
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_config_drive(self):
        self.fake.servers = [FakeServer(config_drive="True"), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'config_drive': 'True',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_metadata(self):
        self.fake.servers = [FakeServer(metadata={"key": "value"}), ]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'metadata': {'key': 'value'},
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

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
        fake_neutron = FakeNeutronManager()
        fake_neutron.subnets = [subnet]
        fake_neutron.networks = [{"id": "1234", "name": "private"}, ]
        self.mock_neutron.return_value = fake_neutron
        addresses = {"private": [{"addr": "10.0.0.2"}]}
        self.fake.servers = [FakeServer(addresses=addresses)]
        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'networks': [
                        {'network': {'get_resource': 'network_0'}}],
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'}
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)

    def test_excluded_volume_attached(self):
        attachments = [{'device': '/dev/vdb',
                        'server_id': '777',
                        'id': '5678',
                        'host_name': None,
                        'volume_id': '5678'}]
        fake_cinder = FakeCinderManager()
        fake_cinder.volumes = [FakeVolume(id=5678, attachments=attachments,
                                          bootable='false'), ]
        self.mock_cinder.return_value = fake_cinder
        server_args = {"id": 777,
                       "os-extended-volumes:volumes_attached": [{'id': 5678}]}
        self.fake.servers = [FakeServer(**server_args), ]
        generator = self.get_generator(False, True, False, False)

        expected_parameters = {
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
        }
        expected_resources = {
            'server_0': {
                'type': 'OS::Nova::Server',
                'properties': {
                    'name': 'server1',
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'},
                    'block_device_mapping_v2': [{'volume_id': {
                        'get_param': 'volume_server1_0'}, 'device_name':
                        '/dev/vdb'}]
                }
            }
        }
        self.check_template(generator._extract_servers(), expected_resources,
                            expected_parameters)


class GenerationTests(BaseTestCase):

    def setUp(self):
        super(GenerationTests, self).setUp()
        self.mock_neutron.return_value = FakeNeutronManager()
        self.mock_nova.return_value = FakeNovaManager()
        self.mock_cinder.return_value = FakeCinderManager()

    def test_generation(self):

        generator = self.get_generator(False, False, False, True)

        expected_parameters = {
            'server_0_flavor': {
                'default': 'm1.small',
                'description': 'Flavor to use for server server_0',
                'type': 'string'
            },
            'server_0_image': {
                'default': '3333',
                'description': 'Image to use to boot server server_0',
                'type': 'string'
            },
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'key_0': {
                'properties': {
                    'name': 'testkey',
                    'public_key': 'ssh-rsa XXXX'
                },
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'properties': {
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'},
                    'name': 'server1'
                },
                'type': 'OS::Nova::Server'
            },
            'volume_0': {
                'properties': {
                    'description': 'Description',
                    'name': 'vol1',
                    'size': 1,
                    'volume_type': {'get_param': 'volume_0_volume_type'}
                },
                'type': 'OS::Cinder::Volume'
            }
        }

        expected_data = {
            'key_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'key_0',
                'resource_data': {},
                'resource_id': 'key',
                'status': 'COMPLETE',
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'server_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Nova::Server'
            },
            'volume_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'volume_0',
                'resource_data': {},
                'resource_id': 1234,
                'status': 'COMPLETE',
                'type': 'OS::Cinder::Volume'
            }
        }
        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers(self):

        generator = self.get_generator(True, False, False, True)

        expected_parameters = {
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            }
        }

        expected_resources = {
            'key_0': {
                'properties': {
                    'name': 'testkey',
                    'public_key': 'ssh-rsa XXXX'
                },
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            },
            'volume_0': {
                'properties': {
                    'description': 'Description',
                    'name': 'vol1',
                    'size': 1,
                    'volume_type': {'get_param': 'volume_0_volume_type'}
                },
                'type': 'OS::Cinder::Volume'
            }
        }

        expected_data = {
            'key_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'key_0',
                'resource_data': {},
                'resource_id': 'key',
                'status': 'COMPLETE',
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            },
            'volume_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'volume_0',
                'resource_data': {},
                'resource_id': 1234,
                'status': 'COMPLETE',
                'type': 'OS::Cinder::Volume'
            }
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_volumes(self):

        generator = self.get_generator(False, True, False, True)

        expected_parameters = {
            'server_0_flavor': {
                'default': 'm1.small',
                'description': 'Flavor to use for server server_0',
                'type': 'string'
            },
            'server_0_image': {
                'default': '3333',
                'description': 'Image to use to boot server server_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'key_0': {
                'properties': {
                    'name': 'testkey',
                    'public_key': 'ssh-rsa XXXX'
                },
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'properties': {
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_resource': 'key_0'},
                    'name': 'server1'
                },
                'type': 'OS::Nova::Server'
            },
        }

        expected_data = {
            'key_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'key_0',
                'resource_data': {},
                'resource_id': 'key',
                'status': 'COMPLETE',
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'server_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Nova::Server'
            }
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_keypairs(self):

        generator = self.get_generator(False, False, True, True)

        expected_parameters = {
            'server_0_flavor': {
                'default': 'm1.small',
                'description': 'Flavor to use for server server_0',
                'type': 'string'
            },
            'server_0_image': {
                'default': '3333',
                'description': 'Image to use to boot server server_0',
                'type': 'string'
            },
            'server_0_key': {
                'default': 'testkey',
                'description': 'Key for server server_0',
                'type': 'string'
            },
            'volume_0_volume_type': {
                'default': 'fast',
                'description': 'Volume type for volume volume_0',
                'type': 'string'
            }
        }
        expected_resources = {
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'properties': {
                    'diskConfig': 'MANUAL',
                    'flavor': {'get_param': 'server_0_flavor'},
                    'image': {'get_param': 'server_0_image'},
                    'key_name': {'get_param': 'server_0_key'},
                    'name': 'server1'
                },
                'type': 'OS::Nova::Server'
            },
            'volume_0': {
                'properties': {
                    'description': 'Description',
                    'name': 'vol1',
                    'size': 1,
                    'volume_type': {'get_param': 'volume_0_volume_type'}
                },
                'type': 'OS::Cinder::Volume'
            }
        }

        expected_data = {
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            },
            'server_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'server_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Nova::Server'
            },
            'volume_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'volume_0',
                'resource_data': {},
                'resource_id': 1234,
                'status': 'COMPLETE',
                'type': 'OS::Cinder::Volume'
            }
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers_and_volumes(self):

        generator = self.get_generator(True, True, False, True)

        expected_parameters = {}
        expected_resources = {
            'key_0': {
                'properties': {
                    'name': 'testkey',
                    'public_key': 'ssh-rsa XXXX'
                },
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            },
        }

        expected_data = {
            'key_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'key_0',
                'resource_data': {},
                'resource_id': 'key',
                'status': 'COMPLETE',
                'type': 'OS::Nova::KeyPair'
            },
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            }
        }
        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers_volumes_keypairs(self):

        generator = self.get_generator(True, True, True, True)

        expected_parameters = {}
        expected_resources = {
            'network_0': {
                'properties': {
                    'admin_state_up': True,
                    'name': 'mynetwork',
                    'shared': False
                },
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'properties': {
                    'admin_state_up': 'true',
                    'name': 'myrouter'
                },
                'type': 'OS::Neutron::Router'
            }
        }
        expected_data = {
            'network_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'network_0',
                'resource_data': {},
                'resource_id': '2222',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Net'
            },
            'router_0': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'router_0',
                'resource_data': {},
                'resource_id': '1234',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::Router'
            }
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)
