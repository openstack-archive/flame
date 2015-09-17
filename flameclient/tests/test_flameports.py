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

    def __init__(self, server_id, **kwargs):
        self.id = server_id
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
        self.groups = [{u'description': u'default',
                        u'id': u'secgorup1',
                        u'name': u'default',
                        u'security_group_rules': [
                            {u'direction': u'ingress',
                             u'ethertype': u'IPv4',
                             u'id': u'secgroup-rule1',
                             u'port_range_max': 65535,
                             u'port_range_min': 1,
                             u'protocol': u'tcp',
                             u'remote_group_id': None,
                             u'remote_ip_prefix': u'0.0.0.0/0',
                             u'security_group_id': u'secgorup1',
                             u'tenant_id': u'tenant1'},
                        ],
                        u'tenant_id': u'tenant1'}]

        self.routers = [
            {u'admin_state_up': True,
             u'external_gateway_info': {u'enable_snat': True,
                                        u'network_id': u'network3'},
             u'id': u'router1',
             u'name': u'gw-internal-a',
             u'routes': [],
             u'status': u'ACTIVE',
             u'tenant_id': u'tenant1'},
        ]

        self.ports = [{u'admin_state_up': True,
                       u'allowed_address_pairs': [],
                       u'binding:vnic_type': u'normal',
                       u'device_id': u'router1',
                       u'device_owner': u'network:router_interface',
                       u'extra_dhcp_opts': [],
                       u'fixed_ips': [{u'ip_address': u'192.168.203.1',
                                       u'subnet_id': u'subnet3'}],
                       u'id': u'port1',
                       u'mac_address': u'fa:16:3e:fe:c1:b3',
                       u'name': u'',
                       u'network_id': u'network1',
                       u'security_groups': [],
                       u'status': u'ACTIVE',
                       u'tenant_id': u'tenant1'},
                      {u'admin_state_up': True,
                       u'allowed_address_pairs': [],
                       u'binding:vnic_type': u'normal',
                       u'device_id': u'server3',
                       u'device_owner': u'compute:nova',
                       u'extra_dhcp_opts': [],
                       u'fixed_ips': [{u'ip_address': u'192.168.203.5',
                                       u'subnet_id': u'subnet3'}],
                       u'id': u'port2',
                       u'mac_address': u'fa:16:3e:e4:44:7b',
                       u'name': u'',
                       u'network_id': u'network1',
                       u'security_groups': [u'secgorup1'],
                       u'status': u'ACTIVE',
                       u'tenant_id': u'tenant1'},
                      {u'admin_state_up': True,
                       u'allowed_address_pairs': [],
                       u'binding:vnic_type': u'normal',
                       u'device_id': u'server2',
                       u'device_owner': u'compute:nova',
                       u'extra_dhcp_opts': [],
                       u'fixed_ips': [{u'ip_address': u'192.168.203.4',
                                       u'subnet_id': u'subnet3'}],
                       u'id': u'port3',
                       u'mac_address': u'fa:16:3e:e8:e4:e2',
                       u'name': u'',
                       u'network_id': u'network1',
                       u'security_groups': [u'secgorup1'],
                       u'status': u'ACTIVE',
                       u'tenant_id': u'tenant1'},
                      {u'admin_state_up': True,
                       u'allowed_address_pairs': [],
                       u'binding:vnic_type': u'normal',
                       u'device_id': u'dhcp1-network1',
                       u'device_owner': u'network:dhcp',
                       u'extra_dhcp_opts': [],
                       u'fixed_ips': [{u'ip_address': u'192.168.203.3',
                                       u'subnet_id': u'subnet3'},
                                      {u'ip_address': u'192.168.204.2',
                                       u'subnet_id': u'subnet4'}],
                       u'id': u'port4',
                       u'mac_address': u'fa:16:3e:af:86:30',
                       u'name': u'',
                       u'network_id': u'network1',
                       u'security_groups': [],
                       u'status': u'ACTIVE',
                       u'tenant_id': u'tenant1'},
                      {u'admin_state_up': True,
                       u'allowed_address_pairs': [],
                       u'binding:vnic_type': u'normal',
                       u'device_id': u'server1',
                       u'device_owner': u'compute:nova',
                       u'extra_dhcp_opts': [],
                       u'fixed_ips': [{u'ip_address': u'192.168.203.2',
                                       u'subnet_id': u'subnet3'}],
                       u'id': u'port6',
                       u'mac_address': u'fa:16:3e:b0:9a:e2',
                       u'name': u'',
                       u'network_id': u'network1',
                       u'security_groups': [u'secgorup1'],
                       u'status': u'ACTIVE',
                       u'tenant_id': u'tenant1'}
                      ]
        self.subnets = [{u'allocation_pools': [
            {u'end': u'172.19.0.254', u'start': u'172.19.0.2'}],
            u'cidr': u'172.19.0.0/24',
            u'dns_nameservers': [],
            u'enable_dhcp': True,
            u'gateway_ip': u'172.19.0.1',
            u'host_routes': [],
            u'id': u'subnet1',
            u'ip_version': 4,
            u'name': u'storage',
            u'network_id': u'network2',
            u'tenant_id': u'tenant1'},
            {u'allocation_pools': [
                {u'end': u'10.8.8.200',
                 u'start': u'10.8.8.100'}],
                u'cidr': u'10.8.8.0/24',
                u'dns_nameservers': [],
                u'enable_dhcp': False,
                u'gateway_ip': u'10.8.8.254',
                u'host_routes': [],
                u'id': u'subnet2',
                u'ip_version': 4,
                u'name': u'ext-subnet',
                u'network_id': u'network3',
                u'tenant_id': u'tenant1'},
            {u'allocation_pools': [{u'end': u'192.168.203.254',
                                    u'start': u'192.168.203.2'}],
             u'cidr': u'192.168.203.0/24',
             u'dns_nameservers': [],
             u'enable_dhcp': True,
             u'gateway_ip': u'192.168.203.1',
             u'host_routes': [],
             u'id': u'subnet3',
             u'ip_version': 4,
             u'name': u'int-a-1',
             u'network_id': u'network1',
             u'tenant_id': u'tenant1'},
            {u'allocation_pools': [{u'end': u'192.168.204.254',
                                    u'start': u'192.168.204.2'}],
             u'cidr': u'192.168.204.0/24',
             u'dns_nameservers': [],
             u'enable_dhcp': True,
             u'gateway_ip': u'192.168.204.1',
             u'host_routes': [],
             u'id': u'subnet4',
             u'ip_version': 4,
             u'name': u'int-a-2',
             u'network_id': u'network1',
             u'tenant_id': u'tenant1'}]
        self.networks = [{u'admin_state_up': True,
                          u'id': u'network1',
                          u'name': u'internal',
                          u'router:external': False,
                          u'shared': False,
                          u'status': u'ACTIVE',
                          u'subnets': [u'subnet3',
                                       u'subnet4'],
                          u'tenant_id': u'tenant1'},
                         {u'admin_state_up': True,
                          u'id': u'network2',
                          u'name': u'storage',
                          u'router:external': False,
                          u'shared': False,
                          u'status': u'ACTIVE',
                          u'subnets': [u'subnet1'],
                          u'tenant_id': u'tenant1'},
                         {u'admin_state_up': True,
                          u'id': u'network3',
                          u'name': u'ext-net',
                          u'router:external': True,
                          u'shared': True,
                          u'status': u'ACTIVE',
                          u'subnets': [u'subnet2'],
                          u'tenant_id': u'tenant1'}]

        self.floatingips = [{u'fixed_ip_address': None,
                             u'floating_ip_address': u'10.8.8.102',
                             u'floating_network_id': u'network3',
                             u'id': u'floating1',
                             u'port_id': None,
                             u'router_id': None,
                             u'status': u'DOWN',
                             u'tenant_id': u'tenant1'},
                            {u'fixed_ip_address': None,
                             u'floating_ip_address': u'10.8.8.101',
                             u'floating_network_id': u'network3',
                             u'id': u'floating2',
                             u'port_id': None,
                             u'router_id': None,
                             u'status': u'DOWN',
                             u'tenant_id': u'tenant1'},
                            {u'fixed_ip_address': u'192.168.203.4',
                             u'floating_ip_address': u'10.8.8.168',
                             u'floating_network_id': u'network3',
                             u'id': u'floating3',
                             u'port_id': u'port3',
                             u'router_id': u'router1',
                             u'status': u'ACTIVE',
                             u'tenant_id': u'tenant1'},
                            {u'fixed_ip_address': None,
                             u'floating_ip_address': u'10.8.8.118',
                             u'floating_network_id': u'network3',
                             u'id': u'floating4',
                             u'port_id': None,
                             u'router_id': None,
                             u'status': u'DOWN',
                             u'tenant_id': u'tenant1'}]

    def subnet_list(self):
        return self.subnets

    def network_list(self):
        return self.networks

    def port_list(self):
        return self.ports

    def router_list(self):
        return self.routers

    def router_interfaces_list(self, router):
        return [port for port in self.ports
                if port['device_id'] == router['id']]

    def secgroup_list(self):
        return self.groups

    def floatingip_list(self):
        return self.floatingips


class FakeNovaManager(object):

    def __init__(self):
        self.servers = [FakeServer('server1'),
                        FakeServer('server2'),
                        FakeServer('server3')]
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

    def test_template_resource_depends(self):
        resource = flame.Resource('my-name',
                                  'my-type',
                                  properties='my-properties')
        resource.depends_on = "depended-on-resource"

        self.assertIn("depends_on",
                      resource.template_resource['my-name'])
        self.assertEqual("depended-on-resource",
                         resource.template_resource['my-name']['depends_on'])


class BaseTestCase(base.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.patch_neutron = mock.patch('flameclient.managers.NeutronManager')
        self.mock_neutron = self.patch_neutron.start()
        self.patch_nova = mock.patch('flameclient.managers.NovaManager')
        self.mock_nova = self.patch_nova.start()
        self.patch_cinder = mock.patch('flameclient.managers.CinderManager')
        self.mock_cinder = self.patch_cinder.start()

    def tearDown(self):
        self.mock_neutron.stop()
        self.mock_nova.stop()
        self.mock_cinder.stop()
        super(BaseTestCase, self).tearDown()

    def get_generator(self, exclude_servers, exclude_volumes,
                      exclude_keypairs, generate_data, extract_ports):
        generator = flame.TemplateGenerator('x', 'x', 'x', 'x', True,
                                            'publicURL')
        generator.extract_vm_details(exclude_servers, exclude_volumes,
                                     exclude_keypairs, generate_data,
                                     extract_ports)
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


class StackDataTests(BaseTestCase):

    def setUp(self):
        super(StackDataTests, self).setUp()
        self.mock_neutron.return_value = FakeNeutronManager()
        self.mock_nova.return_value = FakeNovaManager()
        self.mock_cinder.return_value = FakeCinderManager()

    def test_routers_presents(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_routers()
        routers = {r.name: r for r in extraction}
        self.assertIn('router_0', routers)

    def test_routers_resource_names(self):
        generator = self.get_generator(False, False, False, True, True)
        generator_output = generator._extract_routers()
        routers = (res for res in generator_output
                   if res.type == "OS::Neutron::Router")
        for n, router in enumerate(routers):
            assert(router.name.startswith("router_"))

    def test_ports_presents(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_ports()
        ports = {r.name: r for r in extraction}
        self.assertIn('port_1', ports)
        self.assertIn('port_2', ports)

    def test_ports_resource_names_types(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_ports()
        for n, port in enumerate(extraction):
            props = port.properties
            assert(extraction[0].name.startswith("port_"))
            self.assertEqual("OS::Neutron::Port", port.type)
            self.assertIsInstance(props['admin_state_up'], bool)
            self.assertIsInstance(props['security_groups'], list)
            assert(props['device_owner'].startswith("compute:"))

    def test_port_fixed_ip(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_ports()
        # Get the right port for the test
        port = next((p for p in extraction if
                    p.properties['mac_address'] == 'fa:16:3e:b0:9a:e2'))
        props = port.properties
        self.assertIsInstance(props['fixed_ips'], list)
        fixed_ip = props['fixed_ips'][0]
        self.assertEqual("192.168.203.2", fixed_ip['ip_address'])
        self.assertEqual({'get_resource': 'subnet_2'},
                         fixed_ip['subnet_id'])

    def test_servers_ports_assignations(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_servers()
        used_ports = []
        for n, server in enumerate(extraction):
            props = server.properties
            self.assertIsInstance(props['networks'], list)
            for network in props['networks']:
                port = network['port']['get_resource']
                assert(port.startswith("port_"))
                # Port has not been used by another server
                self.assertNotIn(port, used_ports)
                used_ports.append(port)

    def test_ports_order(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_ports()
        # Get the right port for the test
        port = next((p for p in extraction if
                    p.properties['mac_address'] == 'fa:16:3e:b0:9a:e2'))
        first_port = port.name
        for n, port in enumerate(extraction):
            if port.name == first_port:
                self.assertIsNone(port.depends_on)
                continue
            self.assertEqual("port_4", port.depends_on)

    def test_floating_association(self):
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_floating()
        associations = (res for res in extraction
                        if res.type == "OS::Neutron::FloatingIPAssociation")
        for association in associations:
            props = association.properties
            assert(props['floatingip_id']['get_resource'].
                   startswith('floatingip_'))
            assert(props['port_id']['get_resource'].
                   startswith('port_'))


class GenerationTests(BaseTestCase):

    def setUp(self):
        super(GenerationTests, self).setUp()
        self.mock_neutron.return_value = FakeNeutronManager()
        self.mock_nova.return_value = FakeNovaManager()
        self.mock_cinder.return_value = FakeCinderManager()

    def test_generation(self):

        generator = self.get_generator(False, False, False, True, True)

        expected_parameters = {
            "server_1_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_1"
            },
            "router_0_external_network": {
                "default": "network3",
                "type": "string",
                "description": "Router external network"
            },
            "server_2_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_2"
            },
            "server_2_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_2"
            },
            "volume_0_volume_type": {
                "default": "fast",
                "type": "string",
                "description": "Volume type for volume volume_0"
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "server_1_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_1"
            },
            "server_0_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_0"
            },
            "server_0_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_0"
            },
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "server_2": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_2_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_2_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_1"
                            }
                        }
                    ]
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group'
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group'
                        }
                    ]
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group'
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "server_0": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_0_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_0_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_4"
                            }
                        }
                    ]
                }
            },
            "volume_0": {
                "type": "OS::Cinder::Volume",
                "properties": {
                    "size": 1,
                    "description": "Description",
                    "volume_type": {
                        "get_param": "volume_0_volume_type"
                    },
                    "name": "vol1"
                }
            },
            "server_1": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_1_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_1_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_2"
                            }
                        }
                    ]
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "key_0": {
                "type": "OS::Nova::KeyPair",
                "properties": {
                    "public_key": "ssh-rsa XXXX",
                    "name": "testkey"
                }
            }
        }

        expected_data = {
            "subnet_2": {
                "status": "COMPLETE",
                "name": "subnet_2",
                "resource_data": {},
                "resource_id": "subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "server_2": {
                "status": "COMPLETE",
                "name": "server_2",
                "resource_data": {},
                "resource_id": "server3",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "subnet_0": {
                "status": "COMPLETE",
                "name": "subnet_0",
                "resource_data": {},
                "resource_id": "subnet1",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "router_0_gateway": {
                "status": "COMPLETE",
                "name": "router_0_gateway",
                "resource_data": {},
                "resource_id": "router1:network3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterGateway",
                "metadata": {}
            },
            "port_2": {
                "status": "COMPLETE",
                "name": "port_2",
                "resource_data": {},
                "resource_id": "port3",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_1": {
                "status": "COMPLETE",
                "name": "port_1",
                "resource_data": {},
                "resource_id": "port2",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "subnet_3": {
                "status": "COMPLETE",
                "name": "subnet_3",
                "resource_data": {},
                "resource_id": "subnet4",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "port_4": {
                "status": "COMPLETE",
                "name": "port_4",
                "resource_data": {},
                "resource_id": "port6",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "router_0_interface_0": {
                "status": "COMPLETE",
                "name": "router_0_interface_0",
                "resource_data": {},
                "resource_id": "router1:subnet_id=subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterInterface",
                "metadata": {}
            },
            "network_0": {
                "status": "COMPLETE",
                "name": "network_0",
                "resource_data": {},
                "resource_id": "network1",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "network_1": {
                "status": "COMPLETE",
                "name": "network_1",
                "resource_data": {},
                "resource_id": "network2",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "floatingip_0": {
                "status": "COMPLETE",
                "name": "floatingip_0",
                "resource_data": {},
                "resource_id": "floating1",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_1": {
                "status": "COMPLETE",
                "name": "floatingip_1",
                "resource_data": {},
                "resource_id": "floating2",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_2": {
                "status": "COMPLETE",
                "name": "floatingip_2",
                "resource_data": {},
                "resource_id": "floating3",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_3": {
                "status": "COMPLETE",
                "name": "floatingip_3",
                "resource_data": {},
                "resource_id": "floating4",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "server_0": {
                "status": "COMPLETE",
                "name": "server_0",
                "resource_data": {},
                "resource_id": "server1",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "volume_0": {
                "status": "COMPLETE",
                "name": "volume_0",
                "resource_data": {},
                "resource_id": 1234,
                "action": "CREATE",
                "type": "OS::Cinder::Volume",
                "metadata": {}
            },
            "server_1": {
                "status": "COMPLETE",
                "name": "server_1",
                "resource_data": {},
                "resource_id": "server2",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "router_0": {
                "status": "COMPLETE",
                "name": "router_0",
                "resource_data": {},
                "resource_id": "router1",
                "action": "CREATE",
                "type": "OS::Neutron::Router",
                "metadata": {}
            },
            "key_0": {
                "status": "COMPLETE",
                "name": "key_0",
                "resource_data": {},
                "resource_id": "key",
                "action": "CREATE",
                "type": "OS::Nova::KeyPair",
                "metadata": {}
            },
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers(self):

        generator = self.get_generator(True, False, False, True, True)

        expected_parameters = {
            "volume_0_volume_type": {
                "default": "fast",
                "type": "string",
                "description": "Volume type for volume volume_0"
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "router_0_external_network": {
                "default": "network3",
                "type": "string",
                "description": "Router external network"
            },
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group'
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group'
                        }
                    ]
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group'
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "volume_0": {
                "type": "OS::Cinder::Volume",
                "properties": {
                    "size": 1,
                    "description": "Description",
                    "volume_type": {
                        "get_param": "volume_0_volume_type"
                    },
                    "name": "vol1"
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "key_0": {
                "type": "OS::Nova::KeyPair",
                "properties": {
                    "public_key": "ssh-rsa XXXX",
                    "name": "testkey"
                }
            }
        }

        expected_data = {
            "subnet_2": {
                "status": "COMPLETE",
                "name": "subnet_2",
                "resource_data": {},
                "resource_id": "subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_3": {
                "status": "COMPLETE",
                "name": "subnet_3",
                "resource_data": {},
                "resource_id": "subnet4",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_0": {
                "status": "COMPLETE",
                "name": "subnet_0",
                "resource_data": {},
                "resource_id": "subnet1",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "router_0_gateway": {
                "status": "COMPLETE",
                "name": "router_0_gateway",
                "resource_data": {},
                "resource_id": "router1:network3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterGateway",
                "metadata": {}
            },
            "port_2": {
                "status": "COMPLETE",
                "name": "port_2",
                "resource_data": {},
                "resource_id": "port3",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_1": {
                "status": "COMPLETE",
                "name": "port_1",
                "resource_data": {},
                "resource_id": "port2",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_4": {
                "status": "COMPLETE",
                "name": "port_4",
                "resource_data": {},
                "resource_id": "port6",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "router_0_interface_0": {
                "status": "COMPLETE",
                "name": "router_0_interface_0",
                "resource_data": {},
                "resource_id": "router1:subnet_id=subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterInterface",
                "metadata": {}
            },
            "network_0": {
                "status": "COMPLETE",
                "name": "network_0",
                "resource_data": {},
                "resource_id": "network1",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "network_1": {
                "status": "COMPLETE",
                "name": "network_1",
                "resource_data": {},
                "resource_id": "network2",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "floatingip_0": {
                "status": "COMPLETE",
                "name": "floatingip_0",
                "resource_data": {},
                "resource_id": "floating1",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_1": {
                "status": "COMPLETE",
                "name": "floatingip_1",
                "resource_data": {},
                "resource_id": "floating2",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_2": {
                "status": "COMPLETE",
                "name": "floatingip_2",
                "resource_data": {},
                "resource_id": "floating3",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_3": {
                "status": "COMPLETE",
                "name": "floatingip_3",
                "resource_data": {},
                "resource_id": "floating4",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "volume_0": {
                "status": "COMPLETE",
                "name": "volume_0",
                "resource_data": {},
                "resource_id": 1234,
                "action": "CREATE",
                "type": "OS::Cinder::Volume",
                "metadata": {}
            },
            "router_0": {
                "status": "COMPLETE",
                "name": "router_0",
                "resource_data": {},
                "resource_id": "router1",
                "action": "CREATE",
                "type": "OS::Neutron::Router",
                "metadata": {}
            },
            "key_0": {
                "status": "COMPLETE",
                "name": "key_0",
                "resource_data": {},
                "resource_id": "key",
                "action": "CREATE",
                "type": "OS::Nova::KeyPair",
                "metadata": {}
            },
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_volumes(self):

        generator = self.get_generator(False, True, False, True, True)

        expected_parameters = {
            "server_1_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_1"
            },
            "router_0_external_network": {
                "default": "network3",
                "type": "string",
                "description": "Router external network"
            },
            "server_2_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_2"
            },
            "server_2_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_2"
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "server_1_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_1"
            },
            "server_0_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_0"
            },
            "server_0_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_0"
            },
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "server_2": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_2_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_2_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_1"
                            }
                        }
                    ]
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group',
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group',
                        }
                    ]
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group',
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "server_0": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_0_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_0_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_4"
                            }
                        }
                    ]
                }
            },
            "server_1": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_resource": "key_0"
                    },
                    "image": {
                        "get_param": "server_1_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_1_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_2"
                            }
                        }
                    ]
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "key_0": {
                "type": "OS::Nova::KeyPair",
                "properties": {
                    "public_key": "ssh-rsa XXXX",
                    "name": "testkey"
                }
            }
        }

        expected_data = {
            "subnet_2": {
                "status": "COMPLETE",
                "name": "subnet_2",
                "resource_data": {},
                "resource_id": "subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "server_2": {
                "status": "COMPLETE",
                "name": "server_2",
                "resource_data": {},
                "resource_id": "server3",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "subnet_0": {
                "status": "COMPLETE",
                "name": "subnet_0",
                "resource_data": {},
                "resource_id": "subnet1",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "router_0_gateway": {
                "status": "COMPLETE",
                "name": "router_0_gateway",
                "resource_data": {},
                "resource_id": "router1:network3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterGateway",
                "metadata": {}
            },
            "port_2": {
                "status": "COMPLETE",
                "name": "port_2",
                "resource_data": {},
                "resource_id": "port3",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_1": {
                "status": "COMPLETE",
                "name": "port_1",
                "resource_data": {},
                "resource_id": "port2",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "subnet_3": {
                "status": "COMPLETE",
                "name": "subnet_3",
                "resource_data": {},
                "resource_id": "subnet4",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "port_4": {
                "status": "COMPLETE",
                "name": "port_4",
                "resource_data": {},
                "resource_id": "port6",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "router_0_interface_0": {
                "status": "COMPLETE",
                "name": "router_0_interface_0",
                "resource_data": {},
                "resource_id": "router1:subnet_id=subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterInterface",
                "metadata": {}
            },
            "network_0": {
                "status": "COMPLETE",
                "name": "network_0",
                "resource_data": {},
                "resource_id": "network1",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "network_1": {
                "status": "COMPLETE",
                "name": "network_1",
                "resource_data": {},
                "resource_id": "network2",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "floatingip_0": {
                "status": "COMPLETE",
                "name": "floatingip_0",
                "resource_data": {},
                "resource_id": "floating1",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_1": {
                "status": "COMPLETE",
                "name": "floatingip_1",
                "resource_data": {},
                "resource_id": "floating2",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_2": {
                "status": "COMPLETE",
                "name": "floatingip_2",
                "resource_data": {},
                "resource_id": "floating3",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_3": {
                "status": "COMPLETE",
                "name": "floatingip_3",
                "resource_data": {},
                "resource_id": "floating4",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "server_0": {
                "status": "COMPLETE",
                "name": "server_0",
                "resource_data": {},
                "resource_id": "server1",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "server_1": {
                "status": "COMPLETE",
                "name": "server_1",
                "resource_data": {},
                "resource_id": "server2",
                "action": "CREATE",
                "type": "OS::Nova::Server",
                "metadata": {}
            },
            "router_0": {
                "status": "COMPLETE",
                "name": "router_0",
                "resource_data": {},
                "resource_id": "router1",
                "action": "CREATE",
                "type": "OS::Neutron::Router",
                "metadata": {}
            },
            "key_0": {
                "status": "COMPLETE",
                "name": "key_0",
                "resource_data": {},
                "resource_id": "key",
                "action": "CREATE",
                "type": "OS::Nova::KeyPair",
                "metadata": {}
            },
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_keypairs(self):

        generator = self.get_generator(False, False, True, True, True)

        expected_parameters = {
            "server_1_key": {
                "default": "testkey",
                "type": "string",
                "description": "Key for server server_1"
            },
            "server_0_key": {
                "default": "testkey",
                "type": "string",
                "description": "Key for server server_0"
            },
            "server_1_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_1"
            },
            "router_0_external_network": {
                "default": "network3",
                "type": "string",
                "description": "Router external network"
            },
            "server_2_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_2"
            },
            "server_2_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_2"
            },
            "volume_0_volume_type": {
                "default": "fast",
                "type": "string",
                "description": "Volume type for volume volume_0"
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "server_1_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_1"
            },
            "server_2_key": {
                "default": "testkey",
                "type": "string",
                "description": "Key for server server_2"
            },
            "server_0_flavor": {
                "default": "m1.small",
                "type": "string",
                "description": "Flavor to use for server server_0"
            },
            "server_0_image": {
                "default": "3333",
                "type": "string",
                "description": "Image to use to boot server server_0"
            },
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "server_2": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_param": "server_2_key"
                    },
                    "image": {
                        "get_param": "server_2_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_2_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_1"
                            }
                        }
                    ]
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group'
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group'
                        }
                    ]
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group'
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "server_0": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_param": "server_0_key"
                    },
                    "image": {
                        "get_param": "server_0_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_0_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_4"
                            }
                        }
                    ]
                }
            },
            "volume_0": {
                "type": "OS::Cinder::Volume",
                "properties": {
                    "size": 1,
                    "description": "Description",
                    "volume_type": {
                        "get_param": "volume_0_volume_type"
                    },
                    "name": "vol1"
                }
            },
            "server_1": {
                "type": "OS::Nova::Server",
                "properties": {
                    "name": "server1",
                    "key_name": {
                        "get_param": "server_1_key"
                    },
                    "image": {
                        "get_param": "server_1_image"
                    },
                    "diskConfig": "MANUAL",
                    "flavor": {
                        "get_param": "server_1_flavor"
                    },
                    "networks": [
                        {
                            "port": {
                                "get_resource": "port_2"
                            }
                        }
                    ]
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            }
        }

        expected_data = {
            'floatingip_0': {'action': 'CREATE',
                             'metadata': {},
                             'name': 'floatingip_0',
                             'resource_data': {},
                             'resource_id': u'floating1',
                             'status': 'COMPLETE',
                             'type': 'OS::Neutron::FloatingIP'},
            'floatingip_1': {'action': 'CREATE',
                             'metadata': {},
                             'name': 'floatingip_1',
                             'resource_data': {},
                             'resource_id': u'floating2',
                             'status': 'COMPLETE',
                             'type': 'OS::Neutron::FloatingIP'},
            'floatingip_2': {'action': 'CREATE',
                             'metadata': {},
                             'name': 'floatingip_2',
                             'resource_data': {},
                             'resource_id': u'floating3',
                             'status': 'COMPLETE',
                             'type': 'OS::Neutron::FloatingIP'},
            'floatingip_3': {'action': 'CREATE',
                             'metadata': {},
                             'name': 'floatingip_3',
                             'resource_data': {},
                             'resource_id': u'floating4',
                             'status': 'COMPLETE',
                             'type': 'OS::Neutron::FloatingIP'},
            'network_0': {'action': 'CREATE',
                          'metadata': {},
                          'name': 'network_0',
                          'resource_data': {},
                          'resource_id': u'network1',
                          'status': 'COMPLETE',
                          'type': 'OS::Neutron::Net'},
            'network_1': {'action': 'CREATE',
                          'metadata': {},
                          'name': 'network_1',
                          'resource_data': {},
                          'resource_id': u'network2',
                          'status': 'COMPLETE',
                          'type': 'OS::Neutron::Net'},
            'port_1': {'action': 'CREATE',
                       'metadata': {},
                       'name': 'port_1',
                       'resource_data': {},
                       'resource_id': u'port2',
                       'status': 'COMPLETE',
                       'type': 'OS::Neutron::Port'},
            'port_2': {'action': 'CREATE',
                       'metadata': {},
                       'name': 'port_2',
                       'resource_data': {},
                       'resource_id': u'port3',
                       'status': 'COMPLETE',
                       'type': 'OS::Neutron::Port'},
            'port_4': {'action': 'CREATE',
                       'metadata': {},
                       'name': 'port_4',
                       'resource_data': {},
                       'resource_id': u'port6',
                       'status': 'COMPLETE',
                       'type': 'OS::Neutron::Port'},
            'router_0': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'router_0',
                         'resource_data': {},
                         'resource_id': u'router1',
                         'status': 'COMPLETE',
                         'type': 'OS::Neutron::Router'},
            'router_0_gateway': {'action': 'CREATE',
                                 'metadata': {},
                                 'name': 'router_0_gateway',
                                 'resource_data': {},
                                 'resource_id': u'router1:network3',
                                 'status': 'COMPLETE',
                                 'type': 'OS::Neutron::RouterGateway'},
            'router_0_interface_0': {'action': 'CREATE',
                                     'metadata': {},
                                     'name':
                                     'router_0_interface_0',
                                     'resource_data': {},
                                     'resource_id':
                                     u'router1:subnet_id=subnet3',
                                     'status': 'COMPLETE',
                                     'type': 'OS::Neutron::RouterInterface'},
            'server_0': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'server_0',
                         'resource_data': {},
                         'resource_id': 'server1',
                         'status': 'COMPLETE',
                         'type': 'OS::Nova::Server'},
            'server_1': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'server_1',
                         'resource_data': {},
                         'resource_id': 'server2',
                         'status': 'COMPLETE',
                         'type': 'OS::Nova::Server'},
            'server_2': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'server_2',
                         'resource_data': {},
                         'resource_id': 'server3',
                         'status': 'COMPLETE',
                         'type': 'OS::Nova::Server'},
            'subnet_0': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'subnet_0',
                         'resource_data': {},
                         'resource_id': u'subnet1',
                         'status': 'COMPLETE',
                         'type': 'OS::Neutron::Subnet'},
            'subnet_2': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'subnet_2',
                         'resource_data': {},
                         'resource_id': u'subnet3',
                         'status': 'COMPLETE',
                         'type': 'OS::Neutron::Subnet'},
            'subnet_3': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'subnet_3',
                         'resource_data': {},
                         'resource_id': u'subnet4',
                         'status': 'COMPLETE',
                         'type': 'OS::Neutron::Subnet'},
            'volume_0': {'action': 'CREATE',
                         'metadata': {},
                         'name': 'volume_0',
                         'resource_data': {},
                         'resource_id': 1234,
                         'status': 'COMPLETE',
                         'type': 'OS::Cinder::Volume'},
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers_and_volumes(self):

        generator = self.get_generator(True, True, False, True, True)

        expected_parameters = {
            "router_0_external_network": {
                "default": "network3",
                "type": "string",
                "description": "Router external network"
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group'
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group'
                        }
                    ]
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group'
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "key_0": {
                "type": "OS::Nova::KeyPair",
                "properties": {
                    "public_key": "ssh-rsa XXXX",
                    "name": "testkey"
                }
            }
        }

        expected_data = {
            "subnet_2": {
                "status": "COMPLETE",
                "name": "subnet_2",
                "resource_data": {},
                "resource_id": "subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_3": {
                "status": "COMPLETE",
                "name": "subnet_3",
                "resource_data": {},
                "resource_id": "subnet4",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_0": {
                "status": "COMPLETE",
                "name": "subnet_0",
                "resource_data": {},
                "resource_id": "subnet1",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "router_0_gateway": {
                "status": "COMPLETE",
                "name": "router_0_gateway",
                "resource_data": {},
                "resource_id": "router1:network3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterGateway",
                "metadata": {}
            },
            "port_2": {
                "status": "COMPLETE",
                "name": "port_2",
                "resource_data": {},
                "resource_id": "port3",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_1": {
                "status": "COMPLETE",
                "name": "port_1",
                "resource_data": {},
                "resource_id": "port2",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_4": {
                "status": "COMPLETE",
                "name": "port_4",
                "resource_data": {},
                "resource_id": "port6",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "router_0_interface_0": {
                "status": "COMPLETE",
                "name": "router_0_interface_0",
                "resource_data": {},
                "resource_id": "router1:subnet_id=subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterInterface",
                "metadata": {}
            },
            "network_0": {
                "status": "COMPLETE",
                "name": "network_0",
                "resource_data": {},
                "resource_id": "network1",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "network_1": {
                "status": "COMPLETE",
                "name": "network_1",
                "resource_data": {},
                "resource_id": "network2",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "floatingip_0": {
                "status": "COMPLETE",
                "name": "floatingip_0",
                "resource_data": {},
                "resource_id": "floating1",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_1": {
                "status": "COMPLETE",
                "name": "floatingip_1",
                "resource_data": {},
                "resource_id": "floating2",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_2": {
                "status": "COMPLETE",
                "name": "floatingip_2",
                "resource_data": {},
                "resource_id": "floating3",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_3": {
                "status": "COMPLETE",
                "name": "floatingip_3",
                "resource_data": {},
                "resource_id": "floating4",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "router_0": {
                "status": "COMPLETE",
                "name": "router_0",
                "resource_data": {},
                "resource_id": "router1",
                "action": "CREATE",
                "type": "OS::Neutron::Router",
                "metadata": {}
            },
            "key_0": {
                "status": "COMPLETE",
                "name": "key_0",
                "resource_data": {},
                "resource_id": "key",
                "action": "CREATE",
                "type": "OS::Nova::KeyPair",
                "metadata": {}
            },
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)

    def test_generation_exclude_servers_volumes_keypairs(self):

        generator = self.get_generator(True, True, True, True, True)

        expected_parameters = {
            'router_0_external_network': {
                'default': u'network3',
                'description': 'Router external network',
                'type': 'string'
            },
            "external_network_for_floating_ip_2": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_3": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_0": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"
            },
            "external_network_for_floating_ip_1": {
                "default": "network3",
                "type": "string",
                "description": "Network to allocate floating IP from"},
            'port_1_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_2_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'},
            'port_4_default_security_group': {
                'default': u'secgorup1',
                'description': u'Default security group for port ',
                'type': 'string'}
        }

        expected_resources = {
            "floatingip_association_2": {
                "type": "OS::Neutron::FloatingIPAssociation",
                "properties": {
                    "floatingip_id": {
                        "get_resource": "floatingip_2"
                    },
                    "port_id": {
                        "get_resource": "port_2"
                    }
                }
            },
            "subnet_2": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.203.2",
                            "end": "192.168.203.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-1",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.203.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_3": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "allocation_pools": [
                        {
                            "start": "192.168.204.2",
                            "end": "192.168.204.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "int-a-2",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "192.168.204.0/24",
                    "dns_nameservers": []
                }
            },
            "subnet_0": {
                "type": "OS::Neutron::Subnet",
                "properties": {
                    "network_id": {
                        "get_resource": "network_1"
                    },
                    "allocation_pools": [
                        {
                            "start": "172.19.0.2",
                            "end": "172.19.0.254"
                        }
                    ],
                    "host_routes": [],
                    "name": "storage",
                    "enable_dhcp": True,
                    "ip_version": 4,
                    "cidr": "172.19.0.0/24",
                    "dns_nameservers": []
                }
            },
            "port_2": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e8:e4:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.4"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_2_default_security_group'
                        }
                    ]
                }
            },
            "port_1": {
                "depends_on": "port_4",
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:e4:44:7b",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.5"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_1_default_security_group'
                        }
                    ]
                }
            },
            "port_4": {
                "type": "OS::Neutron::Port",
                "properties": {
                    "admin_state_up": True,
                    "network_id": {
                        "get_resource": "network_0"
                    },
                    "device_owner": "compute:nova",
                    "mac_address": "fa:16:3e:b0:9a:e2",
                    "fixed_ips": [
                        {
                            "subnet_id": {
                                "get_resource": "subnet_2"
                            },
                            "ip_address": "192.168.203.2"
                        }
                    ],
                    "security_groups": [
                        {
                            'get_param': 'port_4_default_security_group'
                        }
                    ]
                }
            },
            "router_0_interface_0": {
                "type": "OS::Neutron::RouterInterface",
                "properties": {
                    "router_id": {
                        "get_resource": "router_0"
                    },
                    "subnet_id": {
                        "get_resource": "subnet_2"
                    }
                }
            },
            "network_0": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "internal",
                    "admin_state_up": True
                }
            },
            "network_1": {
                "type": "OS::Neutron::Net",
                "properties": {
                    "shared": False,
                    "name": "storage",
                    "admin_state_up": True
                }
            },
            "floatingip_0": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_0"
                    }
                }
            },
            "floatingip_1": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_1"
                    }
                }
            },
            "floatingip_2": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_2"
                    }
                }
            },
            "floatingip_3": {
                "type": "OS::Neutron::FloatingIP",
                "properties": {
                    "floating_network_id": {
                        "get_param": "external_network_for_floating_ip_3"
                    }
                }
            },
            "router_0": {
                "type": "OS::Neutron::Router",
                "properties": {
                    "name": "gw-internal-a",
                    "admin_state_up": True
                }
            },
            "router_0_gateway": {
                "type": "OS::Neutron::RouterGateway",
                "properties": {
                    "network_id": {
                        "get_param": "router_0_external_network"
                    },
                    "router_id": {
                        "get_resource": "router_0"
                    }
                }
            }
        }

        expected_data = {
            "subnet_2": {
                "status": "COMPLETE",
                "name": "subnet_2",
                "resource_data": {},
                "resource_id": "subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_3": {
                "status": "COMPLETE",
                "name": "subnet_3",
                "resource_data": {},
                "resource_id": "subnet4",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "subnet_0": {
                "status": "COMPLETE",
                "name": "subnet_0",
                "resource_data": {},
                "resource_id": "subnet1",
                "action": "CREATE",
                "type": "OS::Neutron::Subnet",
                "metadata": {}
            },
            "port_2": {
                "status": "COMPLETE",
                "name": "port_2",
                "resource_data": {},
                "resource_id": "port3",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_1": {
                "status": "COMPLETE",
                "name": "port_1",
                "resource_data": {},
                "resource_id": "port2",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "port_4": {
                "status": "COMPLETE",
                "name": "port_4",
                "resource_data": {},
                "resource_id": "port6",
                "action": "CREATE",
                "type": "OS::Neutron::Port",
                "metadata": {}
            },
            "router_0_interface_0": {
                "status": "COMPLETE",
                "name": "router_0_interface_0",
                "resource_data": {},
                "resource_id": "router1:subnet_id=subnet3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterInterface",
                "metadata": {}
            },
            "network_0": {
                "status": "COMPLETE",
                "name": "network_0",
                "resource_data": {},
                "resource_id": "network1",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "network_1": {
                "status": "COMPLETE",
                "name": "network_1",
                "resource_data": {},
                "resource_id": "network2",
                "action": "CREATE",
                "type": "OS::Neutron::Net",
                "metadata": {}
            },
            "router_0": {
                "status": "COMPLETE",
                "name": "router_0",
                "resource_data": {},
                "resource_id": "router1",
                "action": "CREATE",
                "type": "OS::Neutron::Router",
                "metadata": {}
            },
            "floatingip_0": {
                "status": "COMPLETE",
                "name": "floatingip_0",
                "resource_data": {},
                "resource_id": "floating1",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_1": {
                "status": "COMPLETE",
                "name": "floatingip_1",
                "resource_data": {},
                "resource_id": "floating2",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_2": {
                "status": "COMPLETE",
                "name": "floatingip_2",
                "resource_data": {},
                "resource_id": "floating3",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "floatingip_3": {
                "status": "COMPLETE",
                "name": "floatingip_3",
                "resource_data": {},
                "resource_id": "floating4",
                "action": "CREATE",
                "type": "OS::Neutron::FloatingIP",
                "metadata": {}
            },
            "router_0_gateway": {
                "status": "COMPLETE",
                "name": "router_0_gateway",
                "resource_data": {},
                "resource_id": "router1:network3",
                "action": "CREATE",
                "type": "OS::Neutron::RouterGateway",
                "metadata": {}
            },
            'floatingip_association_2': {
                'action': 'CREATE',
                'metadata': {},
                'name': 'floatingip_association_2',
                'resource_data': {},
                'resource_id': u'floating3:port3',
                'status': 'COMPLETE',
                'type': 'OS::Neutron::FloatingIPAssociation'},
        }

        generator.extract_data()
        self.assertEqual(generator.template['resources'], expected_resources)
        self.assertEqual(generator.template['parameters'], expected_parameters)
        self.assertEqual(generator.stack_data['resources'], expected_data)
