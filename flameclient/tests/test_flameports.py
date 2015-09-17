# -*- coding: utf-8 -*-

# Copyright (c) 2014 Cloudwatt

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

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
        self.servergroups = []
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

    def servergroup_list(self):
        return self.servergroups


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
        reference = [{'ip_address': '192.168.203.2',
                      'subnet_id': {'get_resource': 'subnet_2'}}]
        generator = self.get_generator(False, False, False, True, True)
        extraction = generator._extract_ports()
        # Get the right port for the test
        port = next((p for p in extraction if
                    p.properties['mac_address'] == 'fa:16:3e:b0:9a:e2'))
        props = port.properties
        self.assertIsInstance(props['fixed_ips'], list)
        fixed_ips = props['fixed_ips']
        for ref in reference:
            self.assertIn(ref, fixed_ips)

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
    resource_ref = set(['floatingip_association_2',
                        'subnet_2', 'subnet_3', 'subnet_0',
                        'port_2', 'port_1', 'port_4',
                        'server_2', 'server_1', 'server_0',
                        'router_0',
                        'router_0_interface_0',
                        'router_0_gateway',
                        'key_0',
                        'network_0', 'network_1',
                        'floatingip_0', 'floatingip_1',
                        'floatingip_2', 'floatingip_3',
                        'volume_0'])

    params_ref = set(['volume_0_volume_type',
                      'external_network_for_floating_ip_3',
                      'external_network_for_floating_ip_2',
                      'external_network_for_floating_ip_1',
                      'external_network_for_floating_ip_0',
                      'port_4_default_security_group',
                      'port_1_default_security_group',
                      'port_2_default_security_group',
                      'router_0_external_network',
                      'server_1_image',
                      'server_1_flavor',
                      'server_1_key',
                      'server_2_image',
                      'server_2_flavor',
                      'server_2_key',
                      'server_0_image',
                      'server_0_flavor',
                      'server_0_key'])

    data_ref = set(['floatingip_0', 'floatingip_1', 'floatingip_2',
                    'floatingip_3',
                    'floatingip_association_2',
                    'key_0',
                    'network_0', 'network_1',
                    'port_1', 'port_2', 'port_4',
                    'router_0',
                    'router_0_gateway',
                    'router_0_interface_0',
                    'server_0', 'server_1', 'server_2',
                    'subnet_0', 'subnet_2', 'subnet_3',
                    'volume_0'])

    def filter_set(self, filtered_set, exclude):
        excluded_set = set()
        for exc in exclude:
            excluded_set.update(
                set([e for e in filtered_set if re.search(exc, e)])
            )
        return filtered_set.difference(excluded_set)

    def setUp(self):
        super(GenerationTests, self).setUp()
        self.mock_neutron.return_value = FakeNeutronManager()
        self.mock_nova.return_value = FakeNovaManager()
        self.mock_cinder.return_value = FakeCinderManager()

    def test_generation(self):

        exclusion_table = [
            {'call_params': (False, False, False, True, True),
             'resource_filter': [],
             'params_filter': ['^server_\d+_key$'],
             'data_filter': []},
            # No server
            {'call_params': (True, False, False, True, True),
             'resource_filter': ['^server'],
             'params_filter': ['^server'],
             'data_filter': ['^server']},
            # No volumes
            {'call_params': (False, True, False, True, True),
             'resource_filter': ['^volume'],
             'params_filter': [r'^volume_\d+_volume_type$',
                               '^server_\d+_key$'],
             'data_filter': ['^volume']},
            # No keys
            {'call_params': (False, False, True, True, True),
             'resource_filter': ['^key_\d+$'],
             'params_filter': [],
             'data_filter': ['^key', 'server_\d+_key']},
            # No ports
            {'call_params': (False, False, False, True, False),
             'resource_filter': ['^port_\d+$'],
             'params_filter': ['^port_\d+_default_security_group$',
                               'server_\d+_key$'],
             'data_filter': ['^port_\d+', '^floatingip_association_\d+$']},
        ]

        for exclusion in exclusion_table:
            generator = self.get_generator(*exclusion['call_params'])
            resource_ref = self.filter_set(self.resource_ref,
                                           exclusion['resource_filter'])
            params_ref = self.filter_set(self.params_ref,
                                         exclusion['params_filter'])
            data_ref = self.filter_set(self.data_ref,
                                       exclusion['data_filter'])

            generator.extract_data()
            # All the resources, params and datas are present
            self.assertEqual(resource_ref,
                             set(generator.template['resources'].keys()),
                             "Called with : %r" % (exclusion['call_params'],))
            self.assertEqual(params_ref,
                             set(generator.template['parameters'].keys()),
                             "Called with : %r" % (exclusion['call_params'],))
            self.assertEqual(data_ref,
                             set(generator.stack_data['resources'].keys()),
                             "Called with : %r" % (exclusion['call_params'],))

    def test_floating_association_data(self):
        generator = self.get_generator(False, False, False, True, True)
        generator.extract_data()
        # Look for floating ips
        assoc_name = 'floatingip_association_2'
        association_data = generator.stack_data['resources'][assoc_name]
        reference = {'action': 'CREATE',
                     'metadata': {},
                     'name': 'floatingip_association_2',
                     'resource_data': {},
                     'resource_id': u'floating3:port3',
                     'status': 'COMPLETE',
                     'type': 'OS::Neutron::FloatingIPAssociation'}
        self.assertEqual(reference, association_data)

    def test_port_data(self):
        generator = self.get_generator(False, False, False, True, True)
        generator.extract_data()
        # Look for floating ips
        assoc_name = 'port_2'
        association_data = generator.stack_data['resources'][assoc_name]
        reference = {'action': 'CREATE',
                     'metadata': {},
                     'name': 'port_2',
                     'resource_data': {},
                     'resource_id': u'port3',
                     'status': 'COMPLETE',
                     'type': 'OS::Neutron::Port'}
        self.assertEqual(reference, association_data)
