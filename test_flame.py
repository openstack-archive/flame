import datetime
import unittest

import flame


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
    name = 'server1'
    config_drive = None
    flavor = {'id': '2'}
    image = 'Fedora 20'
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
    public_key = 'ssh-rsa AAAAB3NzaC'


class FakeSecurityGroup(FakeBase):
    id = '1'

class FakeNeutronManager(object):
    groups = []
    routers = []
    ports = []
    subnets = []
    networks = []

    def subnet_list(self):
        return self.subnets

    def network_list(self):
        return self.networks

    def router_list(self):
        return self.routers

    def router_interfaces_list(self, router):
        return self.ports

    def secgroup_list(self):
        return self.groups

    def floatingip_list(self):
        return []


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

class NetworkTests(unittest.TestCase):

    def setUp(self):
        self.neutron_manager = FakeNeutronManager()
        flame.TemplateGenerator.neutron_manager = (
            lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        flame.TemplateGenerator.nova_manager = (
            lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        flame.TemplateGenerator.cinder_manager = (
            lambda x: self.cinder_manager)

    def test_router(self):
        router = {
            'name': 'myrouter',
            'id': '1234',
            'admin_state_up': 'true',
            'external_gateway_info': None
        }
        self.neutron_manager.routers = [router]
        generator = flame.TemplateGenerator([], [])
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
        generator = flame.TemplateGenerator([], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'router_0_external_network': {
                    'type': 'string',
                    'description': 'Router external network',
                    'constraints': [{'custom_constraint': 'neutron.network'}]}
            },
            'resources': {
                'router_0_gateway': {
                    'type': 'OS::Neutron::RouterGateway',
                    'properties': {
                        'router_id': {'get_resource': 'router_0'},
                        'network_id': {'get_param': 'router_0_external_network'}
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

    def test_router_with_port(self):
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
            'id': '1111'}

        self.neutron_manager.ports = [port]
        self.neutron_manager.subnets = [subnet]
        self.neutron_manager.routers = [router]

        generator = flame.TemplateGenerator([], [])
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


class VolumeTests(unittest.TestCase):

    def setUp(self):
        self.neutron_manager = FakeNeutronManager()
        flame.TemplateGenerator.neutron_manager = (
            lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        flame.TemplateGenerator.nova_manager = (
            lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        flame.TemplateGenerator.cinder_manager = (
            lambda x: self.cinder_manager)

    def test_basic(self):
        self.cinder_manager.volumes = [FakeVolume()]
        generator = flame.TemplateGenerator([], [])
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
        generator = flame.TemplateGenerator([], [])
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
        generator = flame.TemplateGenerator([], [])
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
        self.cinder_manager.volumes = [FakeVolume(bootable='true')]
        generator = flame.TemplateGenerator([], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_image': {
                    'description': 'Image to create volume volume_0 from',
                    'constraints': [{
                        'custom_constraint': 'glance.image'
                    }],
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
        generator = flame.TemplateGenerator([], [])
        expected = {
            'heat_template_version': datetime.date(2013, 5, 23),
            'description': 'Generated template',
            'parameters': {
                'volume_0_snapshot_id': {
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
        generator = flame.TemplateGenerator([], [])
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
        generator = flame.TemplateGenerator([], [])
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


class ServerTests(unittest.TestCase):

    def setUp(self):
        self.neutron_manager = FakeNeutronManager()
        flame.TemplateGenerator.neutron_manager = (
            lambda x: self.neutron_manager)
        self.nova_manager = FakeNovaManager()
        flame.TemplateGenerator.nova_manager = (
            lambda x: self.nova_manager)
        self.cinder_manager = FakeCinderManager()
        flame.TemplateGenerator.cinder_manager = (
            lambda x: self.cinder_manager)

    def test_basic(self):
        self.nova_manager.servers = [FakeServer()]
        generator = flame.TemplateGenerator([], [])
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
                    'constraints': [{
                        'custom_constraint': 'glance.image'
                    }],
                    'default': 'Fedora 20',
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
        generator = flame.TemplateGenerator([], [])
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
                    'constraints': [{
                        'custom_constraint': 'glance.image'
                    }],
                    'default': 'Fedora 20',
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
        server = FakeServer(id=777, image=None)
        setattr(server,
                'os-extended-volumes:volumes_attached',
                [{'id': 5678}])
        self.nova_manager.servers = [server]
        generator = flame.TemplateGenerator([], [])
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
        server = FakeServer(id=777)
        setattr(server,
                'os-extended-volumes:volumes_attached',
                [{'id': 5678}])
        self.nova_manager.servers = [server]
        generator = flame.TemplateGenerator([], [])
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
                    'constraints': [{
                        'custom_constraint': 'glance.image'
                    }],
                    'default': 'Fedora 20',
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
        generator = flame.TemplateGenerator([], [])
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
                    'constraints': [{
                        'custom_constraint': 'glance.image'
                    }],
                    'default': 'Fedora 20',
                    'type': 'string'
                }
            },
            'resources': {
                'group1_0': {
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
                        'security_groups': [{'get_resource': 'group1_0'}],
                        'flavor': {'get_param': 'server_0_flavor'},
                        'image': {'get_param': 'server_0_image'}
                    }
                }
            }
        }
        generator.extract_secgroups()
        generator.extract_servers()
        self.assertEqual(expected, generator.template)
