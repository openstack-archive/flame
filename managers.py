from cinderclient.v1 import client as cinder_client
from keystoneclient.v2_0 import client as keystone_client
from neutronclient.v2_0 import client as neutron_client
from novaclient.v1_1 import client as nova_client


class KeystoneManager(object):
    """Manages Keystone queries."""

    def __init__(self, username, password, project, auth_url, insecure):
        self.client = keystone_client.Client(
            username=username, password=password,
            tenant_name=project, auth_url=auth_url, insecure=insecure)

    def get_token(self):
        return self.client.auth_token

    def get_endpoint(self, service_type, endpoint_type="publicURL"):
        catalog = self.client.service_catalog.get_endpoints()
        return catalog[service_type][0][endpoint_type]

    def get_project_id(self):
        return self.client.tenant_id


class NeutronManager(object):
    def __init__(self, username, password, project, auth_url, insecure):
        self.client = neutron_client.Client(
            username=username, password=password,
            tenant_name=project, auth_url=auth_url,
            insecure=insecure)
        keystone_mgr = KeystoneManager(username, password, project,
                                       auth_url, insecure)
        self.project_id = keystone_mgr.get_project_id()

    def router_list(self):
        return filter(self._owned_resource,
                      self.client.list_routers()['routers'])

    def router_interfaces_list(self, router):
        return self.client.list_ports(device_id=router['id'])['ports']

    def port_list(self):
        return self.client.list_ports()['ports']

    def network_list(self):
        return filter(self._owned_resource,
                      self.client.list_networks()['networks'])

    def secgroup_list(self):
        return filter(self._owned_resource,
                      self.client.list_security_groups()['security_groups'])

    def floatingip_list(self):
        return filter(self._owned_resource,
                      self.client.list_floatingips()['floatingips'])

    def subnet_list(self):
        return filter(self._owned_resource,
                      self.client.list_subnets()['subnets'])

    def _owned_resource(self, res):
        # Only considering resources owned by project
        return res['tenant_id'] == self.project_id


class NovaManager(object):
    """Manage nova resources."""

    def __init__(self, username, password, project, auth_url, insecure):
        self.client = nova_client.Client(username, password, project,
                                         auth_url, insecure=insecure)

    def server_list(self):
        return self.client.servers.list()

    def floating_ip_list(self):
        return self.client.floating_ips.list()

    def flavor_list(self):
        return self.client.flavors.list()

    def flavor_get(self, id):
        return self.client.flavors.get(id)

    def keypair_list(self):
        return self.client.keypairs.list()

    def keypair_show(self, keypair):
        return self.client.keypairs.get(keypair)

    def server_security_group_list(self, server):
        return self.client.servers.list_security_group(server)


class CinderManager(object):
    """Manage Cinder resources."""

    def __init__(self, username, password, project, auth_url, insecure):
        self.client = cinder_client.Client(username,
                                           password,
                                           project,
                                           auth_url,
                                           insecure=insecure)

    def volume_list(self):
        volumes = []
        for vol in self.client.volumes.list():
            volumes.append(self.client.volumes.get(vol.id))
        return volumes

    def snapshot_list(self):
        return self.client.volume_snapshots.list()
