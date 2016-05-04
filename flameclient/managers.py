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

from cinderclient.v1 import client as cinder_client
from keystoneclient.v2_0 import client as keystone_client
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as nova_client


class KeystoneManager(object):
    """Manages Keystone queries."""
    _client = None

    def __init__(self, username, password, project, auth_url, insecure,
                 endpoint_type='publicURL', region_name=None, auth_token=None):
        self.username = username
        self.password = password
        self.project = project
        self.auth_url = auth_url
        self.insecure = insecure
        self.region_name = region_name
        self.endpoint_type = endpoint_type
        self.auth_token = auth_token

    def authenticate(self):
        self.client().authenticate()
        self.auth_token = self.client().auth_token

    def client(self):
        if not self._client:
            self._client = keystone_client.Client(
                username=self.username,
                password=self.password,
                tenant_name=self.project,
                auth_url=self.auth_url,
                region_name=self.region_name,
                insecure=self.insecure,
                endpoint_type=self.endpoint_type,
                token=self.auth_token)
        return self._client

    def set_client(self, client):
        self._client = client

    def get_token(self):
        return self.client().auth_token

    def get_endpoint(self, service_type, endpoint_type="publicURL"):
        catalog = self.client().service_catalog.get_endpoints()
        return catalog[service_type][0][endpoint_type]

    def get_project_id(self):
        return self.client().project_id


class NeutronManager(object):
    _client = None
    _project_id = None

    def __init__(self, keystone_mgr):
        self.keystone_mgr = keystone_mgr

    def client(self):
        if not self._client:
            # Create the client
            self._client = neutron_client.Client(
                auth_url=self.keystone_mgr.auth_url,
                insecure=self.keystone_mgr.insecure,
                endpoint_url=self.keystone_mgr.get_endpoint('network'),
                token=self.keystone_mgr.auth_token)
        if not self._project_id:
            self._project_id = self.keystone_mgr.get_project_id()
        return self._client

    def set_client(self, client):
        self._client = client

    def set_project_id(self, project_id):
        self._project_id = project_id

    def router_list(self):
        return filter(self._owned_resource,
                      self.client().list_routers()['routers'])

    def router_interfaces_list(self, router):
        return self._client.list_ports(device_id=router['id'])['ports']

    def port_list(self):
        return self.client().list_ports()['ports']

    def network_list(self):
        return filter(self._owned_resource,
                      self.client().list_networks()['networks'])

    def secgroup_list(self):
        return filter(self._owned_resource,
                      self.client().list_security_groups()['security_groups'])

    def floatingip_list(self):
        return filter(self._owned_resource,
                      self.client().list_floatingips()['floatingips'])

    def subnet_list(self):
        return filter(self._owned_resource,
                      self.client().list_subnets()['subnets'])

    def _owned_resource(self, res):
        # Only considering resources owned by project
        return res['tenant_id'] == self._project_id


class NovaManager(object):
    """Manage nova resources."""
    _client = None

    def __init__(self, keystone_mgr):
        self.keystone_mgr = keystone_mgr

    def client(self):
        if not self._client:
            self._client = nova_client.Client(
                '2',
                self.keystone_mgr.username,
                self.keystone_mgr.auth_token,
                self.keystone_mgr.project,
                self.keystone_mgr.auth_url,
                region_name=self.keystone_mgr.region_name,
                insecure=self.keystone_mgr.insecure,
                endpoint_type=self.keystone_mgr.endpoint_type,
                auth_token=self.keystone_mgr.auth_token
            )
        return self._client

    def set_client(self, client):
        self._client = client

    def server_list(self):
        return self.client().servers.list()

    def floating_ip_list(self):
        return self.client().floating_ips.list()

    def flavor_list(self):
        return self.client().flavors.list()

    def flavor_get(self, id):
        return self.client().flavors.get(id)

    def keypair_list(self):
        return self.client().keypairs.list()

    def keypair_show(self, keypair):
        return self.client().keypairs.get(keypair)

    def server_security_group_list(self, server):
        return self.client().servers.list_security_group(server)


class CinderManager(object):
    """Manage Cinder resources."""
    _client = None

    def __init__(self, keystone_mgr):
        self.keystone_mgr = keystone_mgr
        self.defined = True

    def client(self):
        if self.defined and not self._client:
            try:
                cinder_url = self.keystone_mgr.get_endpoint("volumev2")
            except KeyError:
                cinder_url = self.keystone_mgr.get_endpoint("volume")
            client = cinder_client.Client(
                self.keystone_mgr.username,
                self.keystone_mgr.auth_token,
                project_id=self.keystone_mgr.project,
                auth_url=cinder_url,
                http_log_debug=True,
                insecure=self.keystone_mgr.insecure
            )
            client.client.auth_token = self.keystone_mgr.auth_token
            client.client.management_url = cinder_url
            self._client = client
        return self._client

    def set_client(self, client):
        self._client = client

    def volume_list(self):
        volumes = []
        client = self.client()
        if client:
            for vol in client.volumes.list():
                volumes.append(client.volumes.get(vol.id))
        return volumes

    def snapshot_list(self):
        client = self.client()
        return client.volume_snapshots.list() if client else []
