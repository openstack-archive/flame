# -*- coding: utf-8 -*-

# This software is released under the MIT License.
#
# Copyright (c) 2018 Orange Cloud for Business / Cloudwatt
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


NAME = 'network.subnets'

FIXTURES = [{'allocation_pools': [{'end': '192.168.0.254', 'start': '192.168.0.2'}],
  'cidr': '192.168.0.0/24',
  'created_at': None,
  'description': None,
  'dns_nameservers': ['8.8.8.8'],
  'enable_dhcp': True,
  'gateway_ip': '192.168.0.1',
  'host_routes': [],
  'id': '541f0782-587f-428b-bd79-ca227a66973b',
  'ip_version': 4,
  'ipv6_address_mode': None,
  'ipv6_ra_mode': None,
  'name': 'tellurium_net_subnet',
  'network_id': 'f054013d-7052-4708-9c72-2948a329fac3',
  'revision_number': None,
  'segment_id': None,
  'service_types': None,
  'subnetpool_id': None,
  'tags': [],
  'tenant_id': '9824a7403a1b411d8d207d26218597ce',
  'updated_at': None,
  'use_default_subnetpool': None}]
