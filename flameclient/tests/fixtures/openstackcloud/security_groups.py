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


NAME = 'network.security_groups'

FIXTURES = [{'created_at': None,
  'description': None,
  'id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
  'name': 'default',
  'revision_number': None,
  'security_group_rules': [{'direction': 'ingress',
                            'ethertype': 'IPv4',
                            'id': 'ec72eaca-22e2-47b6-b1a5-2fe6f8129e47',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'remote_ip_prefix': None,
                            'security_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'},
                           {'direction': 'ingress',
                            'ethertype': 'IPv6',
                            'id': 'd5720f56-e7ce-4c7f-982d-a70d76c37b11',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'remote_ip_prefix': None,
                            'security_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'},
                           {'direction': 'egress',
                            'ethertype': 'IPv4',
                            'id': 'd05bc784-b34c-4e0c-a2ea-7b10992caa1e',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': '0.0.0.0/0',
                            'security_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'},
                           {'direction': 'egress',
                            'ethertype': 'IPv6',
                            'id': 'a6abbc8e-92c2-42f6-9ac9-a04544588739',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': '::/0',
                            'security_group_id': '9ffd2654-7ca6-48ae-852d-6503d5ce4a60',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'}],
  'tags': [],
  'tenant_id': '9824a7403a1b411d8d207d26218597ce',
  'updated_at': None},
 {'created_at': None,
  'description': '',
  'id': '156799a3-565e-48b3-938c-f95f09093c66',
  'name': 'http',
  'revision_number': None,
  'security_group_rules': [{'direction': 'egress',
                            'ethertype': 'IPv4',
                            'id': '80508f7d-b893-4bcb-bddc-51a946634492',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': '0.0.0.0/0',
                            'security_group_id': '156799a3-565e-48b3-938c-f95f09093c66',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'},
                           {'direction': 'egress',
                            'ethertype': 'IPv6',
                            'id': 'eab50b80-bc3c-484c-a3c8-fd6cf5ee9c50',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': None,
                            'security_group_id': '156799a3-565e-48b3-938c-f95f09093c66',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'},
                           {'direction': 'ingress',
                            'ethertype': 'IPv4',
                            'id': 'a6ed0dc8-ee29-462e-84a0-961675e08c4a',
                            'port_range_max': 80,
                            'port_range_min': 80,
                            'protocol': 'tcp',
                            'remote_group_id': None,
                            'remote_ip_prefix': '0.0.0.0/0',
                            'security_group_id': '156799a3-565e-48b3-938c-f95f09093c66',
                            'tenant_id': '9824a7403a1b411d8d207d26218597ce'}],
  'tags': [],
  'tenant_id': '9824a7403a1b411d8d207d26218597ce',
  'updated_at': None}]
