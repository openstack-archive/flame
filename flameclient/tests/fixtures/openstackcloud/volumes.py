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


NAME = 'volume.volumes'

FIXTURES = [{'attachments': [{'attached_at': '2018-11-09T13:39:41.000000',
                   'attachment_id': '7edd34f8-5c1b-4c46-afac-916db0e10726',
                   'device': '/dev/vda',
                   'host_name': None,
                   'id': '8ca10346-fe4c-4e68-9a18-98df875d1ecc',
                   'server_id': '99c42e21-5099-4903-9121-063925aad299',
                   'volume_id': '8ca10346-fe4c-4e68-9a18-98df875d1ecc'}],
  'availability_zone': 'prd1',
  'bootable': True,
  'consistencygroup_id': None,
  'created_at': '2018-11-09T13:34:08.000000',
  'description': '',
  'encrypted': False,
  'id': '8ca10346-fe4c-4e68-9a18-98df875d1ecc',
  'imageRef': None,
  'links': [{'href': 'https://volume.fr1.cloudwatt.com/v2/9824a7403a1b411d8d207d26218597ce/volumes/8ca10346-fe4c-4e68-9a18-98df875d1ecc',
             'rel': 'self'},
            {'href': 'https://volume.fr1.cloudwatt.com/9824a7403a1b411d8d207d26218597ce/volumes/8ca10346-fe4c-4e68-9a18-98df875d1ecc',
             'rel': 'bookmark'}],
  'metadata': {'attached_mode': 'rw', 'readonly': 'False'},
  'name': 'Ubuntu 14.04',
  'os-vol-host-attr:host': None,
  'os-vol-mig-status-attr:migstat': None,
  'os-vol-mig-status-attr:name_id': None,
  'os-vol-tenant-attr:tenant_id': '9824a7403a1b411d8d207d26218597ce',
  'os-volume-replication:driver_data': None,
  'os-volume-replication:extended_status': None,
  'replication_status': 'disabled',
  'size': 20,
  'snapshot_id': None,
  'source_volid': None,
  'status': 'in-use',
  'volume_image_metadata': {'checksum': '8ec802fe753dfe8e226645a2e0106bf7',
                            'container_format': 'bare',
                            'cw_cat': 'open_source',
                            'cw_logo': 'lin-ubuntu.png',
                            'cw_origin': 'Cloudwatt',
                            'cw_os': 'Ubuntu',
                            'disk_format': 'qcow2',
                            'hw_cpu_max_sockets': '1',
                            'hw_rng_model': 'virtio',
                            'image_id': '70a9c910-dd99-4065-bce9-11e89bc479fe',
                            'image_name': 'Ubuntu 14.04',
                            'min_disk': '20',
                            'min_ram': '0',
                            'size': '1009057792'},
  'volume_type': 'standard'},
 {'attachments': [],
  'availability_zone': 'prd1',
  'bootable': False,
  'consistencygroup_id': None,
  'created_at': '2018-11-09T04:54:29.000000',
  'description': None,
  'encrypted': False,
  'id': '34ce951a-f2d9-4bdd-904d-9f70269c680b',
  'imageRef': None,
  'links': [{'href': 'https://volume.fr1.cloudwatt.com/v2/9824a7403a1b411d8d207d26218597ce/volumes/34ce951a-f2d9-4bdd-904d-9f70269c680b',
             'rel': 'self'},
            {'href': 'https://volume.fr1.cloudwatt.com/9824a7403a1b411d8d207d26218597ce/volumes/34ce951a-f2d9-4bdd-904d-9f70269c680b',
             'rel': 'bookmark'}],
  'metadata': {},
  'name': 'tellurium_volume',
  'os-vol-host-attr:host': None,
  'os-vol-mig-status-attr:migstat': None,
  'os-vol-mig-status-attr:name_id': None,
  'os-vol-tenant-attr:tenant_id': '9824a7403a1b411d8d207d26218597ce',
  'os-volume-replication:driver_data': None,
  'os-volume-replication:extended_status': None,
  'replication_status': 'disabled',
  'size': 5,
  'snapshot_id': None,
  'source_volid': None,
  'status': 'available',
  'volume_image_metadata': {},
  'volume_type': 'standard'}]
