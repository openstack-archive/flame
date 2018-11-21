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

import six

from flameclient import resources as base_resources
from flameclient.utils import data_list_to_dict
from flameclient.utils import memoized_property


class Volume(base_resources.AdvancedHotResource):
    type = 'OS::Cinder::Volume'
    property_keys = ('size', 'name')

    def _add_source_volume(self):
        volume = self.data
        if volume.source_volid:
            if volume.source_volid in self.api.volumes:
                key = self.manager.get_resource_name(volume.source_volid)
                self.properties['source_volid'] = {'get_resource': key}
            else:
                key = "%s_source_volid" % self.name
                description = (
                    "Volume to create volume %s from" % self.name)
                self.add_parameter(key, description)
                self.properties['source_volid'] = {'get_param': key}

    def _add_image(self):
        volume = self.data
        if volume.bootable and not volume.snapshot_id:
            key = "%s_image" % self.name
            description = "Image to create volume %s from" % self.name
            constraints = [{'custom_constraint': "glance.image"}]
            default = volume.volume_image_metadata['image_id']
            self.add_parameter(key, description,
                               constraints=constraints,
                               default=default)
            self.properties['image'] = {'get_param': key}

    def _add_snapshot(self):
        volume = self.data
        if volume.snapshot_id:
            key = "%s_snapshot_id" % self.name
            self.properties['snapshot_id'] = {'get_param': key}
            description = (
                "Snapshot to create volume %s from" % self.name)
            self.add_parameter(key, description,
                               default=volume.snapshot_id)

    def _add_display_name(self):
        volume = self.data
        if hasattr(volume, 'display_name') and volume.display_name:
            self.properties['name'] = volume.display_name

    def _add_display_description(self):
        volume = self.data
        if (
            hasattr(volume, 'display_description') and
            volume.display_description
        ):
            self.properties['description'] = volume.display_description

    def _add_volume_type(self):
        volume = self.data
        if volume.volume_type and volume.volume_type != 'None':
            key = "%s_volume_type" % self.name
            description = (
                "Volume type for volume %s" % self.name)
            default = volume.volume_type
            self.add_parameter(key, description, default=default)
            self.properties['volume_type'] = {'get_param': key}

    def _add_metadata(self):
        volume = self.data
        if volume.metadata:
            self.properties['metadata'] = volume.metadata

    def __init__(self, manager, name, volume, properties=None):
        super(Volume, self).__init__(manager, name, volume, properties)
        self._add_source_volume()
        self._add_image()
        self._add_display_name()
        self._add_display_description()
        self._add_volume_type()
        self._add_metadata()


class VolumesManager(base_resources.ResourceManager):

    def add_resource_attached_volumes(self, resource):
        server = resource.data
        manager = resource.manager
        server_volumes = []
        att_key = 'os-extended-volumes:volumes_attached'
        for server_volume in server[att_key]:
            volume = self.api.volumes[server_volume['id']]
            volume_resource_name = self.get_resource_name(server_volume['id'])
            device = volume.attachments[0]['device']
            if not self.options.exclude_volumes:
                server_volumes.append(
                    {'volume_id': {'get_resource': volume_resource_name},
                     'device_name': device})
            else:
                volume_parameter_name = ("volume_%s_%d" %
                                         (server.name, volume.enum))
                description = ("Volume for %s %s, device %s" %
                               (manager.singular_name, server.name, device))
                server_volumes.append(
                    {'volume_id': {'get_param': volume_parameter_name},
                     'device_name': device})
                resource.add_parameter(volume_parameter_name, description,
                                       default=server_volume['id'])
        if server_volumes:
            # block_device_mapping_v2 is the new way of associating
            # block devices to an instance
            resource.properties['block_device_mapping_v2'] = server_volumes

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument('--exclude-volumes', action='store_true',
                            default=False,
                            help="Do not export volume resources.")
        return parser

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.volume.volumes)
        )

    def get_hot_resources(self):
        if not self.options.exclude_volumes:
            return [
                Volume(self, self.get_resource_name(volume.id), volume)
                for volume in six.itervalues(self.api.volumes)
            ]
        return []
