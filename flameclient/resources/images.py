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

from flameclient import resources as base_resources
from flameclient.utils import data_list_to_dict
from flameclient.utils import memoized_property


class ImagesManager(base_resources.ResourceManager):
    """Used only to provide api resources. Heat does not create images."""

    @staticmethod
    def add_resource_image(resource):
        data = resource.data
        manager = resource.manager
        if data.image:
            image_parameter_name = "%s_image" % resource.name
            description = (
                "Image to use for %s %s" % (
                    manager.singular_name, resource.name
                )
            )
            constraints = [{'custom_constraint': "glance.image"}]
            resource.add_parameter(image_parameter_name, description,
                                   default=data.image['id'],
                                   constraints=constraints)
            resource.properties['image'] = {'get_param': image_parameter_name}

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            # self.conn.compute.images gives detailed images
            self.generator_memoize(self.conn.image.images)
        )

    def get_hot_resources(self):
        return []
