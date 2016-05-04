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

from flameclient.flame import TemplateGenerator  # noqa


class Client(object):
    def __init__(self, username, password, tenant_name, auth_url, auth_token,
                 **kwargs):
        self.template_generator = TemplateGenerator(username, password,
                                                    tenant_name, auth_url,
                                                    auth_token,
                                                    **kwargs)

    def generate(self, exclude_servers, exclude_volumes, exclude_keypairs,
                 generate_stack_data):
        self.template_generator.extract_vm_details(exclude_servers,
                                                   exclude_volumes,
                                                   exclude_keypairs,
                                                   generate_stack_data
                                                   )
        self.template_generator.extract_data()
        heat_template = self.template_generator.heat_template()
        if generate_stack_data:
            stack_data = self.template_generator.stack_data_template()
        else:
            stack_data = None
        return (heat_template, stack_data)
