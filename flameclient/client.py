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
