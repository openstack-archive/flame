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

from copy import deepcopy
import six

from flameclient import collections_abc
from flameclient import resources as base_resources
from flameclient.utils import clean_dict
from flameclient.utils import data_list_to_dict
from flameclient.utils import memoized_property


class SecurityGroup(base_resources.AdvancedHotResource):
    type = 'OS::Neutron::SecurityGroup'
    property_keys = ('description',)

    def __init__(self, manager, name, data, properties=None):
        super(SecurityGroup, self).__init__(
            manager, name, data, properties
        )
        if data['name'] == 'default':
            self.properties['name'] = '_default'
        else:
            self.properties['name'] = data['name']

        self.properties['rules'] = self._build_rules(
            data['security_group_rules']
        )

    def _build_rules(self, original_rules):
        final_rules = []
        for rule in original_rules:
            new_rule = deepcopy(rule)
            if new_rule['protocol'] == 'any':
                del new_rule['protocol']
                del new_rule['port_range_min']
                del new_rule['port_range_max']
            rg_id = new_rule['remote_group_id']
            if rg_id is not None:
                new_rule['remote_mode'] = "remote_group_id"
                resource_name = self.manager.get_resource_name(rg_id)
                if rg_id == new_rule['security_group_id']:
                    del new_rule['remote_group_id']
                else:
                    new_rule['remote_group_id'] = {
                        'get_resource': resource_name
                    }
            del new_rule['tenant_id']
            del new_rule['id']
            del new_rule['security_group_id']
            final_rule = clean_dict(new_rule, clean_list=False)
            final_rules.append(final_rule)
        return final_rules


class SecurityGroupsManager(base_resources.ResourceManager):

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument('--exclude-secgroups', action='store_true',
                            default=False,
                            help="Do not export the security group resources.")
        return parser

    @memoized_property
    def api_resources(self):
        return data_list_to_dict(
            self.generator_memoize(self.conn.network.security_groups)
        )

    def get_security_group(self, name_or_id):
        if isinstance(name_or_id, six.string_types):
            try:
                return self.api_resources[name_or_id]
            except KeyError:
                for sg in six.itervalues(self.api_resources):
                    if name_or_id == sg.name:
                        return sg
                raise ValueError(
                    "No security group with '%s' id or name found"
                )
        elif isinstance(name_or_id, collections_abc.Mapping):
            if 'id' in name_or_id:
                return self.get_security_group(name_or_id['id'])
            elif 'name' in name_or_id:
                return self.get_security_group(name_or_id['name'])
            else:
                raise KeyError(
                    "%s has no 'id' or 'name' key" % name_or_id
                )
        else:
            raise ValueError(
                "%s has to be a string or dict with 'id' or 'name' key."
            )

    def get_resource_secgroups(self, resource):
        return [
            self.get_security_group(sg)
            for sg in resource.data.security_groups
        ]

    def add_resource_secgrp_props_and_params(self, resource):
        """Add security group properties and parameters to a resource

        :param BaseHotResource resource: a BaseHotResource (or subclass)
                                         instance

        """
        if not self.options.exclude_secgroups:

            manager = resource.manager

            data = resource.data
            security_groups = []

            secgroup_default_parameter = None
            for secgr in self.get_resource_secgroups(resource):
                if secgr['name'] == 'default' and \
                        self.options.generate_adoption_data:
                    if not secgroup_default_parameter:
                        res_name = manager.get_resource_name(data['id'])
                        param_name = "%s_default_security_group" % res_name
                        description = (
                            "Default security group for %s %s" % (
                                manager.singular_name, resource['name']
                            )
                        )
                        default = secgr['id']
                        resource.add_parameter(
                            param_name, description, default=default
                        )
                        secgroup_default_parameter = {'get_param': param_name}
                    security_groups.append(secgroup_default_parameter)
                else:
                    resource_name = self.get_resource_name(secgr['id'])
                    security_groups.append({'get_resource': resource_name})

            if security_groups:
                resource.properties['security_groups'] = security_groups

    def get_hot_resources(self):
        resources = []
        if not self.options.exclude_secgroups:
            for secgroup in six.itervalues(self.api.security_groups):
                if secgroup['name'] == 'default' \
                        and self.options.generate_adoption_data:
                    continue
                resources.append(
                    SecurityGroup(
                        self, self.get_resource_name(secgroup.id), secgroup
                    )
                )
        return resources
