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

from __future__ import print_function

import argparse
import collections
import logging
import threading

import concurrent.futures

import six

import yaml

from keystoneauth1.exceptions.auth_plugins import OptionError
from openstack.connection import Connection  # noqa
from shade.openstackcloud import OpenStackCloud  # noqa

from flameclient import resources as base_resources
from flameclient import session
from flameclient import utils

# We want logging to be configured with the configuration, so the following
# import is to import logging configuration, therefore we silence out pep8
# and pylint about this unused import:
from flameclient import logs  # noqa  # pylint: disable=W0611
LOG = logging.getLogger(__name__)


template_skeleton = '''
heat_template_version: 2013-05-23
description: Generated template
parameters:
resources:
'''

adoption_data_skeleton = '''
status: 'COMPLETE'
action: 'CREATE'
resources:
'''


def add_arguments(parser=None, managers=None):
    if parser is None:
        desc = "Heat template and data file generator"
        parser = argparse.ArgumentParser(description=desc)
        # argparse does not support `allow_abbrev=False` before python 3.5
        # e.g.: `argparse.ArgumentParser(description=desc, allow_abbrev=False)`
        # will not work in python 2 to 3.4 so we do not use it yet.
        # More info:
        # https://stackoverflow.com/questions/10750802/disable-abbreviation-in-argparse"  # noqa
    parser.add_argument('-v', '--debug', action='store_true',
                        default=False,
                        help="Activate debug verbose output (set log level to "
                             "debug).")
    parser.add_argument('-f', '--file', metavar='FILE_NAME',
                        help="Send results to FILE_NAME instead of standard "
                             "output.")
    parser.add_argument('--generate-adoption-data', action='store_true',
                        default=False,
                        help="Generate Heat adoption data.")
    parser.add_argument('--include-constraints', action='store_true',
                        default=False,
                        help="Export in template custom constraints.")
    parser.add_argument('--no-threads', action='store_true',
                        default=False,
                        help='Deactivate threads for api calls, (usefull for '
                             '(i)pdb debugging.')
    parser.add_argument('--prefetch', action='store_true',
                        default=False,
                        help='Prefetch all API calls (works only without '
                             '--no-threads).')
    if managers is not None:
        for manager in managers:
            manager.add_arguments(parser)
    return parser


class TemplateGenerator(object):
    """Generate a heat template from existing openstack resources.

    :param openstack.connection.Connection connection:
        An `openstack.connection.Connection` instance (`openstacksdk`).
        Since `shade.openstackcloud.OpenStackCloud` (`shade`) is a subclass it,
        you can also use shade instances.
        If you do not pass this parameter, environment variables and CLI args
        will be parsed.

    :param list managers:
        A list of `flameclient.resources.ResourceManager` instances or
        subclasses
        We will get them automatically if not set.
        If we receive subclasses, we instantiate them.

    :param argparse.Namespace options:
        argparse options. It allows you to pass the ordinary command line
        arguments.
    :param dict options:
        You can also pass an ordinary dictionary and it will
        be converted to an `argparse.Namespace` instance.
        Passing an ordinary dictionary is useful when importing
        TemplateGenerator from other modules or projects than flame.

    args and kwargs are extra parameters which each
    `flameclient.resources.ResourceManager` will have access to.

    `self.cache_dict` is a dict to store data on the template generator.
    Usefull to share cache data between several objects on a single
    TemplateGenerator instance.
    """

    _heat_routers = None
    _heat_router_interfaces = None
    _locks = None
    _memoize_dict = None
    _routers = None
    adoption_data = None
    api = base_resources.DirectManagerApiResourceAccess()
    args = ()
    cloud = None
    connection = None
    hot_resources = None
    managers = None
    options = None
    parser = None
    template = None

    def __init__(
            self, connection=None, options=None, managers=None, *args, **kwargs
    ):

        self.args = args
        self.kwargs = kwargs or {}
        self._memoize_dict = {}
        self._locks = collections.defaultdict(threading.Lock)

        if managers is None:
            self.managers = base_resources.ManagerList(
                manager_class(self)
                for manager_class in base_resources.get_manager_classes()
            )
            self.parser = add_arguments(managers=self.managers)
        else:
            self.parser = add_arguments()
            self.managers = base_resources.ManagerList()
            for manager in managers:
                self.add_manager(manager)
                self.add_manager_args(manager)

        # We want to have all option defaults without parsing CLI
        # argument yet, so we parse an empty list.
        # We parse CLI args only if connection is None, when we set a
        # connection.
        self.options = self.parser.parse_args([])
        if options:
            self.update_options(options)

        self.set_connection(connection)

        self._setup_templates()

    def update_options(self, options):
        all_options = vars(self.options)
        if isinstance(options, argparse.Namespace):
            options = vars(options)
        if isinstance(options, dict):
            all_options.update(options)
            self.options = utils.dict_to_options(all_options)
        else:
            raise TypeError(
                "'options' has to be dict or argparse.Namespace but "
                "received %s" % type(options)
            )
        if self.options.debug:
            LOG.setLevel(logging.DEBUG)

    def add_manager(self, manager):
        """Add a manager class or instance.

        :param flameclient.resources.ResourceManager manager:
            a `flameclient.resources.ResourceManager` class or instance

        You may want (or not) to add the manager's arguments afterwards with
        the add_manager_args method.
        """
        if isinstance(manager, base_resources.ResourceManager):
            if manager.generator is not self:
                LOG.debug(
                    "Setting `%s.generator = %s`", manager, self
                )
                manager.generator = self
            self.managers.append(manager)
        elif issubclass(manager, base_resources.ResourceManager):
            self.managers.append(manager(self))
        else:
            raise TypeError(
                "managers need to be instances or subclasses of "
                "%s but received %s (%s instance)." % (
                    base_resources.ResourceManager, manager, type(manager)
                )
            )

    def add_manager_args(self, manager):
        """Add a manager's arguments to the argparse.ArgumentParser.

        :param flameclient.resources.ResourceManager manager:
            a `flameclient.resources.ResourceManager` class or instance


        You may want (or not) to update the options (parsed args) list
        afterwards with the update_options method.
        """
        manager.add_arguments(self.parser)

    def set_connection(self, connection):
        """Set the connection

        :param openstack.connection.Connection connection:
            An `openstack.connection.Connection` instance (`openstacksdk`).
            Since `shade.openstackcloud.OpenStackCloud` (`shade`) is a subclass
            you can also use shade instances.
            If you do not pass this parameter, environment variables and CLI
            args will be parsed to set a connection.
        """
        if not connection:
            known_args, unknown_args = session.get_openstack_cli_arguments(
                self.parser, renamed_args=True
            )

            if unknown_args:
                msg = 'unrecognized arguments: %s'
                self.parser.error(msg % ' '.join(unknown_args))

            self.update_options(known_args)
            LOG.debug("Setting Openstack connection from envvars and args")
            try:
                connection = session.get_shade(
                    parser_or_options=self.options, load_envvars=True,
                    load_yaml_config=True
                )
            except OptionError as e:
                self.parser.error(str(e))

        if isinstance(connection, Connection):
            self.connection = connection
        if isinstance(connection, OpenStackCloud):
            # OpenStackCloud is a subclass of Connection so when we have an
            # OpenStackCloud instance, both self.connection and self.cloud will
            # be available. We want this because we want to be able to call
            # self.connection methods indifferently even if we have an
            # OpenStackCloud instance.
            self.cloud = connection
        if not (self.cloud or self.connection):
            raise TypeError(
                "`conn` has to be either an "
                "openstack.connection.Connection or "
                "shade.openstackcloud.OpenStackCloud instance"
            )

    @classmethod
    def get_new_template(cls):
        template = yaml.load(template_skeleton)
        template['resources'] = {}
        template['parameters'] = {}
        return template

    @classmethod
    def get_new_adoption_data(cls):
        adoption_data = yaml.load(adoption_data_skeleton)
        adoption_data['resources'] = {}
        return adoption_data

    def _setup_templates(self):
        self.template = self.get_new_template()
        self.adoption_data = self.get_new_adoption_data()

    @property
    def conn(self):
        return self.connection

    @property
    def api_resource_getters(self):
        return {
            manager.__module__: manager.get_api_resources
            for manager in self.managers
        }

    @property
    def hot_resource_getters(self):
        return {
            manager.__module__: manager.get_hot_resources
            for manager in self.managers
        }

    def prefetch_api_resources(self):
        """Fetch all api resources in parallel calls"""
        if self.options.prefetch and not self.options.no_threads:
            futures = {}
            with concurrent.futures.ThreadPoolExecutor(10) as tp:
                for name, getter in six.iteritems(self.api_resource_getters):
                    futures[tp.submit(getter)] = name
                for res in concurrent.futures.as_completed(futures):
                    name = futures[res]
                    LOG.debug("Getting api resources from %s", name)

    def get_hot_resources(self):
        resources = self.hot_resources or []

        self.prefetch_api_resources()

        if self.options.no_threads:
            for name, getter in six.iteritems(self.hot_resource_getters):
                LOG.debug("Getting resources from %s", name)
                resources.extend(getter())
        else:
            futures = {}
            with concurrent.futures.ThreadPoolExecutor(10) as tp:
                for name, getter in six.iteritems(self.hot_resource_getters):
                    futures[tp.submit(getter)] = name
                for res in concurrent.futures.as_completed(futures):
                    name = futures[res]
                    LOG.debug("Getting resources from %s", name)
                    resources.extend(res.result())

        self.hot_resources = resources
        return resources

    def get_managers_by_post_priority(self):
        # Copy the list of managers:
        managers = [manager for manager in self.managers]
        # And sort
        managers.sort(key=lambda manager: manager.post_priority)
        return managers

    def call_managers_post_process(self):
        for manager in self.get_managers_by_post_priority():
            manager.post_process()

    def call_managers_post_process_hot_resources(self):
        for manager in self.get_managers_by_post_priority():
            self.hot_resources = manager.post_process_hot_resources(
                self.hot_resources
            )

    def call_managers_post_process_heat_template(self):
        for manager in self.get_managers_by_post_priority():
            self.template = manager.post_process_heat_template(self.template)

    def call_managers_post_process_adoption_data(self):
        for manager in self.get_managers_by_post_priority():
            self.adoption_data = manager.post_process_adoption_data(
                self.adoption_data
            )

    def extract_data(self):
        for resource in self.get_hot_resources():
            self.template['resources'].update(resource.template_resource)
            self.template['parameters'].update(resource.template_parameter)
            if self.options.generate_adoption_data:
                self.adoption_data['resources'].update(resource.stack_resource)

        self.call_managers_post_process()
        self.call_managers_post_process_hot_resources()
        self.call_managers_post_process_heat_template()
        self.call_managers_post_process_adoption_data()

    @staticmethod
    def format_template(data):
        return yaml.safe_dump(data, default_flow_style=False)

    def heat_template_and_data(self):
        if self.options.generate_adoption_data:
            out = self.adoption_data.copy()
            out['template'] = self.template
            out['environment'] = {"parameter_defaults": {},
                                  "parameters": {}}

            return self.format_template(out)
        else:
            return self.format_template(self.template)

    def output_template_and_data(self):
        output_data = self.heat_template_and_data()
        if self.options.file:
            with open(self.options.file, 'w') as fp:
                fp.write(output_data)
        else:
            print(output_data)

    def generator_memoize(self, method, *args, **kwargs):
        """Memoize method calls on this instance

        Utility to memoize API calls on a TemplateGenerator instance
        """
        try:
            key = utils.hash_func_call(method, *args, **kwargs)
            with self._locks[key]:
                if key not in self._memoize_dict:
                    result = method(*args, **kwargs)
                    if isinstance(result, collections.Iterator):
                        # We can not memoize an iterator, so we store it in a
                        # tuple. The choice for tuples is because tuples take
                        # less memory than lists:
                        # https://stackoverflow.com/questions/46664007/why-do-tuples-take-less-space-in-memory-than-lists  # noqa
                        result = tuple(result)
                    self._memoize_dict[key] = result
                return self._memoize_dict[key]
        except TypeError:
            LOG.error(
                "Could not hash %s call with args %s and kwargs %s",
                method.__name__, args, kwargs, exc_info=True
            )
            return method(*args, **kwargs)

    def get_resource_name(self, manager_name, resource_id):
        for manager in self.managers:
            if manager.name == manager_name:
                return manager.get_resource_name(resource_id)
