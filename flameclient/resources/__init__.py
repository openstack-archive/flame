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

import abc
import logging

import six
from six.moves import UserDict

from flameclient.utils import camel_to_snake
from flameclient.utils import ClassProperty
from flameclient.utils import clean_dict
from flameclient.utils import load_resource_entry_points
from flameclient.utils import load_resource_modules
from flameclient.utils import munchify


LOG = logging.getLogger(__name__)


class BaseHotResource(object):
    """Describes a heat resource from parameters

    :param ResourceManager manager:
        A ResourceManager instance.
        This instance is necessary to have access to the manager's
        openstack.connection.Connection instance

    :param string type: The name of the openstack resource type.
                        e.g.: "OS::Nova::Server" etc...

    :param string id: The openstack resource id.

    :param dict properties: The openstack resource properties.

    """

    id = None
    manager = None
    parameters = None
    properties = None
    type = None

    def __init__(self, manager, name, type=None, id=None, properties=None):  # noqa pylint: disable=W0622
        if not isinstance(manager, ResourceManager):
            raise TypeError(
                "manager needs to be a flameclient.resources.ResourceManager "
                "instance. Received '%s' (%s) instead" % (
                    manager, self.__type(manager)
                )
            )
        self.manager = manager
        self.name = name
        if type:
            self.type = type
        self.id = id
        self.status = 'COMPLETE'
        self.properties = properties or {}
        self.parameters = {}

    @staticmethod
    def __type(*args, **kwargs):
        """Needed to call the builtin type function when overriden"""
        return type(*args, **kwargs)

    @property
    def connection(self):
        return self.manager.connection

    @property
    def conn(self):
        return self.connection

    @property
    def cloud(self):
        return self.manager.cloud

    @property
    def generator(self):
        return self.manager.generator

    @property
    def managers(self):
        return self.generator.managers

    @property
    def api(self):
        return self.generator.api

    @property
    def options(self):
        return self.generator.options

    @property
    def kwargs(self):
        return self.manager.kwargs

    def add_parameter(
            self, name, description, parameter_type='string', constraints=None,
            default=None
    ):
        data = {
            'type': parameter_type,
            'description': description,
        }

        if constraints and self.options.include_constraints:
            data['constraints'] = constraints
        if default:
            data['default'] = default

        self.parameters[name] = data

    @property
    def clean_properties(self):
        return clean_dict(self.properties)

    @property
    def template_resource(self):
        return {
            self.name: {
                'type': self.type,
                'properties': self.clean_properties
            }
        }

    @property
    def clean_parameters(self):
        return clean_dict(self.parameters)

    @property
    def template_parameter(self):
        return self.parameters

    @property
    def stack_resource(self):
        if self.id is None:
            return {}
        return {
            self.name: {
                'status': self.status,
                'name': self.name,
                'resource_data': {},
                'resource_id': self.id,
                'action': 'CREATE',
                'type': self.type,
                'metadata': {}
            }
        }

    def generator_memoize(self, method, *args, **kwargs):
        return self.manager.generator_memoize(method, *args, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class TypedHotResource(BaseHotResource):
    """Describes a heat resource from parameters with predefined type

    :param ResourceManager manager:
        A ResourceManager instance.
        This instance is necessary to have access to the manager's
        openstack.connection.Connection instance

    :param string id: The openstack resource id.

    :param dict properties: The openstack resource properties.

    """

    def __init__(self, manager, name, id=None, properties=None):  # noqa pylint: disable=W0622
        super(TypedHotResource, self).__init__(
            manager, name, type=None, id=id, properties=properties
        )

    @abc.abstractproperty
    def type(self):  # pylint: disable=E0202
        """The resource type

        You need to set this property on subclasses.
        """
        raise NotImplementedError


@six.add_metaclass(abc.ABCMeta)
class AdvancedHotResource(TypedHotResource, UserDict):
    """Describes a heat resource from openstack.resource.Resource instance

    These advanced resources mays also have resources.

    property_keys are properties to automatically extract from the resource.

    :param ResourceManager manager:
        A ResourceManager instance.
        This instance is necessary to have access to the manager's
        openstack.connection.Connection instance

    :param string name: The name of the openstack resource.
                        e.g.: "My_server".

    :param openstack.resource.Resource data:
        An `openstack.resource.Resource` instance or a munch.Munch instance
        representing the openstack resource returned by an openstack client or
        returned by an `openstack.connection.Connection` instance's API call
        method, or returned by a `shade.openstackcloud.OpenStackCloud`
        instance's API call method.

    :param dict properties: The openstack resource properties.

    When subclassing this class, the `property_keys` tuple represents
    property keys which will be automatically extracted from the resource,
    allowing you to not pass any properties.

    Since we inheritate from UserDict, we have a direct access to `self.data`.
    More info here:
    https://docs.python.org/3/library/collections.html#userdict-objects
    The only difference is that we use a munch instead of dict for `self.data`
    This means we can access `self.data[key]` with `self[key]` (UserDict) and
    via `self.data.key` (munch).
    """

    property_keys = ()
    data = None

    def __init__(self, manager, name, data, properties=None):

        data = munchify(data)

        final_properties = {}
        # Automatically get properties from self.property_keys
        for key in self.property_keys:
            final_properties[key] = data[key]
        # Override properties:
        if properties:
            final_properties.update(properties)

        super(AdvancedHotResource, self).__init__(
            manager, name, id=data.get('id'),
            properties=final_properties
        )
        self.data = data


@six.add_metaclass(abc.ABCMeta)
class ResourceManager(object):
    """Resource manager to list specific openstack resources

    :param flameclient.flame.TemplateGenerator generator:
        A `flameclient.flame.TemplateGenerator` instance.

    :param argparse.Namespace options:
    argparse options.

    args and kwargs are extra parameters which each resource can access in case
    of developer needs.

    This class needs to be subclassed. Every subclass which is imported will be
    discovered by `resources.get_manager_classes()`
    """

    generator = None
    args = ()
    kwargs = None

    def __init__(self, generator, *args, **kwargs):
        self.generator = generator
        self.args = args
        self.kwargs = kwargs or {}

    @ClassProperty
    def name(cls):
        """The resource manager name

        You need to set this property on subclasses if the automatic naming
        does not work.

        ex.: If this class is calles FooBarsManager, this property will return
        'foo_bars'
        """
        return camel_to_snake(cls.__name__).rstrip('_manager')

    @ClassProperty
    def singular_name(cls):
        """The resource manager singular name

        You need to set this property on subclasses if the automatic naming
        does not work.

        Override this if the singular of self.name does not consist in
        in removing the trailing 's'.
        """
        return cls.name.rstrip('s')

    @property
    def options(self):
        return self.generator.options

    @property
    def connection(self):
        return self.generator.connection

    @property
    def conn(self):
        """Give a short name access"""
        return self.connection

    @property
    def cloud(self):
        return self.generator.cloud

    @property
    def managers(self):
        return self.generator.managers

    @classmethod
    def add_arguments(cls, parser):
        """Add parser argparse.ArgumentParser arguments

        Use this method in your subclasses if you want to add any specific
        argparse arguments. These arguments will then be available on
        `self.options`.

        :param argparse.ArgumentParser parser: An argparse.ArgumentParser
                                               instance

        :returns: An argparse.ArgumentParser parser instance
        """
        return parser

    @abc.abstractproperty
    def api_resources(self):
        """Implement this property to return api resources

        This property will be automatically set as an attribute on
        `generator.api` and `self.api` with `self.name`.

        e.g.: if this class has `self.name` set to 'routers', the
        `self.generator.api.routers` attribute and `self.api.routers`
        attribute will return the results of this property.

        Consider using the `utils.memoized_property` decorator on the
        property. This is because this property should be computed only once
        It's the reason why it's a property and not a method.
        Also consider using self.generator_memoize on API calls.

        This property should return a Munch instance generated by
        `utils.data_list_to_dict` on a list of `openstack.resource.Resource`
        instances in order to be consistent with all managers
        the result has to be in the following form:

            Munch(
                {
                    'some_id': Munch({}),
                    'other_id': Munch{},
                 }
            )

        The `get_resource_name` expects to find a `.enum` attribute on
        each munch value. You will need to override `get_resource_name` if
        you have a different data format.
        """
        raise NotImplementedError

    def get_api_resources(self):
        return self.api_resources

    @property
    def api(self):
        """Direct access to all managers' api resources

        e.g.: if there is a FooManager (with FooManager.name = 'foo'),
        `self.api.foo` will give access to `FooManager.api_resources`
        if the current instance and a FooManager instance are in a ManagerList
        on a TemplateGenerator.

        This allows access to each manager's api resources from any other
        manager.

        For this to work it implies that TemplateGenerator.api is a
        DirectManagerApiResourceAccess instance.
        """
        return self.generator.api

    @abc.abstractmethod
    def get_hot_resources(self):
        """Implement this method to return resources

        You need to take into account `self.options.no_threads` and not use
        threads (e.g.: `concurrent.futures`, threading module, etc...) when it
        is True.
        """
        raise NotImplementedError

    def get_resource_num(self, resource_id):
        return self.api_resources[resource_id].enum

    def get_resource_name(self, resource_id):
        return '%s_%d' % (
            self.singular_name, self.get_resource_num(resource_id)
        )

    def generator_memoize(self, method, *args, **kwargs):
        return self.generator.generator_memoize(method, *args, **kwargs)

    @ClassProperty
    def post_priority(cls):
        return 100

    def post_process(self):
        """This method is called after get_hot_resources of all managers

        Use this method to perform actions after processing.

        This method will be called on all managers sorted by the order of
        their self.post_priority number.
        """
        pass

    def post_process_hot_resources(self, resources):  # pylint: disable=R0201
        """This method is called after get_hot_resources of all managers

        Use this method to perform post processing resources modifications.

        :param list resources: the self.generator.resources attribute after
                               all managers' `get_hot_resources` methods have
                               been called.
        :returns: A modified resources list (or a new resources list).
                  A resources list is a list containing resources returned by
                  each manager's `get_hot_resources` method.

        This method will be called on all managers sorted by the order of
        their self.post_priority number.
        This allows you to modify the list aof resources returned by managers.
        """
        return resources

    def post_process_heat_template(self, template):  # pylint: disable=R0201
        """This method is called after get_hot_resources of all managers

        Use this method to perform post processing template modifications.

        :param dict template: the self.generator.template attribute after
                              all managers' `get_hot_resources` methods have
                              been called.
        :returns: The template dictionary which the generator will use to
                  render the flame template. If ou need to create a blank
                  template use `self.generator.get_new_template()` to
                  initialise it.


        You need to return a heat template (in python dictionary format)
        This method will be called on all managers sorted by the order of
        their self.post_priority number.
        """
        return template

    def post_process_adoption_data(self, adoption_data):  # noqa pylint: disable=R0201
        """This method is called after get_hot_resources of all managers

        Use this method to perform post processing adoption_data modifications.

        :param dict adoption_data: the self.generator.adoption_data attribute
                                   after all managers' `get_hot_resources`
                                   methods have been called.
        :returns: The adoption_data dictionary which the generator will use to
                  render the flame adoption data. If ou need to create a blank
                  template use `self.generator.get_new_adoption_data()` to
                  initialise it.

        This method will be called on all managers sorted by the order of
        their self.post_priority number.
        """
        return adoption_data


class ManagerList(list):

    def __getattr__(self, name):
        for manager in self:
            if manager.name == name:
                return manager
        raise AttributeError(
            "'%s' has no '%s' manager" % (
                self.__name__, name
            )
        )

    def __setattr__(self, name, value):
        if isinstance(value, ResourceManager):
            if name != value.name:
                raise ValueError(
                    "'%s'.name != '%s'" % (value, name)
                )
            self.append(value)
        raise TypeError(
            "'%s' '%s' has to be a ResourceManager instance instead of %s" % (
                value, name, type(value)
            )
        )

    def __delattr__(self, name):
        for num, manager in enumerate(self):
            if manager.name == name:
                self.pop(num)
        raise AttributeError(
            "'%s' has no '%s' manager" % (
                self.__name__, name
            )
        )


class DirectManagerApiResourceAccess(object):
    """Give direct access to a manager's api_resources attribute


    This needs to be set as the 'api' attribute on the TemplateGenerator
    class.
    """

    instance = None
    owner = None

    def __get__(self, instance, owner):
        if instance:
            self.instance = instance
        self.owner = owner
        return self

    def __getattr__(self, name):
        if self.instance:
            for manager in self.instance.managers:
                if manager.name == name:
                    return manager.api_resources
            raise AttributeError(
                "'%s' has no '%s' manager in self.managers" % (
                    self.owner.__name__, name
                )
            )


def get_manager_classes():
    """List all subclasses of ResourceManager

    if any loaded python module contains a ResourceManager subclass, it will be
    discovered.
    Make sure to load any module containing the subclass if you want it to be
    discoverable.
    You can use `utils.load_resource_modules(dirname) or
    `utils.load_resource_entry_points(name='openstack_flame')` to load modules
    containing ResourceManager subclasses before using this method.
    """
    load_resource_modules(__file__)
    load_resource_entry_points()
    return ResourceManager.__subclasses__()
