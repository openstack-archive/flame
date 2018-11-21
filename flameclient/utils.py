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

import argparse
import re
from threading import Lock

import importlib
import os
import pkgutil
import sys

import munch
import pkg_resources
import six

from flameclient import collections_abc


CS2STR1 = re.compile('(.)([A-Z][a-z]+)')
CS2STR2 = re.compile('(.)([0-9]+)')
CS2STR3 = re.compile('([a-z0-9])([A-Z])')
REPLSTR = r'\1_\2'


def camel_to_snake(string):
    """Transform camel_case string to snake_case string"""
    return CS2STR3.sub(
        REPLSTR, CS2STR2.sub(REPLSTR, CS2STR1.sub(REPLSTR, string))
    ).lower()


def sys_path_to_module(path):
    full_path = os.path.realpath(os.path.abspath(path))
    path = full_path
    while True:
        if path in sys.path:
            break
        path = os.path.dirname(path)
        if path == '/':
            return ''
    return path


def get_module_name_from_file(filename):
    filename = os.path.realpath(os.path.abspath(filename))
    sys_path = '%s/' % sys_path_to_module(filename)
    package_path = filename.split(sys_path, 1)[1]
    package_path = package_path.rsplit('.py', 1)[0]
    return package_path.replace('/', '.')


def load_resource_modules(base_file_or_dir, exclude=tuple()):
    """Load packages in a directory

    base_file_or_dir: the base file or dir where we will load packages.
    prefix: the prefix to add to module names.
    """
    modules = {}
    if isinstance(exclude, six.string_types):
        exclude = (exclude, )
    full_path = os.path.realpath(os.path.abspath(base_file_or_dir))
    if os.path.isdir(full_path):
        pkg_dir = full_path
    elif os.path.isfile(full_path):
        pkg_dir = os.path.dirname(full_path)
    else:
        raise ImportError('Can not find "%s"' % full_path)
    prefix = "%s." % get_module_name_from_file(pkg_dir)
    for _, name, ispkg in pkgutil.iter_modules([pkg_dir], prefix):
        # `name` has the form "foo.bar.plop"
        # We do not want to load "foo.bar.test*" modules to not load unittest
        # files.
        # We also do not want to load files starting with an underscore.
        if (
                not name.split('.')[-1].startswith('test') and
                not name.split('.')[-1].startswith('_') and
                name not in exclude and
                not ispkg
        ):
            modules[name] = importlib.import_module(name)
    return modules


def load_resource_entry_points(name='openstack_flame'):
    entry_points = {}
    for entry_point in pkg_resources.iter_entry_points(name):
        entry_points[entry_point.name] = entry_point.load()
    return entry_points


def munchify(obj, iterator_type=list, remunch=False):
    """Transforms an object into a `munch.Munch` object when possible.

        The difference with `munch.munchify` is that when an object has a
    `_to_munch` method, we call this method which was designed for it.

    This method is useful when we have `openstack.resource.Resource` objects
    because they have a `_to_munch` method.

    The purpose is to have the same type of objects whether we use
    `openstack.connection.Connection` methods or
    `shade.openstackcloud.OpenStackCloud` specific methods.

    `openstack.connection.Connection` methods return
    `openstack.resource.Resource` subclasses and
    `shade.openstackcloud.OpenStackCloud` methods return `munch.Munch` objects.

    :param bool remunch: If True we return a deep copy of the object if it's
                         already a `munch.Munch` instance. By default we
                         return the `munch.Munch` object as is.


    :param function iterator_type: If we have an iterator instead of an
                                   iterable object we return a list by default.
                                   You can change this behaviour by passing the
                                   callable to the type you want (ex.: tuple).
                                   This only affects Iterators and not
                                   iterables for which we keep the same type.
                                   You get an iterator when you have an
                                   `openstack.connection.Connection` instance
                                   and do e.g.: `conn.compute.servers()`.
                                   So if you call
                                   `munchify(conn.compute.servers())` you will
                                   get the iterator_type (a list by default).
    """

    # Check
    # https://docs.python.org/2/library/collections.html#collections-abstract-base-classes  # noqa
    # or
    # https://docs.python.org/3/library/collections.abc.html#collections-abstract-base-classes  # noqa
    # To know in which order to test.
    if not remunch and isinstance(obj, munch.Munch):
        return obj
    if hasattr(obj, '_to_munch'):
        return obj._to_munch()
    elif isinstance(obj, collections_abc.Mapping):  # Test for `dict` likes.
        # Mappings (dicts, OrderedDict, etc...) are iterable so it
        # needs to be tested before iterable types.
        return munch.Munch(
            (key, munchify(value)) for key, value in six.iteritems(obj)
        )
    elif isinstance(obj, six.string_types):
        # Strings are iterable so this needs to be tested before the
        # iterable types.
        return obj
    elif isinstance(obj, collections_abc.Iterator):
        # `Iterator` is a subclass of `Iterable` so we need to test it first.
        return iterator_type(munchify(elt) for elt in obj)
    elif isinstance(obj, collections_abc.Iterable):
        # At last, check if we have an iterable object.
        return type(obj)(munchify(elt) for elt in obj)
    else:
        return munch.munchify(obj)


def data_list_to_dict(data_list, enum=True):
    data_dict = munch.Munch()
    for num, data in enumerate(data_list):
        data_dict[data.id] = munchify(data)
        if enum:
            data_dict[data.id].enum = num
    return data_dict


def clean_dict(obj, clean_list=True, super_clean=False, iterator_type=list):
    """Returns a dict copy with only values which are not None

    :param bool clean_list: whether to suppress or not None values from lists
    :param bool super_clean: whether to suppress or not values which evaluate
                             to False (not only None).
    :param function iterator_type: cast function for iterator types.

    """

    if isinstance(obj, six.string_types):
        return obj
    elif isinstance(obj, collections_abc.Mapping):
        if super_clean:
            return type(obj)(
                (key, clean_dict(
                    value, clean_list=clean_list, super_clean=super_clean))
                for key, value in six.iteritems(obj) if value
            )
        return type(obj)(
            (key, clean_dict(
                value, clean_list=clean_list, super_clean=super_clean))
            for key, value in six.iteritems(obj)if value is not None
        )
    elif isinstance(obj, collections_abc.Iterator):
        if super_clean:
            return iterator_type(
                clean_dict(elt, clean_list=clean_list, super_clean=super_clean)
                for elt in obj if elt or not clean_list
            )
        return iterator_type(
            clean_dict(elt, clean_list=clean_list, super_clean=super_clean)
            for elt in obj if elt is not None or not clean_list
        )
    elif isinstance(obj, collections_abc.Iterable):
        # At last, check if we have an iterable object.
        if super_clean:
            return type(obj)(
                clean_dict(elt, clean_list=clean_list, super_clean=super_clean)
                for elt in obj if elt or not clean_list
            )
        return type(obj)(
            clean_dict(elt, clean_list=clean_list, super_clean=super_clean)
            for elt in obj if elt is not None or not clean_list
        )
    else:
        return obj


def format_option(option_str):
    option_str = option_str.lstrip('-')
    option_str = option_str.replace('-', '_')
    return option_str


def format_option_kwargs(kwargs):
    """Format a dictionary with option names to dict keys.

    This will allow further keyword arguments passing of argparse options.

    example:
    change `{'--foo-bar': 'value'}` to `{'foo_bar': 'value'}` etc...

    """
    return {
        format_option(key): value for key, value in six.iteritems(kwargs)
    }


def dict_to_options(kwargs):
    if kwargs is not None:
        if isinstance(kwargs, argparse.Namespace):
            return kwargs
        return argparse.Namespace(**format_option_kwargs(kwargs))
    return None


def rename_os_kwargs(kwargs, clean=False):
    """Clean Openstack kwargs from the 'os_' prefix.

    envvars return 'os_username', 'os_auth_url', etc... variables.
    we want to remove the 'os_' prefix

    :param dict kwargs: the dictionary to clean

    :param bool clean: If true, the returned dictionary will not have keys
                            with empty values.

    """
    new_kwargs = {}
    for key, value in six.iteritems(kwargs):
        if value or not clean:
            if key.startswith('os_'):
                new_kwargs[key.split('os_')[1]] = value
            else:
                new_kwargs[key] = value
    return new_kwargs


def rename_os_options(options, clean=False):
    """Clean Openstack envvars from the 'os_' prefix.

    envvars return 'os_username', 'os_auth_url', etc... variables.
    we want to remove the 'os_' prefix

    :param argparse.Namespace options: the options to clean

    :param bool clean: If true, the returned options will not have
                            attributes with empty values.
    """
    kwargs = vars(options)
    renamed_kwargs = rename_os_kwargs(kwargs, clean=clean)
    return argparse.Namespace(**renamed_kwargs)


def hash_func_call(func, *args, **kwargs):
    """hash a function call"""
    # kwargs is a dict, and dicts are not hashable.
    kwargs_tuple = tuple((key, value) for key, value in six.iteritems(kwargs))
    return hash((func, args, kwargs_tuple))


def get_deep_attr(obj, value):
    """Get deep attribute

    example, `getattr(some_object, 'attr.subattr')` does not work.
    With get_deep_attr it works.

    """
    subelts = value.split('.', 1)
    if len(subelts) == 1:
        return getattr(obj, value)
    else:
        return get_deep_attr(getattr(obj, subelts[0]), subelts[1])


def memoized_property(func):
    """Decorator to set properties which will be computed only once

    """
    attr_name = '__%s' % func.__name__
    lock = Lock()

    class FixedProperty(object):
        def __get__(self, instance, owner):
            if instance:
                with lock:
                    try:
                        return getattr(instance, attr_name)
                    except AttributeError:
                        result = func(instance)
                        setattr(instance, attr_name, result)
                        return result

            return self

        def __set__(self, instance, value):
            with lock:
                setattr(instance, attr_name, value)

        def __delete__(self, instance):
            with lock:
                delattr(instance, attr_name)

    return FixedProperty()


class ClassProperty(classmethod):

    def __get__(self, instance, owner):
        return self.__func__(owner)

    def __set__(self, instance, value):
        setattr(instance, self.__func__.__name__, value)

    def __delete__(self, instance):
        delattr(instance, self.__func__)
