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
import logging
import sys

from keystoneauth1 import loading
from keystoneauth1 import session as keystone_session
from openstack import connection as os_connection
# We get a subclass of openstack.config.loader.OpenStackConfig which is more
# complete:
from os_client_config.config import OpenStackConfig  # noqa
from shade.openstackcloud import OpenStackCloud  # noqa

from flameclient import utils

LOG = logging.getLogger(__name__)


def list_auth_types():
    return [loader for loader in loading.get_available_plugin_loaders()]


def get_loader(auth_type):
    if auth_type not in list_auth_types():
        raise ValueError(
            "'auth_type' has to be one of %s (received %s)" % (
                list_auth_types(), auth_type
            )
        )
    return loading.get_plugin_loader(auth_type)


def extract_loader_kwargs(loader, **kwargs):
    """Get keystoneauth1.loading.get_plugin_loader's auth kwargs

    Return the specific auth kwargs and remaining kwargs
    """
    loader_keys = [option.dest for option in loader.get_options()]
    loader_kwargs = {
        key: kwargs[key] for key in loader_keys if key in kwargs
    }
    remaining_kwargs = {
        key: kwargs[key] for key in kwargs if key not in loader_keys
    }
    return loader_kwargs, remaining_kwargs


def get_openstack_config_with_envvars(
        parser, config=None, load_envvars=False, load_yaml_config=False
):
    """Add openstack_options to argparse.ArgumentParser

    :param argparse.ArgumentParser parser: argparse.ArgumentParser instance
                                           or None.

    :param bool load_envvars:
        Whether or not to load config settings from environment variables.
        Defaults to True.

    :returns: OpenStackConfig instance
    """

    if config is None:
        # If we use `openstack.config.loader.OpenStackConfig` instead of
        # `os_client_config.config.OpenStackConfig` and then instantiate a
        # `shade.openstackcloud.OpenStackCloud` instance as `cloud`, when
        # trying to access the `cloud.keystone_client` attribute (or any other
        # `*_client attribute`), we get a
        # "TypeError: 'NoneType' object is not callable" exception
        # This is why we use `os_client_config.config.OpenStackConfig`: it's to
        # have all `shade.openstackcloud.OpenStackCloud` attributes working
        # properly. Whether we use them or not, whether these attributes are
        # deprecated or not, we do not want a 'broken' shade instance in case
        # third party managers would use them.
        config = OpenStackConfig(
            load_envvars=load_envvars, load_yaml_config=load_yaml_config
        )
    if parser:
        if load_envvars or load_yaml_config:
            config.register_argparse_arguments(parser, sys.argv)
        else:
            config.register_argparse_arguments(parser, [])
    return config


def get_openstack_cli_arguments(
        parser=None, load_envvars=True, load_yaml_config=True,
        renamed_args=False
):
    if parser is None:
        parser = argparse.ArgumentParser()
    get_openstack_config_with_envvars(
        parser, load_envvars=load_envvars, load_yaml_config=load_yaml_config
    )
    known_args, unknown_args = parser.parse_known_args()
    if renamed_args:
        known_args = utils.rename_os_options(known_args, clean=False)
    return known_args, unknown_args


def get_openstack_envvars_as_kwargs(
        with_args=False, parser=None, load_envvars=True, load_yaml_config=True
):
    """Get openstack environment variables"""
    known_args, unknown_args = get_openstack_cli_arguments(
        parser=parser, load_envvars=load_envvars,
        load_yaml_config=load_yaml_config
    )
    kwargs = utils.rename_os_kwargs(vars(known_args), clean=True)
    if with_args:
        return known_args, unknown_args, kwargs
    return kwargs


def get_keystoneauth1_session(
        load_envvars=False, load_yaml_config=False, **kwargs
):
    if load_envvars:
        kwargs.update(
            get_openstack_envvars_as_kwargs(
                load_envvars=load_envvars, load_yaml_config=load_yaml_config
            )
        )
    auth_type = kwargs.get('auth_type', 'password')
    loader = get_loader(auth_type)
    loader_kwargs, _ = extract_loader_kwargs(loader, **kwargs)
    auth = loader.load_from_options(**loader_kwargs)
    return keystone_session.Session(auth=auth)


get_keystone_session = get_keystoneauth1_session


def get_openstack_config(
        parser_or_options=None, load_envvars=False, load_yaml_config=False,
        **kwargs
):
    """Same as os_client_config.get_config with less errors.

    Indeed, if we source OS_* variable environments, and one calls:

        os_client_config.get_config(
            load_envvars=False, load_yaml_config=False, **kwargs
        )

    we get this kind of error:

        ConfigException: Region fr1 is not a valid region name for cloud
        envvars. Valid choices are fr0. Please note that region names are case
        sensitive.

    It seems like os_client_config.get_config fails to NOT handle envvars.

    Also, os_client_config.get_config saves the config in a global variable...
    This is absolutely not thread safe...

    """
    parsed_options = None
    parser = None
    if isinstance(parser_or_options, argparse.ArgumentParser):
        parser = parser_or_options
    config = get_openstack_config_with_envvars(
        parser=parser, load_envvars=load_envvars,
        load_yaml_config=load_yaml_config
    )
    if parser_or_options is not None:
        if isinstance(parser_or_options, argparse.Namespace):
            parsed_options = parser_or_options
        elif isinstance(parser_or_options, dict):
            parsed_options = utils.dict_to_options(parser_or_options)
        elif isinstance(parser_or_options, argparse.ArgumentParser):
            if load_envvars or load_yaml_config:
                parsed_options, _ = parser_or_options.parse_known_args(
                    sys.argv)
            else:
                parsed_options, _ = parser_or_options.parse_known_args([])
        else:
            raise AttributeError(
                "'parser_options' has to be an 'argparse.ArgumentParser' or "
                "'argparse.Namespace' instance or dict or None. "
                "Received '%s'" % type(parser_or_options)
            )
    return config.get_one(
        options=parsed_options,
        load_yaml_config=load_yaml_config,
        load_envvars=load_envvars,
        **kwargs
    )


def get_openstack_sdk_connection(
        parser_or_options=None, load_envvars=False, load_yaml_config=False,
        cloud_config=None, session=None,
        **kwargs
):
    if session is not None:
        return os_connection.Connection(session=session, **kwargs)

    if cloud_config is None:
        # we could return
        # `openstack.connect(load_envvars=load_envvars, load_yaml_config=load_yaml_config, **kwargs)`  # noqa
        # but by doing so magic things are lacking in the config and we have
        # random failing methods on the instance. See comments in
        # get_openstack_config_with_envvars for more information.
        cloud_config = get_openstack_config(
            parser_or_options=parser_or_options, load_envvars=load_envvars,
            load_yaml_config=load_yaml_config,
            **kwargs
        )
    if isinstance(parser_or_options, dict):
        parser_or_options = utils.dict_to_options(parser_or_options)
    return os_connection.from_config(
        cloud_config=cloud_config, options=parser_or_options
    )


def get_shade(
        parser_or_options=None, cloud_config=None, connection=None,
        load_envvars=False, load_yaml_config=False,
        **kwargs
):
    """Get shade instance

    You can use an `argparse.ArgumentParser` or `argparse.Namespace` instance
    with `load_envvars` and/or `load_yaml_config` set to True,
    Or you kan use kwargs to authenticate with `load_envvars` AND
    `load_yaml_config` set to False:

        cloud = get_shade(
            auth_type='password',
            auth_url='https://identity.fr1.cloudwatt.com/v2.0',
            interface='public',
            password='YourPassword',
            project_id='Your ProjectID,
            project_name='YourProjectName,
            region_name='YourRegionName',
            username='YourUserName'
        )

    You can also use a token instead of password with kwargs, If so, use
    `auth_type='token'`.

    """
    if cloud_config is not None:
        return OpenStackCloud(cloud_config=cloud_config, **kwargs)
    elif connection is not None:
        return OpenStackCloud(cloud_config=connection.config, **kwargs)
    else:
        return OpenStackCloud(
            cloud_config=get_openstack_config(
                parser_or_options=parser_or_options, load_envvars=load_envvars,
                load_yaml_config=load_yaml_config,
                **kwargs
            )
        )
