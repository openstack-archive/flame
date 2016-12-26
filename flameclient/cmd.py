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

from __future__ import print_function

import argparse
import os

from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session

from flameclient import client


def main(args=None):
    desc = "Heat template and data file generator"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--username", type=str,
                        default=os.environ.get("OS_USERNAME"),
                        help="A user name with access to the project. "
                             "Defaults to env[OS_USERNAME]")
    parser.add_argument("--password", type=str,
                        default=os.environ.get("OS_PASSWORD"),
                        help="The user's password. "
                             "Defaults to env[OS_PASSWORD]")
    parser.add_argument("--project", type=str,
                        default=os.environ.get("OS_TENANT_NAME"),
                        help="Name of project. "
                             "Defaults to env[OS_TENANT_NAME]")
    parser.add_argument("--region",
                        default=os.environ.get("OS_REGION_NAME"),
                        help="Name of region. "
                             "Defaults to env[OS_REGION_NAME]")
    parser.add_argument("--auth_url", type=str,
                        default=os.environ.get("OS_AUTH_URL"),
                        help="Authentication URL. "
                             "Defaults to env[OS_AUTH_URL].")
    parser.add_argument("--user-domain-name", type=str,
                        default=os.environ.get("OS_USER_DOMAIN_NAME"),
                        help="User domain id. "
                             "Defaults to env[OS_USER_DOMAIN_NAME].")
    parser.add_argument("--user-domain-id", type=str,
                        default=os.environ.get("OS_USER_DOMAIN_ID"),
                        help="User domain name. "
                             "Defaults to env[OS_USER_DOMAIN_ID].")
    parser.add_argument("--project-domain-id", type=str,
                        default=os.environ.get("OS_PROJECT_DOMAIN_ID"),
                        help="Project domain id. "
                             "Defaults to env[OS_PROJECT_DOMAIN_ID].")
    parser.add_argument("--project-domain-name", type=str,
                        default=os.environ.get("OS_PROJECT_DOMAIN_NAME"),
                        help="project domain name. "
                             "Defaults to env[OS_PROJECT_DOMAIN_NAME].")
    parser.add_argument("--os-auth-token", type=str,
                        default=os.environ.get("OS_AUTH_TOKEN"),
                        help="User's auth token. "
                             "Defaults to env[OS_AUTH_TOKEN].")
    parser.add_argument('--insecure', action='store_true', default=False,
                        help="Explicitly allow clients to perform"
                             "\"insecure\" SSL (https) requests. The "
                             "server's certificate will not be verified "
                             "against any certificate authorities. This "
                             "option should be used with caution.")
    parser.add_argument("--endpoint_type", type=str,
                        default=os.environ.get("OS_ENDPOINT_TYPE",
                                               "publicURL"),
                        help="Defaults to env[OS_ENDPOINT_TYPE] or publicURL")
    parser.add_argument("--os-cert", type=str, metavar='<certificate>',
                        default=os.environ.get("OS_CERT"),
                        help="User's certificate. "
                             "Defaults to env[OS_CERT].")
    parser.add_argument("--os-key", type=str, metavar='<key>',
                        default=os.environ.get("OS_KEY"),
                        help="User's key. "
                             "Defaults to env[OS_KEY].")
    parser.add_argument('--exclude-servers', action='store_true',
                        default=False,
                        help="Do not export in template server resources")
    parser.add_argument('--exclude-volumes', action='store_true',
                        default=False,
                        help="Do not export in template volume resources")
    parser.add_argument('--exclude-keypairs', action='store_true',
                        default=False,
                        help="Do not export in template key pair resources")
    parser.add_argument('--generate-stack-data', action='store_true',
                        default=False,
                        help="In addition to template, generate Heat "
                             "stack data file.")
    parser.add_argument('--extract-ports', action='store_true',
                        default=False,
                        help="Export the tenant network ports")
    parser.add_argument('--exclude-secgroups', action='store_true',
                        default=False,
                        help="Do not export in template "
                             "security group resources")
    parser.add_argument('--exclude-floatingips', action='store_true',
                        default=False,
                        help="Do not export in template floating"
                             " ip resources")

    args = parser.parse_args()

    auth_map = {
        2: get_v2_auth,
        3: get_v3_auth
    }
    auth = auth_map[_determine_auth_version(args.auth_url)](args)
    ses = session.Session(
        auth=auth,
        cert=args.os_cert,
        verify=not args.insecure
    )

    flame = client.Client(ses, args.username, args.password,
                          args.project, args.auth_url,
                          args.os_auth_token,
                          cert=args.os_cert, key=args.os_key,
                          region_name=args.region,
                          endpoint_type=args.endpoint_type,
                          insecure=args.insecure)
    template = flame.template_generator
    template.extract_vm_details(args.exclude_servers,
                                args.exclude_volumes,
                                args.exclude_keypairs,
                                args.generate_stack_data,
                                args.extract_ports,
                                args.exclude_secgroups,
                                args.exclude_floatingips)
    template.extract_data()
    print("### Heat Template ###")
    print(template.heat_template_and_data())


def _determine_auth_version(auth_url):
    return 3 if "v3" in auth_url else 2


def get_v2_auth(args):
    return v2.Password(
        args.auth_url, args.username,
        args.password, tenant_name=args.project
    )


def get_v3_auth(args):
    return v3.Password(
        args.auth_url,
        username=args.username,
        password=args.password,
        user_domain_name=args.user_domain_name,
        user_domain_id=args.user_domain_id,
        project_name=args.project,
        project_domain_name=args.project_domain_name,
        project_domain_id=args.project_domain_id,
    )
