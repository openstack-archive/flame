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

from __future__ import print_function

import argparse
import os

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
    parser.add_argument('--alter-allocation-pools', action='store_true',
                        default=False,
                        help="Have the DHCP allocation pools start at the "
                             "DHCP's IP address for the current subnet.")

    args = parser.parse_args()
    if args.alter_allocation_pools and not args.extract_ports:
        raise argparse.ArgumentError(None,
                                     "Must use --extract-ports with "
                                     "--alter-allocation-pools.")
    flame = client.Client(args.username, args.password,
                          args.project, args.auth_url,
                          args.os_auth_token,
                          region_name=args.region,
                          endpoint_type=args.endpoint_type,
                          insecure=args.insecure)
    template = flame.template_generator
    template.extract_vm_details(args.exclude_servers,
                                args.exclude_volumes,
                                args.exclude_keypairs,
                                args.generate_stack_data,
                                args.extract_ports,
                                args.alter_allocation_pools)
    template.extract_data()
    print("### Heat Template ###")
    print(template.heat_template())
    if args.generate_stack_data:
        print("### Stack Data ###")
        print(template.stack_data_template())
