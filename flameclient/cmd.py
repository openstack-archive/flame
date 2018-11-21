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

from flameclient import flame


def main():
    """Flame heat template generation

    Flame can be used with a shade or openstack sdk instance, and options can
    be passed as option kwargs.

    ex:

        from flameclient.session import get_shade
        from flameclient import flame

        auth_kwargs = {
            'auth_type': u'password',
            'auth_url': 'https://your_cloud_identity_url/v2.0',
            'interface': 'public',
            'password': 'YourPassword',
            'project_id': 'YourProjectID',
            'project_name': 'YourProjectName',
            'region_name': 'region_one',
            'username': 'YourUserName'
        }

        cloud = get_shade(**auth_kwargs)

    Or instead of kwargs if you want to use environment variables:

        cloud = get_shade(load_envvars=True)

    Then:

        generator = flame.TemplateGenerator(
            connection=cloud,
            options=dict(
                include_constraint=True,
                extract_ports=True,
                generate_adoption_data=True,
                no_threads=True)
        )

        generator.extract_data()
        print(generator.heat_template_and_data())

    Passing a shade or openstack sdk instance and option kwargs allows you to
    integrate shade in other projects.

    """
    template_generator = flame.TemplateGenerator()
    template_generator.extract_data()
    template_generator.output_template_and_data()


if __name__ == '__main__':
    main()
