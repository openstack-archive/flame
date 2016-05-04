Flame: Automatic Heat template generation
============================================

OpenStack Orchestration project Heat implements an orchestration engine to
launch multiple composite cloud applications based on templates. A Heat
template describes infrastructure resources (servers, networks, floating ips,
etc) and the relationships between these resources, allowing Heat to deploy the
resources in a correct order and to manage whole infrastructure lifecycle.

`flame` is a standalone tool that generates HOT Heat
template from already existing infrastructure. It provides support
for Nova (key pairs and servers), Cinder (volumes) and Neutron (router,
networks, subnets, security groups and floating IPs) resources.

`flame` works as follows: using provided credentials (user name, project name,
password or auth_token, authentication url), the tool will list supported
resources deployed in the project and will generate corresponding, highly
customized HOT template.

Installation
------------

First of all, clone the repository and go to the repository directory:

        git clone https://github.com/openstack/flame.git
        cd flame

Then just run:

        python setup.py install

Usage
----------------------

    usage: flame [-h] [--username USERNAME] [--password PASSWORD]
                 [--project PROJECT] [--region REGION] [--auth_url AUTH_URL]
                 [--insecure] [--exclude-servers] [--exclude-volumes]
                 [--generate-stack-data]

    Heat template and data file generator

    optional arguments:
      -h, --help            show this help message and exit
      --username USERNAME   A user name with access to the project. Defaults to
                            env[OS_USERNAME]
      --password PASSWORD   The user's password. Defaults to env[OS_PASSWORD]
      --project PROJECT     Name of project. Defaults to env[OS_TENANT_NAME]
      --region REGION       Name of region. Defaults to env[OS_REGION_NAME]
      --auth_url AUTH_URL   Authentication URL. Defaults to env[OS_AUTH_URL].
      --os-auth-token OS_AUTH_TOKEN
                            User's auth token. Defaults to env[OS_AUTH_TOKEN].
      --insecure            Explicitly allow clients to perform"insecure" SSL
                            (https) requests. The server's certificate will not be
                            verified against any certificate authorities. This
                            option should be used with caution.
      --exclude-servers     Do not export in template server resources
      --exclude-volumes     Do not export in template volume resources
      --exclude-keypairs    Do not export in template key pair resources
      --generate-stack-data
                            In addition to template, generate Heat stack data
                            file.

Usage example
-------------

To use Flame you can provide yours OpenStack credentials as arguments :

    $ flame --username user --password password --project project
    --auth_url http://<Keystone_host>:5000/v2.0


Or you can source your OpenStack RC file and use Flame without arguments.

Flame can be used with either a login and password pair or a keystone
token by exporting the OS_AUTH_TOKEN variable (the token is obtained
with keystone token-get).
