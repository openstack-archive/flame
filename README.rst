Flame: Automatic Heat template generation
=========================================

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
-----

To use the CLI of flame::

    usage: flame [-h] [--debug] [--generate-stack-data] [--include-constraints]
                 [--no-threads] [--prefetch] [--exclude-keypairs]
                 [--extract-ports] [--exclude-secgroups] [--exclude-servers]
                 [--exclude-volumes] [--os-cloud <name>] [--os-auth-type <name>]
                 [--os-auth-url OS_AUTH_URL] [--os-system-scope OS_SYSTEM_SCOPE]
                 [--os-domain-id OS_DOMAIN_ID] [--os-domain-name OS_DOMAIN_NAME]
                 [--os-project-id OS_PROJECT_ID]
                 [--os-project-name OS_PROJECT_NAME]
                 [--os-project-domain-id OS_PROJECT_DOMAIN_ID]
                 [--os-project-domain-name OS_PROJECT_DOMAIN_NAME]
                 [--os-trust-id OS_TRUST_ID]
                 [--os-default-domain-id OS_DEFAULT_DOMAIN_ID]
                 [--os-default-domain-name OS_DEFAULT_DOMAIN_NAME]
                 [--os-user-id OS_USER_ID] [--os-username OS_USERNAME]
                 [--os-user-domain-id OS_USER_DOMAIN_ID]
                 [--os-user-domain-name OS_USER_DOMAIN_NAME]
                 [--os-password OS_PASSWORD] [--insecure]
                 [--os-cacert <ca-certificate>] [--os-cert <certificate>]
                 [--os-key <key>] [--timeout <seconds>] [--collect-timing]
                 [--os-service-type <name>] [--os-service-name <name>]
                 [--os-interface <name>] [--os-region-name <name>]
                 [--os-endpoint-override <name>] [--os-api-version <name>]

    Heat template and data file generator

    optional arguments:
      -h, --help            show this help message and exit
      --debug               set debuging log level
      --generate-stack-data
                            In addition to template, generate Heat stack data
                            file.
      --include-constraints
                            Export in template custom constraints
      --no-threads          Deactivate threads for api calls, (usefull for (i)pdb
                            debugging.
      --prefetch            Prefetch all API calls (works only without --no-
                            threads
      --exclude-keypairs    Do not export in template key pair resources
      --extract-ports       Export the tenant network ports
      --exclude-secgroups   Do not export in template security group resources
      --exclude-servers     Do not export in template server resources
      --exclude-volumes     Do not export in template volume resources
      --os-cloud <name>     Named cloud to connect to
      --os-auth-type <name>, --os-auth-plugin <name>
                            Authentication type to use

    Authentication Options:
      Options specific to the password plugin.

      --os-auth-url OS_AUTH_URL
                            Authentication URL
      --os-system-scope OS_SYSTEM_SCOPE
                            Scope for system operations
      --os-domain-id OS_DOMAIN_ID
                            Domain ID to scope to
      --os-domain-name OS_DOMAIN_NAME
                            Domain name to scope to
      --os-project-id OS_PROJECT_ID, --os-tenant-id OS_PROJECT_ID
                            Project ID to scope to
      --os-project-name OS_PROJECT_NAME, --os-tenant-name OS_PROJECT_NAME
                            Project name to scope to
      --os-project-domain-id OS_PROJECT_DOMAIN_ID
                            Domain ID containing project
      --os-project-domain-name OS_PROJECT_DOMAIN_NAME
                            Domain name containing project
      --os-trust-id OS_TRUST_ID
                            Trust ID
      --os-default-domain-id OS_DEFAULT_DOMAIN_ID
                            Optional domain ID to use with v3 and v2 parameters.
                            It will be used for both the user and project domain
                            in v3 and ignored in v2 authentication.
      --os-default-domain-name OS_DEFAULT_DOMAIN_NAME
                            Optional domain name to use with v3 API and v2
                            parameters. It will be used for both the user and
                            project domain in v3 and ignored in v2 authentication.
      --os-user-id OS_USER_ID
                            User id
      --os-username OS_USERNAME, --os-user-name OS_USERNAME
                            Username
      --os-user-domain-id OS_USER_DOMAIN_ID
                            User's domain id
      --os-user-domain-name OS_USER_DOMAIN_NAME
                            User's domain name
      --os-password OS_PASSWORD
                            User's password

    API Connection Options:
      Options controlling the HTTP API Connections

      --insecure            Explicitly allow client to perform "insecure" TLS
                            (https) requests. The server's certificate will not be
                            verified against any certificate authorities. This
                            option should be used with caution.
      --os-cacert <ca-certificate>
                            Specify a CA bundle file to use in verifying a TLS
                            (https) server certificate. Defaults to
                            env[OS_CACERT].
      --os-cert <certificate>
                            Defaults to env[OS_CERT].
      --os-key <key>        Defaults to env[OS_KEY].
      --timeout <seconds>   Set request timeout (in seconds).
      --collect-timing      Collect per-API call timing information.

    Service Options:
      Options controlling the specialization of the API Connection from
      information found in the catalog

      --os-service-type <name>
                            Service type to request from the catalog
      --os-service-name <name>
                            Service name to request from the catalog
      --os-interface <name>
                            API Interface to use [public, internal, admin]
      --os-region-name <name>
                            Region of the cloud to use
      --os-endpoint-override <name>
                            Endpoint to use instead of the endpoint in the catalog
      --os-api-version <name>
                            Which version of the service API to use

Usage example
-------------

To use Flame you can provide yours OpenStack credentials as arguments ::

    $ flame --os-username 'user_name' \
            --os-password 'password' \
            --os-project-name 'project_name' \
            --os-auth-url 'http://<Keystone_host>:5000/v2.0'

Or you can source your OpenStack RC file and use Flame without arguments.

To establish a two-way SSL connection with the identity service ::

    $flame --os-username 'user_name' \
           --os-password 'password' \
           --os-project-name 'project_name' \
           --os-auth_url http://<Keystone_host>:5000/v2.0 \
           --os-cert <path/to/certificate>  \
           --os-key <path/to/key>

Flame can be used with either a login and password pair or a keystone
token by exporting the OS_AUTH_TOKEN variable and the `--os-auth-type 'token'`
parameter (the token is obtained with keystone token-get )::

    $ flame --os-auth-type 'token' \
            --os-token 'token_id' \
            --os-auth-url 'http://<Keystone_host>:5000/v2.0'

