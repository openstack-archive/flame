========
Usage
========

To use install flame in a project::

    python setup.py install

To use the CLI of flame::

  usage: flame [-h] [--username USERNAME] [--password PASSWORD]
               [--project PROJECT] [--region REGION] [--auth_url AUTH_URL]
               [--insecure] [--endpoint_type ENDPOINT_TYPE] [--exclude-servers]
               [--exclude-volumes] [--exclude-keypairs] [--generate-stack-data]
               [--extract-ports]

  Heat template and data file generator

  optional arguments:
    -h, --help            show this help message and exit
    --username USERNAME   A user name with access to the project. Defaults to
                          env[OS_USERNAME]
    --password PASSWORD   The user's password. Defaults to env[OS_PASSWORD]
    --project PROJECT     Name of project. Defaults to env[OS_TENANT_NAME]
    --region REGION       Name of region. Defaults to env[OS_REGION_NAME]
    --auth_url AUTH_URL   Authentication URL. Defaults to env[OS_AUTH_URL].
    --insecure            Explicitly allow clients to perform"insecure" SSL
                          (https) requests. The server's certificate will not be
                          verified against any certificate authorities. This
                          option should be used with caution.
    --endpoint_type ENDPOINT_TYPE
                          Defaults to env[OS_ENDPOINT_TYPE] or publicURL
    --exclude-servers     Do not export in template server resources
    --exclude-volumes     Do not export in template volume resources
    --exclude-keypairs    Do not export in template key pair resources
    --generate-stack-data
                          In addition to template, generate Heat stack data
                          file.
    --extract-ports       Export the tenant network ports



Example
-------

To use Flame you can provide yours OpenStack credentials as arguments::

      $ flame --username arezmerita --password password \
              --project project-arezmerita --auth_url https://example.com/v2.0/

Or you can source your OpenStack RC file and use Flame without arguments::

    $ source credential.rc
    $ flame
