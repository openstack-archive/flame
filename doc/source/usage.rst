=====
Usage
=====

To use install flame in a project::

    python setup.py install

To use the CLI of flame::

    usage: flame [-h] [--username USERNAME] [--password PASSWORD]
                 [--project PROJECT] [--os-auth-token OS_AUTH_TOKEN]
                 [--auth_url AUTH_URL] [--insecure] [--exclude_servers]
                 [--exclude_volumes]

    Generate Heat Template

    optional arguments:
      -h, --help           show this help message and exit
      --username USERNAME  A user name with access to the project. Defaults to
                           env[OS_USERNAME]
      --password PASSWORD  The user's password. Defaults to env[OS_PASSWORD]
      --project PROJECT    Name of project. Defaults to env[OS_TENANT_NAME]
      --auth_url AUTH_URL  Authentication URL. Defaults to env[OS_AUTH_URL].
      --os-auth-token OS_AUTH_TOKEN
                           User's auth token. Defaults to env[OS_AUTH_TOKEN].
      --insecure           Explicitly allow clients to perform"insecure" SSL
                           (https) requests. The server's certificate will not be
                           verified against any certificate authorities. This
                           option should be used with caution.
      --exclude_servers    Do not export in template server resources
      --exclude_volumes    Do not export in template volume resources
      --generate-stack-data
                           In addition to template, generate Heat stack data
                           file.


Example
-------

To use Flame you can provide yours OpenStack credentials as arguments::

      $ flame --username arezmerita --password password \
              --project project-arezmerita --auth_url https://example.com/v2.0/

Or a token and a tenant::

      $ flame --username arezmerita --os-auth-token keystonetoken \
              --project project-arezmerita --auth_url https://example.com/v2.0/

Or you can source your OpenStack RC file and use Flame without arguments::

    $ source credential.rc
    $ flame
