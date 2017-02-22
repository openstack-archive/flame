=====
Usage
=====

To use install flame in a project::

    python setup.py install

To use the CLI of flame::

    usage: flame [-h] [--os-username USERNAME] [--username USERNAME] [--os-password PASSWORD]
                 [--password PASSWORD] [--os-project-name PROJECT] [--project PROJECT]
                 [--os-region-name REGION] [--region REGION] [--os-auth-url AUTH_URL]
                 [--auth_url AUTH_URL] [--os-auth-token OS_AUTH_TOKEN] [--insecure]
                 [--os-cert <certification>] [--os-key <key>] [--os-endpoint-type ENDPOINT_TYPE]
                 [--endpoint_type ENDPOINT_TYPE] [--exclude-servers]
                 [--exclude-volumes] [--exclude-keypairs] [--generate-stack-data]
                 [--extract-ports]

    Heat template and data file generator

    optional arguments:
      -h, --help            show this help message and exit.
      --os-username USERNAME
                            A user name with access to the project. Defaults to
                            env[OS_USERNAME].
      --username USERNAME   Deprecated ! Use --os-username.
      --os-password PASSWORD
                            The user's password. Defaults to env[OS_PASSWORD].
      --password PASSWORD   Deprecated ! Use --os-password.
      --os-project-name PROJECT
                            Name of project. Defaults to env[OS_TENANT_NAME].
      --project PROJECT     Deprecated ! Use --os-project-name.
      --os-region-name REGION
                            Name of region. Defaults to env[OS_REGION_NAME]
      --region REGION       Deprecated ! Use --os-region-name.
      --os-auth-url AUTH_URL
                            Authentication URL. Defaults to env[OS_AUTH_URL]
      --auth_url AUTH_URL   Deprecated ! Use --os-auth-url.
      --os-auth-token OS_AUTH_TOKEN
                            User's auth token. Defaults to env[OS_AUTH_TOKEN].
      --os-cert <certificate>
                            Path to user's certificate needed to establish
                            two-way SSL connection with the identity service.
                            Defaults to env[OS_CERT].
      --os-key <key>        Path to the user's certificate private key.
                            Defaults to env[OS_KEY].
      --insecure            Explicitly allow clients to perform"insecure" SSL
                            (https) requests. The server's certificate will not be
                            verified against any certificate authorities. This
                            option should be used with caution.
      --os-endpoint-type ENDPOINT_TYPE
                            Defaults to env[OS_ENDPOINT_TYPE] or publicURL.
      --endpoint_type ENDPOINT_TYPE
                            Deprecated ! Use --os-endpoint-type
      --exclude-servers     Do not export in template server resources.
      --exclude-volumes     Do not export in template volume resources.
      --exclude-keypairs    Do not export in template key pair resources.
      --generate-stack-data
                            In addition to template, generate Heat stack data
                            file.
      --extract-ports       Export the tenant network ports.


Example
-------

To use Flame you can provide yours OpenStack credentials as arguments::

      $ flame --os-username arezmerita --os-password password \
              --os-project-name project-arezmerita --os-auth-url https://example.com/v2.0/

Or a token and a tenant::

      $ flame --os-username arezmerita --os-auth-token keystonetoken \
              --os-project-name project-arezmerita --os-auth-url https://example.com/v2.0/

To establish a two-way SSL connection with the identity service ::

      $flame --os-username arezmerita --os-auth-token keystonetoken \
              --os-project-name project-arezmerita --os-auth-url https://example.com/v2.0/
              --os-cert <path/to/certificate>  --os-key <path/to/key>

Or you can source your OpenStack RC file and use Flame without arguments::

    $ source credential.rc
    $ flame
