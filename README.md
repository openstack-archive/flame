Flame: Generate Heat Template
============================================

Usage
-----

Available options can be displayed by using `flame.py -h`:

    $python flame.py  --help
    usage: flame.py [-h] [--username USERNAME] [--password PASSWORD]
                    [--project PROJECT] [--auth_url AUTH_URL] [--insecure]
                    [--exclude_servers] [--exclude_volumes]

    Generate Heat Template

    optional arguments:
      -h, --help           show this help message and exit
      --username USERNAME  A user name with access to the project. Defaults to
                           env[OS_USERNAME]
      --password PASSWORD  The user's password. Defaults to env[OS_PASSWORD]
      --project PROJECT    Name of project. Defaults to env[OS_TENANT_NAME]
      --auth_url AUTH_URL  Authentication URL. Defaults to env[OS_AUTH_URL].
      --insecure           Explicitly allow clients to perform "insecure" SSL
                           (https) requests. The server's certificate will not be
                           verified against any certificate authorities. This
                           option should be used with caution.
      --exclude_servers    Do not export in template server resources
      --exclude_volumes    Do not export in template volume resources
      --generate-stack-data
                          In addition to template, generate Heat stack data
                          file


Example
-------

    $ python flame.py --username arezmerita --password password \
    --project project-arezmerita --auth_url https://identity0.cw-labs.net/v2.0/


License / Copyright
-------------------

This software is released under the MIT License.

Copyright (c) 2014 Cloudwatt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
