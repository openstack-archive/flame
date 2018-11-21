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

import logging
from logging.config import dictConfig
import sys


COLOR_LOGS = sys.stdout.isatty()


class CWColorFormatter(logging.Formatter):
    """Special Formatter adding color to logs.

    color is not added if settings.DEBUG is True to prevent syslog cluttering
    when in production.

    This Formatter is just Candy for developers.
    """
    LEVEL_COLORS = {
        logging.NOTSET: '\033[01;0m',     # Reset color
        logging.DEBUG: '\033[00;32m',     # GREEN
        logging.INFO: '\033[00;36m',      # CYAN
        # Where did this one go?:
        # logging.AUDIT: '\033[01;36m',     # BOLD CYAN
        logging.WARN: '\033[01;33m',      # BOLD YELLOW
        logging.ERROR: '\033[01;31m',     # BOLD RED
        logging.CRITICAL: '\033[01;31m',  # BOLD RED
    }

    reset_color = '\033[01;0m'

    def format(self, record):
        if COLOR_LOGS:
            record.reset_color = self.reset_color
            record.color = self.LEVEL_COLORS[record.levelno]
        else:
            # We do not want colors in production because syslog does not
            # handle them.
            record.reset_color = ''
            record.color = ''
        return super(CWColorFormatter, self).format(record)


LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            '()': CWColorFormatter,
            'format': '%(color)s%(levelname)s: %(pathname)s %(funcName)s %(lineno)d:%(reset_color)s %(message)s'  # noqa
        },
    },
    'handlers': {
        'default': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': True
        },
        'flameclient': {
            'handlers': ['default'],
            # This can be overriden in the config's logging section
            'level': 'INFO',
            'propagate': False
        },
    }
}


dictConfig(LOGGING_CONFIG)
