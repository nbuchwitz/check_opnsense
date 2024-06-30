#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_opnsense.py - A check plugin for monitoring OPNsense firewalls.
# Copyright (C) 2018  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 0.1.0
#
# ------------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ------------------------------------------------------------------------------

import sys

try:
    from enum import Enum
    import argparse
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)

# Timeout for API requests in seconds
CHECK_API_TIMEOUT = 30


class NagiosState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckOPNsense:
    VERSION = '0.1.0'
    API_URL = 'https://{host}:{port}/api/{uri}'

    options = {}
    perfdata = []
    checkResult = -1
    checkMessage = ""

    def checkOutput(self):
        message = self.checkMessage
        if self.perfdata:
            message += self.getPerfdata()

        self.output(self.checkResult, message)

    def output(self, returnCode, message):
        prefix = returnCode.name

        message = '{} - {}'.format(prefix, message)

        print(message)
        sys.exit(returnCode.value)

    def getURL(self, part):
        return self.API_URL.format(
            host=self.options.hostname,
            port=self.options.port,
            uri=part)

    def request(self, url, method='get', **kwargs):
        response = None
        try:
            if method == 'post':
                response = requests.post(
                    url,
                    verify=not self.options.api_insecure,
                    auth=(self.options.api_key, self.options.api_secret),
                    data=kwargs.get('data', None),
                    timeout=CHECK_API_TIMEOUT,
                )
            elif method == 'get':
                response = requests.get(
                    url,
                    auth=(self.options.api_key, self.options.api_secret),
                    verify=not self.options.api_insecure,
                    params=kwargs.get('params', None),
                    timeout=CHECK_API_TIMEOUT,
                )
            else:
                self.output(NagiosState.CRITICAL, "Unsupport request method: {}".format(method))
        except requests.exceptions.ConnectTimeout:
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Connection timeout")
        except requests.exceptions.SSLError:
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Certificate validation failed")
        except requests.exceptions.ConnectionError as e:
            print(e)
            self.output(NagiosState.UNKNOWN, "Could not connect to OPNsense: Failed to resolve hostname")

        if response.ok:
            return response.json()
        else:
            message = "Could not fetch data from API: "

            if response.status_code == 401:
                message += "Could not connection to OPNsense: invalid username or password"
            elif response.status_code == 403:
                message += "Access denied. Please check if API user has sufficient permissions."
            else:
                message += "HTTP error code was {}".format(response.status_code)

            self.output(NagiosState.UNKNOWN, message)

    def check(self):
        self.checkResult = NagiosState.OK

        if self.options.mode == 'updates':
            self.checkUpdates()
        else:
            message = "Check mode '{}' not known".format(self.options.mode)
            self.output(NagiosState.UNKNOWN, message)

        self.checkOutput()

    def parseOptions(self):
        p = argparse.ArgumentParser(description='Check command OPNsense firewall monitoring')

        api_opts = p.add_argument_group('API Options')

        api_opts.add_argument("-H", "--hostname", required=True, help="OPNsense hostname or ip address")
        api_opts.add_argument("-p", "--port", required=False, dest='port', help="OPNsense https-api port", default=443, type=int)
        api_opts.add_argument("--api-key", dest='api_key', required=True,
                              help="API key (See OPNsense user manager)")
        api_opts.add_argument("--api-secret", dest='api_secret', required=True,
                              help="API key (See OPNsense user manager)")
        api_opts.add_argument("-k", "--insecure", dest='api_insecure', action='store_true', default=False,
                              help="Don't verify HTTPS certificate")

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=('updates',),
                                required=True,
                                help="Mode to use.")
        check_opts.add_argument('-w', '--warning', dest='treshold_warning', type=float,
                                help='Warning treshold for check value')
        check_opts.add_argument('-c', '--critical', dest='treshold_critical', type=float,
                                help='Critical treshold for check value')

        options = p.parse_args()

        self.options = options

    def checkUpdates(self):
        url = self.getURL('core/firmware/status')
        data = self.request(url)

        if data['status'] == 'ok' and data['status_upgrade_action'] == 'all':
            count = data['updates']

            self.checkResult = NagiosState.WARNING
            self.checkMessage = "{} pending updates".format(count)

            if data['upgrade_needs_reboot']:
                self.checkResult = NagiosState.CRITICAL
                self.checkMessage = "{}. Subsequent reboot required.".format(self.checkMessage)
        else:
            self.checkMessage = "System up to date"

    def __init__(self):
        self.parseOptions()

        if self.options.api_insecure:
            # disable urllib3 warning about insecure requests
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


opnsense = CheckOPNsense()
opnsense.check()

