#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_opnsense.py - A check plugin for monitoring OPNsense firewalls.
# Copyright (C) 2018 - 2025  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 0.3.0
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

"""OPNsense monitoring check command for various monitoring systems like Icinga and others."""

import sys
from typing import Dict, Union

try:
    import argparse
    from enum import Enum

    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

except ImportError as e:
    print(f"Missing python module: {e.msg}")
    sys.exit(255)

# Timeout for API requests in seconds
CHECK_API_TIMEOUT = 30


class CheckState(Enum):
    """Check return values."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckOPNsense:
    """Check command for OPNsense."""

    VERSION = "0.3.0"
    API_URL = "https://{host}:{port}/api/{uri}"

    def check_output(self) -> None:
        """Print check command output with perfdata and return code."""
        message = self.check_message
        if self.perfdata:
            message += self.get_perfdata()

        self.output(self.check_result, message)

    @staticmethod
    def output(rc: CheckState, message: str) -> None:
        """Print message to stdout and exit with given return code."""
        prefix = rc.name
        print(f"{prefix} - {message}")
        sys.exit(rc.value)

    def get_url(self, command: str) -> str:
        """Get API url for specific command."""
        return self.API_URL.format(host=self.options.hostname, port=self.options.port, uri=command)

    def request(self, url: str, method: str = "get", **kwargs: Dict) -> Union[Dict, None]:
        """Execute request against OPNsense API and return json data."""
        response = None
        try:
            if method == "post":
                response = requests.post(
                    url,
                    verify=not self.options.api_insecure,
                    auth=(self.options.api_key, self.options.api_secret),
                    data=kwargs.get("data", None),
                    timeout=CHECK_API_TIMEOUT,
                )
            elif method == "get":
                response = requests.get(
                    url,
                    auth=(self.options.api_key, self.options.api_secret),
                    verify=not self.options.api_insecure,
                    params=kwargs.get("params", None),
                    timeout=CHECK_API_TIMEOUT,
                )
            else:
                self.output(CheckState.CRITICAL, f"Unsupport request method: {method}")
        except requests.exceptions.ConnectTimeout:
            self.output(CheckState.UNKNOWN, "Could not connect to OPNsense: Connection timeout")
        except requests.exceptions.SSLError:
            self.output(
                CheckState.UNKNOWN, "Could not connect to OPNsense: Certificate validation failed"
            )
        except requests.exceptions.ConnectionError:
            self.output(
                CheckState.UNKNOWN, "Could not connect to OPNsense: Failed to resolve hostname"
            )

        if response.ok:
            return response.json()

        message = "Could not fetch data from API: "

        if response.status_code == 401:
            message += "Could not connection to OPNsense: invalid username or password"
        elif response.status_code == 403:
            message += "Access denied. Please check if API user has sufficient permissions."
        else:
            message += f"HTTP error code was {response.status_code}"

        self.output(CheckState.UNKNOWN, message)
        return {}

    def get_perfdata(self) -> str:
        """Get perfdata string."""
        perfdata = ""

        if self.perfdata:
            perfdata = "|"
            perfdata += " ".join(self.perfdata)

        return perfdata

    def check(self) -> None:
        """Execute the real check command."""
        self.check_result = CheckState.OK

        if self.options.mode == "updates":
            self.check_updates()
        elif self.options.mode == "ipsec":
            self.check_ipsec()
        else:
            message = f"Check mode '{self.options.mode}' not known"
            self.output(CheckState.UNKNOWN, message)

        self.check_output()

    def parse_args(self) -> None:
        """Parse CLI arguments."""
        p = argparse.ArgumentParser(description="Check command OPNsense firewall monitoring")

        api_opts = p.add_argument_group("API Options")

        api_opts.add_argument(
            "-H", "--hostname", required=True, help="OPNsense hostname or ip address"
        )
        api_opts.add_argument(
            "-p",
            "--port",
            required=False,
            dest="port",
            help="OPNsense https-api port",
            default=443,
            type=int,
        )
        api_opts.add_argument(
            "--api-key", dest="api_key", required=True, help="API key (See OPNsense user manager)"
        )
        api_opts.add_argument(
            "--api-secret",
            dest="api_secret",
            required=True,
            help="API key (See OPNsense user manager)",
        )
        api_opts.add_argument(
            "-k",
            "--insecure",
            dest="api_insecure",
            action="store_true",
            default=False,
            help="Don't verify HTTPS certificate",
        )

        check_opts = p.add_argument_group("Check Options")

        check_opts.add_argument(
            "-m",
            "--mode",
            choices=(
                "updates",
                "ipsec",
            ),
            required=True,
            help="Mode to use.",
        )
        check_opts.add_argument(
            "-w",
            "--warning",
            dest="treshold_warning",
            type=float,
            help="Warning treshold for check value",
        )
        check_opts.add_argument(
            "-c",
            "--critical",
            dest="treshold_critical",
            type=float,
            help="Critical treshold for check value",
        )

        options = p.parse_args()

        self.options = options

    def check_updates(self) -> None:
        """Check opnsense for system updates."""
        url = self.get_url("core/firmware/status")
        data = self.request(url)

        if data["status"] in ("none", "error"):
            # no update information available -> trigger check
            data = self.request(url, method="post")

        has_update = data["status"] in ("update", "upgrade")
        needs_reboot = data.get("status_reboot", 0) == "1"

        if has_update:
            self.check_result = CheckState.WARNING
            self.check_message = data["status_msg"]

            if needs_reboot:
                self.check_result = CheckState.CRITICAL
        else:
            self.check_message = "System up to date"

        # Performance data
        upgrade_packages = len(data["upgrade_packages"])
        reinstall_packages = len(data["reinstall_packages"])
        remove_packages = len(data["remove_packages"])
        available_updates = upgrade_packages + reinstall_packages + remove_packages
        self.perfdata.append(f"upgrade_packages={upgrade_packages}")
        self.perfdata.append(f"reinstall_packages={reinstall_packages}")
        self.perfdata.append(f"remove_packages={remove_packages}")
        self.perfdata.append(f"available_updates={available_updates}")

    def check_ipsec(self) -> None:
        """Check IPsec tunnel status."""
        url = self.get_url("ipsec/sessions/search_phase1")
        data = self.request(url)
        tunnels_connected = []
        tunnels_disconnected = []

        for row in data["rows"]:
            if not row["connected"]:
                self.check_result = CheckState.WARNING
                tunnels_disconnected.append(row["phase1desc"])
            if row["connected"]:
                tunnels_connected.append(row["phase1desc"])

        if tunnels_disconnected:
            self.check_message = "IPsec tunnels not connected: "
            self.check_message += ", ".join(tunnels_disconnected)
        elif tunnels_connected:
            self.check_message = "IPsec tunnels connected: "
            self.check_message += ", ".join(tunnels_connected)
        else:
            self.check_message = "No IPsec tunnels configured"

        self.perfdata.append(f"tunnels_connected={len(tunnels_connected)}")
        self.perfdata.append(f"tunnels_disconnected={len(tunnels_disconnected)}")

    def __init__(self) -> None:
        self.options = {}
        self.perfdata = []
        self.check_result = CheckState.UNKNOWN
        self.check_message = ""

        self.parse_args()

        if self.options.api_insecure:
            # disable urllib3 warning about insecure requests
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


opnsense = CheckOPNsense()
opnsense.check()
