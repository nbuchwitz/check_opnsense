#!/usr/bin/env python3
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
        print(f"[{prefix}] {message}")
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
        elif self.options.mode == "interfaces":
            self.check_interfaces()
        elif self.options.mode == "services":
            self.check_services()
        elif self.options.mode == "wireguard":
            self.check_wireguard()
        else:
            message = f"Check mode '{self.options.mode}' not known"
            self.output(CheckState.UNKNOWN, message)

        if self.options.filter:
            self.options.filter = self.options.filter.split(",")
        else:
            self.options.filter = []

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
            choices=("updates", "ipsec", "interfaces", "services", "wireguard"),
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
        check_opts.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=0,
            help="Enable verbose Output max -vvv",
            required=False,
        )
        check_opts.add_argument(
            "-f",
            "--filter",
            type=str,
            default="",
            help=(
                "String that can be used in multiple modes to exclude unwanted items "
                "from the output or exit code calculation. Example: 'Disk 1, Disk 2'."
            ),
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

    def check_interfaces(self) -> None:
        """Check physical interface status."""
        url = self.get_url("interfaces/overview/interfaces_info")
        data = self.request(url)

        interfaces_up = []
        interfaces_down = []
        interfaces_filtered = []

        for row in data["rows"]:
            device = row.get("device", None)
            enabled = row.get("enabled", False)
            status = row.get("status", "Down")
            if device not in self.options.filter:
                if enabled:
                    if status == "up":
                        self.check_result = CheckState.OK
                        interfaces_up.append(device)
                    else:
                        self.check_result = CheckState.CRITICAL
                        interfaces_down.append(device)
            else:
                interfaces_filtered.append(device)
        if interfaces_down:
            counter = len(interfaces_down)
            self.check_message = f"{counter} interface(s) are down\n"
            self.check_message += "\n".join(interfaces_down)
        elif interfaces_up:
            counter = len(interfaces_up)
            self.check_message = f"{counter} interface(s) are up\n"

        for i in interfaces_down:
            self.check_message += f"[DOWN] interface {i} is down\n"

        for i in interfaces_up:
            self.check_message += f"[UP] interface {i} is up\n"

        if self.options.verbose >= 1:
            self.check_message += "\n--- VERBOSE ---\n"
            for i in interfaces_filtered:
                self.check_message += f"[FILTER] interface {i} is filtered by --filter\n"

    def check_services(self) -> None:
        """Check services status."""
        list_of_services = [
            "dhcpv4",
            "dhcpv6",
            "ids",
            "kea",
            "syslog",
            "unbound",
        ]

        running_services = []
        failed_services = []
        disabled_services = []
        filtered_services = []
        for i in list_of_services:
            if i not in self.options.filter:
                url = self.get_url(f"{i}/service/status")
                data = self.request(url)

                status = data.get("status", "disabled")
                if status != "disabled":
                    if status == "running":
                        running_services.append(i)
                    else:
                        failed_services.append(i)
                else:
                    disabled_services.append(i)
            else:
                filtered_services.append(i)

        if failed_services:
            counter = len(failed_services)
            self.check_message = f"{counter} services have failed\n"
            self.check_result = CheckState.CRITICAL
        elif running_services:
            counter = len(running_services)
            self.check_message = f"{counter} services are running\n"
            self.check_result = CheckState.OK

        for i in failed_services:
            self.check_message += f"[CRITICAL] Service {i} has failed\n"
        for i in running_services:
            self.check_message += f"[OK] Service {i} is running\n"
        if self.options.verbose >= 1:
            self.check_message += "\n--- VERBOSE ---\n"
            for i in filtered_services:
                self.check_message += f"[FILTER] Service {i} is filtered by --filter\n"
            for i in disabled_services:
                self.check_message += f"[OK] Service {i} is disabled\n"

    def check_wireguard(self) -> None:
        """Check WireGuard tunnel status."""
        url = self.get_url("wireguard/service/show")
        data = self.request(url)

        online = []
        offline = []
        filtered = []

        for wgs in data["rows"]:
            peer_status = wgs.get("peer-status", "offline")
            name = wgs.get("name", "unknown")
            endpoint = wgs.get("endpoint", "unknown")

            if name not in self.options.filter:
                if peer_status == "online":
                    online.append(f"[OK] Peer {name} is online ({endpoint})")
                else:
                    offline.append(f"[CRITICAL] Peer {name} is offline ({endpoint})")
            else:
                filtered.append(name)

        counter_on = len(online)
        counter_off = len(offline)

        counter_sum = counter_off + counter_on

        if offline:
            self.check_message = f"{counter_off}/{counter_sum} WireGuard peers are offline\n"
            self.check_result = CheckState.CRITICAL
        elif online:
            self.check_message = f"{counter_on}/{counter_sum} WireGuard peers are online\n"
            self.check_result = CheckState.OK

        for i in offline:
            self.check_message += f"{i}\n"
        for i in online:
            self.check_message += f"{i}\n"
        if self.options.verbose >= 1:
            self.check_message += "\n--- VERBOSE ---\n"
            for i in filtered:
                self.check_message += f"[FILTER] Peer {i} is filtered by --filter\n"

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
