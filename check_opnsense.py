#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_opnsense.py - A check plugin for monitoring OPNsense firewalls.
# Copyright (C) 2018 - 2026  Nicolai Buchwitz <nb@tipi-net.de>
#
# Version: 0.5.0
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

import os
import sys
from typing import Dict, NoReturn, Optional, Sequence, Tuple, Type

try:
    import argparse
    from enum import Enum

    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning

except ImportError as e:
    print(f"Missing python module: {e.msg}")
    sys.exit(255)

# Timeout for API requests in seconds
CHECK_API_TIMEOUT = 30

# Errors raised when an API response does not have the expected shape or content
DATA_ERRORS = (KeyError, IndexError, TypeError, ValueError, ZeroDivisionError)

# Available check modes, filled in by CheckOPNsense.__init_subclass__
CHECKS: Dict[str, Type["CheckOPNsense"]] = {}


class CheckState(Enum):
    """Check return values."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckArgumentParser(argparse.ArgumentParser):
    """Argument parser which reports usage errors as a check result."""

    def error(self, message: str) -> NoReturn:
        """Exit with UNKNOWN, since a usage error says nothing about the firewall."""
        self.print_usage(sys.stderr)
        CheckOPNsense.output(CheckState.UNKNOWN, f"Invalid command line: {message}")
        raise SystemExit(CheckState.UNKNOWN.value)


class CheckOPNsense:
    """Base class for a check mode.

    A subclass declares which endpoint it needs and implements run() to turn
    the response into a result. Fetching, filtering, thresholds, error
    handling and output are provided here, and defining the subclass is
    enough to register the mode with --mode.
    """

    VERSION = "0.5.0"
    API_URL = "https://{host}:{port}/api/{uri}"

    #: Name of the mode as given to --mode
    name = ""
    #: API endpoint the check reads its data from
    endpoint = ""
    #: HTTP method used to read the endpoint
    method = "get"
    #: Warning and critical threshold to use when none are given on the command line
    defaults: Optional[Tuple[float, float]] = None
    #: Reported when the response cannot be read
    data_error = "Unexpected data received from OPNsense API"

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Register a check mode under its name."""
        super().__init_subclass__(**kwargs)

        if cls.name:
            CHECKS[cls.name] = cls

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.perfdata = []
        self.check_result = CheckState.UNKNOWN
        self.check_message = ""
        self.check_details = []
        self.filtered_items = []
        self.counts = {state: 0 for state in CheckState}

        if self.options.api_insecure:
            # disable urllib3 warning about insecure requests
            urllib3.disable_warnings(category=InsecureRequestWarning)

    def check_output(self) -> None:
        """Print check command output with perfdata and return code."""
        if self.options.verbose >= 1 and self.filtered_items:
            self.check_details.append("--- FILTERED ---")
            for item in self.filtered_items:
                self.check_details.append(f"[FILTER] {item} is excluded by --filter")

        message = self.check_message
        if self.perfdata:
            message += self.get_perfdata()
        if self.check_details:
            message += "\n" + self.get_check_details()

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

    def fetch(self, uri: str, method: str = "get") -> Optional[Dict]:
        """Fetch the json data of an API endpoint."""
        return self.request(self.get_url(uri), method)

    def request(
        self,
        url: str,
        method: str = "get",
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Execute request against OPNsense API and return json data."""
        try:
            if method == "post":
                response = requests.post(
                    url,
                    verify=not self.options.api_insecure,
                    auth=(self.options.api_key, self.options.api_secret),
                    data=data,
                    timeout=CHECK_API_TIMEOUT,
                )
            elif method == "get":
                response = requests.get(
                    url,
                    auth=(self.options.api_key, self.options.api_secret),
                    verify=not self.options.api_insecure,
                    params=params,
                    timeout=CHECK_API_TIMEOUT,
                )
            else:
                self.output(CheckState.UNKNOWN, f"Unsupported request method: {method}")
        except requests.exceptions.SSLError:
            self.output(
                CheckState.UNKNOWN, "Could not connect to OPNsense: Certificate validation failed"
            )
        except requests.exceptions.Timeout:
            self.output(CheckState.UNKNOWN, "Could not connect to OPNsense: Connection timeout")
        except requests.exceptions.ConnectionError:
            self.output(CheckState.UNKNOWN, "Could not connect to OPNsense: Connection failed")
        except requests.exceptions.RequestException as e:
            self.output(CheckState.UNKNOWN, f"Could not connect to OPNsense: {e}")

        if response.ok:
            try:
                return response.json()
            except ValueError:
                self.output(
                    CheckState.UNKNOWN, "Could not fetch data from API: response is not valid JSON"
                )

        message = "Could not fetch data from API: "

        if response.status_code == 401:
            message += "invalid API key or secret"
        elif response.status_code == 403:
            message += "Access denied. Please check if API user has sufficient permissions."
        else:
            message += f"HTTP error code was {response.status_code}"

        self.output(CheckState.UNKNOWN, message)

    @property
    def num_items(self) -> int:
        """Number of items recorded so far."""
        return sum(self.counts.values())

    def add(self, state: CheckState, detail: str) -> None:
        """Record the state of a single item and raise the overall result to match."""
        self.counts[state] += 1
        self.check_details.append(f"[{state.name}] {detail}")

        if state.value > self.check_result.value:
            self.check_result = state

    def filtered(self, *names: str) -> bool:
        """Tell whether an item is excluded via --filter, remembering it if it is."""
        if not any(name in self.options.filter for name in names):
            return False

        self.filtered_items.append(names[0])
        return True

    def thresholds(self) -> Tuple[float, float]:
        """Get the configured thresholds, falling back to the check specific defaults."""
        warning, critical = self.defaults
        configured_warning = self.options.threshold_warning
        configured_critical = self.options.threshold_critical

        return (
            warning if configured_warning is None else configured_warning,
            critical if configured_critical is None else configured_critical,
        )

    @staticmethod
    def evaluate(value: float, warning: float, critical: float) -> CheckState:
        """Map a measured value to a check state."""
        if value >= critical:
            return CheckState.CRITICAL
        if value >= warning:
            return CheckState.WARNING

        return CheckState.OK

    @staticmethod
    def activity_header(data: Dict, marker: str) -> str:
        """Get the top(1) style header line containing a marker."""
        return next((line for line in data["headers"] if marker in line), "")

    def get_perfdata(self) -> str:
        """Get perfdata string."""
        perfdata = ""

        if self.perfdata:
            perfdata = " | "
            perfdata += " ".join(self.perfdata)

        return perfdata

    def get_check_details(self) -> str:
        """Get the detail messages as string."""
        details = ""
        for detail in self.check_details:
            details += f"{detail}\n"

        return details

    def run(self, data: Dict) -> None:
        """Turn the API response into a check result."""
        raise NotImplementedError

    def check(self) -> None:
        """Execute the real check command."""
        self.check_result = CheckState.OK

        self.options.filter = [
            item.strip() for item in self.options.filter.split(",") if item.strip()
        ]

        try:
            self.run(self.fetch(self.endpoint, self.method))
        except DATA_ERRORS as e:
            self.output(CheckState.UNKNOWN, f"{self.data_error} ({e})")

        self.check_output()


class UpdatesCheck(CheckOPNsense):
    """Check opnsense for system updates."""

    name = "updates"
    endpoint = "core/firmware/status"

    def run(self, data: Dict) -> None:
        """Evaluate the firmware status response."""
        if data["status"] in ("none", "error"):
            # no update information available -> trigger check
            data = self.fetch(self.endpoint, method="post")

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


class IPsecCheck(CheckOPNsense):
    """Check IPsec tunnel status."""

    name = "ipsec"
    endpoint = "ipsec/sessions/search_phase1"

    def run(self, data: Dict) -> None:
        """Evaluate the IPsec session response."""
        data = self.fetch("ipsec/sessions/search_phase1")
        tunnels_connected = []
        tunnels_disconnected = []

        for row in data["rows"]:
            desc = row["phase1desc"]
            if self.filtered(desc):
                continue

            if row["connected"]:
                tunnels_connected.append(desc)
            else:
                tunnels_disconnected.append(desc)

        if tunnels_disconnected:
            self.check_result = CheckState.WARNING
            self.check_message = "IPsec tunnels not connected: " + ", ".join(tunnels_disconnected)
        elif tunnels_connected:
            self.check_message = "IPsec tunnels connected: " + ", ".join(tunnels_connected)
        else:
            self.check_message = "No IPsec tunnels configured"

        self.perfdata.append(f"tunnels_connected={len(tunnels_connected)}")
        self.perfdata.append(f"tunnels_disconnected={len(tunnels_disconnected)}")


class InterfacesCheck(CheckOPNsense):
    """Check physical interface status."""

    name = "interfaces"
    endpoint = "interfaces/overview/interfaces_info"

    def run(self, data: Dict) -> None:
        """Evaluate the interface response."""
        for row in data["rows"]:
            device = row.get("device", None)
            if self.filtered(device):
                continue

            if not row.get("enabled", False):
                continue

            if row.get("status", "Down") == "up":
                self.add(CheckState.OK, f"interface {device} is up")
            else:
                self.add(CheckState.CRITICAL, f"interface {device} is down")

        interfaces_up = self.counts[CheckState.OK]
        interfaces_down = self.counts[CheckState.CRITICAL]

        if interfaces_down:
            self.check_message = f"{interfaces_down} interface(s) are down"
        elif interfaces_up:
            self.check_message = f"{interfaces_up} interface(s) are up"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "No interfaces found"

        self.perfdata.append(f"interfaces_up={interfaces_up}")
        self.perfdata.append(f"interfaces_down={interfaces_down}")


class ServicesCheck(CheckOPNsense):
    """Check all configured services status via core/service/search."""

    name = "services"
    endpoint = "core/service/search"
    method = "post"
    data_error = "Could not retrieve services list from API."

    def run(self, data: Dict) -> None:
        """Evaluate the service response."""
        running_services = []
        stopped_services = []

        for row in data["rows"]:
            service_id = str(row.get("id", ""))
            name = str(row.get("name", ""))
            desc = str(row.get("description", name))
            is_running = row.get("running", 0) == 1

            if self.filtered(f"{desc} ({service_id})", service_id, name):
                continue

            if is_running:
                running_services.append(f"{desc} ({service_id})")
            else:
                stopped_services.append(f"{desc} ({service_id})")

        # Performance Data
        self.perfdata.append(f"services_running={len(running_services)}")
        self.perfdata.append(f"services_stopped={len(stopped_services)}")

        if stopped_services:
            self.check_result = CheckState.CRITICAL
            self.check_message = (
                f"{len(stopped_services)} service(s) stopped: {', '.join(stopped_services)}"
            )
        elif running_services:
            self.check_result = CheckState.OK
            self.check_message = f"All {len(running_services)} configured service(s) are running."
        else:
            self.check_result = CheckState.OK
            self.check_message = "No active services found."

        if self.options.verbose < 1:
            return

        if running_services:
            self.check_message += "\n\n--- RUNNING SERVICES ---\n"
            for service in running_services:
                self.check_message += f"[RUNNING] {service}\n"


class WireGuardCheck(CheckOPNsense):
    """Check WireGuard tunnel status."""

    name = "wireguard"
    endpoint = "wireguard/service/show"

    def run(self, data: Dict) -> None:
        """Evaluate the WireGuard response."""
        for wgs in data["rows"]:
            if wgs.get("type", "peer") != "peer":
                continue

            name = wgs.get("name", "unknown")
            if self.filtered(name):
                continue

            endpoint = wgs.get("endpoint", "unknown")
            if wgs.get("peer-status", "offline") == "online":
                self.add(CheckState.OK, f"Peer {name} is online ({endpoint})")
            else:
                self.add(CheckState.CRITICAL, f"Peer {name} is offline ({endpoint})")

        online = self.counts[CheckState.OK]
        offline = self.counts[CheckState.CRITICAL]

        if offline:
            self.check_message = f"{offline}/{self.num_items} WireGuard peers are offline"
        elif online:
            self.check_message = f"{online}/{self.num_items} WireGuard peers are online"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "No WireGuard peers found"

        self.perfdata.append(f"peers_online={online}")
        self.perfdata.append(f"peers_offline={offline}")


class DiskCheck(CheckOPNsense):
    """Check available disk space."""

    name = "disk"
    endpoint = "diagnostics/system/system_disk"
    defaults = (80.0, 90.0)
    data_error = "No disk data received."

    def run(self, data: Dict) -> None:
        """Evaluate the disk usage response."""
        # Response is of this type:
        # {
        #     "devices": [
        #         {
        #             "device": "\/dev\/gpt\/rootfs",
        #             "type": "ufs",
        #             "blocks": "222G",
        #             "used": "3.9G",
        #             "available": "201G",
        #             "used_pct": 2,
        #             "mountpoint": "\/"
        #         }
        #     ]
        # }

        warn, crit = self.thresholds()

        for dev in data.get("devices", []):
            mountpoint = dev["mountpoint"]
            if self.filtered(mountpoint):
                continue

            free_space = dev["available"]
            total_space = dev["blocks"]
            used_pct = dev["used_pct"]
            available_pct = 100 - float(used_pct)

            state = self.evaluate(used_pct, warn, crit)
            qualifier = "" if state is CheckState.OK else "only "
            self.add(
                state,
                f"{mountpoint} has {qualifier}{free_space} of {total_space}"
                f" ({available_pct}%) free disk space",
            )

            # Performance data
            self.perfdata.append(f"{mountpoint}={used_pct}%;{warn};{crit};0;100")

        num_critical = self.counts[CheckState.CRITICAL]
        num_warning = self.counts[CheckState.WARNING]

        if num_critical:
            self.check_message = f"Disk space is critically low on {num_critical} disk(s)"
        elif num_warning:
            self.check_message = f"Disk space is low on {num_warning} disk(s)"
        elif self.num_items:
            self.check_message = "Disk space is ok"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "No disks found"


class MemoryCheck(CheckOPNsense):
    """Check memory usage."""

    name = "memory"
    endpoint = "diagnostics/system/system_resources"
    defaults = (80.0, 90.0)
    data_error = "No memory data received."

    def run(self, data: Dict) -> None:
        """Evaluate the memory usage response."""
        warn, crit = self.thresholds()

        memory = data["memory"]
        total_mem = int(memory.get("total_frmt"))
        used_mem = int(memory.get("used_frmt"))

        # Check if the system uses ARC (ZFS Cache) and substract it from used memory
        # since it is filesystem cache that can be cleared by the system to regain space
        arc_mem = int(memory.get("arc_frmt") or 0)
        used_mem = used_mem - arc_mem

        used_pct = round(float(used_mem / total_mem * 100), 1)

        self.perfdata.append(f"memory={used_pct}%;{warn};{crit};0;100;")
        if arc_mem > 0:
            self.perfdata.append(f"arc_size={arc_mem}MB;")
            self.check_details.append(f"Additional memory used for ARC: {arc_mem}MB")

        self.check_result = self.evaluate(used_pct, warn, crit)
        self.check_message = f"Memory usage is {used_pct}%"


class SwapCheck(CheckOPNsense):
    """Check swap usage."""

    name = "swap"
    endpoint = "diagnostics/system/system_swap"
    defaults = (80.0, 90.0)
    data_error = "No swap data received."

    def run(self, data: Dict) -> None:
        """Evaluate the swap usage response."""
        warn, crit = self.thresholds()

        num_devs = 0
        total_swap = 0
        total_used_swap = 0
        total_used_pct = 0

        for dev in data.get("swap", []):
            swap_device = dev.get("device")
            if self.filtered(swap_device):
                continue

            num_devs += 1
            swap = int(dev.get("total"))
            total_swap += swap

            used_swap = int(dev.get("used"))
            total_used_swap += used_swap

            used_pct = round(float(used_swap / swap * 100), 1)

            self.check_details.append(f"Swap usage on {swap_device} is {used_pct}%")
            # Performance data
            self.perfdata.append(f"{swap_device}={used_pct}%;{warn};{crit};0;100")

        if num_devs > 0:
            total_used_pct = round(float(total_used_swap / total_swap * 100), 1)

        if num_devs == 0:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "No swap found"
            return

        self.check_result = self.evaluate(total_used_pct, warn, crit)
        self.check_message = f"Total swap usage is {total_used_pct}%"


class CPUCheck(CheckOPNsense):
    """Check CPU usage."""

    name = "cpu"
    endpoint = "diagnostics/activity/get_activity"
    defaults = (80.0, 90.0)
    data_error = "No CPU usage data received."

    def run(self, data: Dict) -> None:
        """Evaluate the CPU activity response."""
        warn, crit = self.thresholds()

        # "CPU:  0.0% user,  0.0% nice,  0.4% system,  0.0% interrupt, 99.6% idle"
        tokens = self.activity_header(data, "CPU:").replace(",", " ").split()
        idle_pct = float(tokens[tokens.index("idle") - 1].strip("%"))
        used_pct = round(100.0 - idle_pct, 1)

        self.perfdata.append(f"cpu_usage={used_pct}%;{warn};{crit};0;100")

        self.check_result = self.evaluate(used_pct, warn, crit)
        self.check_message = f"CPU usage is {used_pct}%"


class LoadCheck(CheckOPNsense):
    """Check load."""

    name = "load"
    endpoint = "diagnostics/activity/get_activity"
    defaults = (3.0, 4.0)
    data_error = "No load data received."

    def run(self, data: Dict) -> None:
        """Evaluate the load average response."""
        warn, crit = self.thresholds()

        # "last pid: 24927;  load averages:  2.06,  0.74,  0.29  up 0+00:00:52    08:44:18"
        marker = "load averages:"
        averages = self.activity_header(data, marker).split(marker)[1].split()
        loads = {
            "load1": float(averages[0].strip(",")),
            "load5": float(averages[1].strip(",")),
            "load15": float(averages[2].strip(",")),
        }

        for name, value in loads.items():
            self.add(self.evaluate(value, warn, crit), f"{name} is {value}")
            self.perfdata.append(f"{name}={value};{warn};{crit};0;")

        if self.counts[CheckState.CRITICAL]:
            self.check_message = "Load is critical."
        elif self.counts[CheckState.WARNING]:
            self.check_message = "Load is warning."
        else:
            self.check_message = "Load is ok."


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    p = CheckArgumentParser(description="Check command OPNsense firewall monitoring")

    api_opts = p.add_argument_group("API Options")

    api_opts.add_argument("-H", "--hostname", required=True, help="OPNsense hostname or ip address")
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
        "--api-key",
        dest="api_key",
        default=os.environ.get("OPNSENSE_API_KEY"),
        help="API key (See OPNsense user manager), defaults to $OPNSENSE_API_KEY",
    )
    api_opts.add_argument(
        "--api-secret",
        dest="api_secret",
        default=os.environ.get("OPNSENSE_API_SECRET"),
        help="API secret (See OPNsense user manager), defaults to $OPNSENSE_API_SECRET",
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
        choices=tuple(CHECKS),
        required=True,
        help="Mode to use.",
    )
    check_opts.add_argument(
        "-w",
        "--warning",
        dest="threshold_warning",
        type=float,
        help="Warning threshold for check value",
    )
    check_opts.add_argument(
        "-c",
        "--critical",
        dest="threshold_critical",
        type=float,
        help="Critical threshold for check value",
    )
    check_opts.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Show additional details, e.g. the items excluded by --filter",
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

    options = p.parse_args(argv)

    # Credentials may come from the environment instead, to keep them out of the process list
    for option, variable in (
        ("api_key", "OPNSENSE_API_KEY"),
        ("api_secret", "OPNSENSE_API_SECRET"),
    ):
        if not getattr(options, option):
            flag = option.replace("_", "-")
            p.error(f"--{flag} is required unless {variable} is set")

    return options


def main() -> None:
    """Run the check command."""
    try:
        options = parse_args()
        CHECKS[options.mode](options).check()
    except Exception as e:  # a check plugin must never exit with a traceback
        CheckOPNsense.output(CheckState.UNKNOWN, f"Unhandled error: {e}")


if __name__ == "__main__":
    main()
