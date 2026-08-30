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

import sys
from typing import Dict, NoReturn, Optional, Sequence, Tuple

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

# Available check modes, each implemented by a CheckOPNsense.check_<mode> method
CHECK_MODES = (
    "updates",
    "ipsec",
    "interfaces",
    "services",
    "wireguard",
    "disk",
    "memory",
    "swap",
    "cpu",
    "load",
)


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
    """Check command for OPNsense."""

    VERSION = "0.5.0"
    API_URL = "https://{host}:{port}/api/{uri}"

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
        response = None
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
        return {}

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

    def thresholds(self, warning: float, critical: float) -> Tuple[float, float]:
        """Get the configured thresholds, falling back to the check specific defaults."""
        configured_warning = self.options.treshold_warning
        configured_critical = self.options.treshold_critical

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

    def check(self) -> None:
        """Execute the real check command."""
        self.check_result = CheckState.OK

        self.options.filter = [
            item.strip() for item in self.options.filter.split(",") if item.strip()
        ]

        handler = getattr(self, f"check_{self.options.mode}", None)
        if handler is None:
            self.output(CheckState.UNKNOWN, f"Check mode '{self.options.mode}' not implemented")

        try:
            handler()
        except DATA_ERRORS as e:
            self.output(CheckState.UNKNOWN, f"Unexpected data received from OPNsense API: {e}")

        self.check_output()

    def check_updates(self) -> None:
        """Check opnsense for system updates."""
        data = self.fetch("core/firmware/status")

        if data["status"] in ("none", "error"):
            # no update information available -> trigger check
            data = self.fetch("core/firmware/status", method="post")

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

    def check_interfaces(self) -> None:
        """Check physical interface status."""
        data = self.fetch("interfaces/overview/interfaces_info")

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

    def check_services(self) -> None:
        """Check all configured services status via core/service/search."""
        data = self.fetch("core/service/search", method="post")

        if not data or "rows" not in data:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not retrieve services list from API."
            return

        running_services = []
        stopped_services = []

        for row in data.get("rows", []):
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

    def check_wireguard(self) -> None:
        """Check WireGuard tunnel status."""
        data = self.fetch("wireguard/service/show")

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

    def check_disk(self) -> None:
        """Check available disk space."""
        data = self.fetch("diagnostics/system/system_disk")

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

        warn, crit = self.thresholds(80.0, 90.0)

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

    def check_memory(self) -> None:
        """Check memory usage."""
        data = self.fetch("diagnostics/system/system_resources")

        warn, crit = self.thresholds(80.0, 90.0)

        try:
            memory = data["memory"]
            total_mem = int(memory.get("total_frmt"))
            used_mem = int(memory.get("used_frmt"))

            # Check if the system uses ARC (ZFS Cache) and substract it from used memory
            # since it is filesystem cache that can be cleared by the system to regain space
            arc_mem = int(memory.get("arc_frmt") or 0)
            used_mem = used_mem - arc_mem

            used_pct = round(float(used_mem / total_mem * 100), 1)
        except DATA_ERRORS as e:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"No memory data received. ({e})"
            return

        self.perfdata.append(f"memory={used_pct}%;{warn};{crit};0;100;")
        if arc_mem > 0:
            self.perfdata.append(f"arc_size={arc_mem}MB;")
            self.check_details.append(f"Additional memory used for ARC: {arc_mem}MB")

        self.check_result = self.evaluate(used_pct, warn, crit)
        self.check_message = f"Memory usage is {used_pct}%"

    def check_swap(self) -> None:
        """Check swap usage."""
        data = self.fetch("diagnostics/system/system_swap")

        warn, crit = self.thresholds(80.0, 90.0)

        num_devs = 0
        total_swap = 0
        total_used_swap = 0
        total_used_pct = 0

        try:
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

        except DATA_ERRORS as e:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"No swap data received. ({e})"
            return

        if num_devs == 0:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "No swap found"
            return

        self.check_result = self.evaluate(total_used_pct, warn, crit)
        self.check_message = f"Total swap usage is {total_used_pct}%"

    def check_cpu(self) -> None:
        """Check CPU usage."""
        data = self.fetch("diagnostics/activity/get_activity")

        warn, crit = self.thresholds(80.0, 90.0)

        # Returned data looks something like this, we want CPU idle percentage in this case:
        #
        # "headers": [
        #  "last pid: 24927;  load averages:  2.06,  0.74,  0.29  up 0+00:00:52    08:44:18",
        #  "147 threads:   2 running, 123 sleeping, 22 waiting",
        #  "CPU:  0.0% user,  0.0% nice,  0.4% system,  0.0% interrupt, 99.6% idle",
        #  "Mem: 159M Active, 117M Inact, 212M Wired, 103M Buf, 471M Free",
        #  "Swap: 7674M Total, 7674M Free"
        # ],

        try:
            idle_pct = float(data["headers"][2].split()[9].strip("%"))
            used_pct = round(100.0 - idle_pct, 1)
        except DATA_ERRORS as e:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"No CPU usage data received. ({e})"
            return

        self.perfdata.append(f"cpu_usage={used_pct}%;{warn};{crit};0;100")

        self.check_result = self.evaluate(used_pct, warn, crit)
        self.check_message = f"CPU usage is {used_pct}%"

    def check_load(self) -> None:
        """Check load."""
        data = self.fetch("diagnostics/activity/get_activity")

        warn, crit = self.thresholds(3.0, 4.0)

        try:
            averages = data["headers"][0].split()
            loads = {
                "load1": float(averages[5].strip(",")),
                "load5": float(averages[6].strip(",")),
                "load15": float(averages[7].strip(",")),
            }
        except DATA_ERRORS as e:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"No load data received. ({e})"
            return

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
        choices=CHECK_MODES,
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

    return p.parse_args(argv)


def main() -> None:
    """Run the check command."""
    try:
        CheckOPNsense(parse_args()).check()
    except Exception as e:  # a check plugin must never exit with a traceback
        CheckOPNsense.output(CheckState.UNKNOWN, f"Unhandled error: {e}")


if __name__ == "__main__":
    main()
