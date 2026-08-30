"""Tests for the check modes covering interfaces, services and tunnels."""

import api_responses as api

from check_opnsense import CheckState


class TestInterfaces:
    """Physical interface check."""

    def test_all_up(self, run_check):
        result = run_check("interfaces", api.interfaces(api.interface("em0")))

        assert result.state is CheckState.OK
        assert "1 interface(s) are up" in result.message
        assert "interfaces_up=1" in result.perfdata
        assert "interfaces_down=0" in result.perfdata

    def test_down_interface_is_critical(self, run_check):
        result = run_check("interfaces", api.interfaces(api.interface("em0", status="down")))

        assert result.state is CheckState.CRITICAL
        assert "1 interface(s) are down" in result.message

    def test_down_interface_is_not_masked_by_later_up_interface(self, run_check):
        """The result must not depend on the order the API returns interfaces in."""
        result = run_check(
            "interfaces",
            api.interfaces(
                api.interface("em0", status="down"),
                api.interface("em1", status="up"),
            ),
        )

        assert result.state is CheckState.CRITICAL

    def test_disabled_interfaces_are_ignored(self, run_check):
        result = run_check(
            "interfaces",
            api.interfaces(
                api.interface("em0"),
                api.interface("em1", status="down", enabled=False),
            ),
        )

        assert result.state is CheckState.OK

    def test_no_interfaces_is_unknown(self, run_check):
        """An empty interface list means the API told us nothing, not that all is well."""
        result = run_check("interfaces", api.interfaces())

        assert result.state is CheckState.UNKNOWN
        assert "No interfaces found" in result.message

    def test_all_interfaces_filtered_is_unknown(self, run_check):
        result = run_check("interfaces", api.interfaces(api.interface("em0")), "-f", "em0")

        assert result.state is CheckState.UNKNOWN
        assert "No interfaces found" in result.message

    def test_down_interface_is_listed_once(self, run_check):
        result = run_check("interfaces", api.interfaces(api.interface("em0", status="down")))

        assert result.output.count("em0") == 1

    def test_filtered_interface_is_ignored(self, run_check):
        result = run_check(
            "interfaces",
            api.interfaces(
                api.interface("em0"),
                api.interface("em1", status="down"),
            ),
            "-f",
            "em1",
        )

        assert result.state is CheckState.OK


class TestServices:
    """Service check."""

    def test_all_running(self, run_check):
        result = run_check("services", api.services(api.service("unbound")))

        assert result.state is CheckState.OK
        assert "All 1 configured service(s) are running" in result.message
        assert "services_running=1" in result.perfdata

    def test_stopped_service_is_critical(self, run_check):
        result = run_check(
            "services",
            api.services(api.service("unbound"), api.service("dhcpd", running=False)),
        )

        assert result.state is CheckState.CRITICAL
        assert "1 service(s) stopped" in result.message

    def test_filtered_service_is_ignored(self, run_check):
        result = run_check(
            "services",
            api.services(api.service("unbound"), api.service("dhcpd", running=False)),
            "-f",
            "dhcpd",
        )

        assert result.state is CheckState.OK

    def test_missing_rows_is_unknown(self, run_check):
        result = run_check("services", {})

        assert result.state is CheckState.UNKNOWN


class TestIPsec:
    """IPsec tunnel check."""

    def test_connected(self, run_check):
        result = run_check("ipsec", api.ipsec(api.tunnel("site-a")))

        assert result.state is CheckState.OK
        assert "IPsec tunnels connected: site-a" in result.message
        assert "tunnels_connected=1" in result.perfdata

    def test_disconnected_is_warning(self, run_check):
        result = run_check(
            "ipsec",
            api.ipsec(api.tunnel("site-a"), api.tunnel("site-b", connected=False)),
        )

        assert result.state is CheckState.WARNING
        assert "IPsec tunnels not connected: site-b" in result.message

    def test_no_tunnels(self, run_check):
        result = run_check("ipsec", api.ipsec())

        assert result.state is CheckState.OK
        assert "No IPsec tunnels configured" in result.message


class TestWireGuard:
    """WireGuard peer check."""

    def test_online(self, run_check):
        result = run_check("wireguard", api.wireguard(api.peer("peer-a")))

        assert result.state is CheckState.OK
        assert "1/1 WireGuard peers are online" in result.message

    def test_offline_is_critical(self, run_check):
        result = run_check(
            "wireguard",
            api.wireguard(api.peer("peer-a"), api.peer("peer-b", status="offline")),
        )

        assert result.state is CheckState.CRITICAL
        assert "1/2 WireGuard peers are offline" in result.message

    def test_interfaces_are_not_treated_as_peers(self, run_check):
        result = run_check(
            "wireguard",
            api.wireguard(api.peer("wg0", status="offline", wg_type="interface")),
        )

        assert result.state is CheckState.OK

    def test_filtered_peer_is_ignored(self, run_check):
        result = run_check(
            "wireguard",
            api.wireguard(api.peer("peer-a"), api.peer("peer-b", status="offline")),
            "-f",
            "peer-b",
        )

        assert result.state is CheckState.OK


class TestUpdates:
    """Firmware update check."""

    def test_up_to_date(self, run_check):
        result = run_check("updates", api.firmware(status="ok"))

        assert result.state is CheckState.OK
        assert "System up to date" in result.message
        assert "available_updates=0" in result.perfdata

    def test_available_update_is_warning(self, run_check):
        result = run_check("updates", api.firmware(status="update", upgrade=3))

        assert result.state is CheckState.WARNING
        assert "upgrade_packages=3" in result.perfdata
        assert "available_updates=3" in result.perfdata

    def test_update_requiring_reboot_is_critical(self, run_check):
        result = run_check("updates", api.firmware(status="upgrade", status_reboot="1"))

        assert result.state is CheckState.CRITICAL

    def test_stale_status_triggers_refresh(self, run_check):
        """A 'none' status means OPNsense has not checked yet, so we ask it to."""
        result = run_check("updates", [api.firmware(status="none"), api.firmware(status="ok")])

        assert result.state is CheckState.OK

    def test_incomplete_response_is_unknown(self, run_check):
        result = run_check("updates", {"status": "ok"})

        assert result.state is CheckState.UNKNOWN


class TestServicesVerbose:
    """Verbose output of the service check."""

    def test_running_services_are_listed(self, run_check):
        result = run_check("services", api.services(api.service("unbound")), "-v")

        assert "--- RUNNING SERVICES ---" in result.output
        assert "[RUNNING] unbound (unbound)" in result.output

    def test_filtered_services_are_listed(self, run_check):
        result = run_check("services", api.services(api.service("unbound")), "-v", "-f", "unbound")

        assert "--- FILTERED ---" in result.output
        assert "[FILTER] unbound (unbound) is excluded by --filter" in result.output

    def test_quiet_by_default(self, run_check):
        result = run_check("services", api.services(api.service("unbound")))

        assert "--- RUNNING SERVICES ---" not in result.output
