"""Tests for command line argument handling."""

import api_responses as api
import pytest

from conftest import BASE_ARGS

import check_opnsense
from check_opnsense import CheckState

DISKS = api.system_disk(
    api.disk_device("/", used_pct=95),
    api.disk_device("/var", used_pct=95),
)


class TestFilter:
    """The --filter option."""

    def test_single_entry(self, run_check):
        result = run_check("disk", DISKS, "-f", "/")

        assert result.state is CheckState.CRITICAL
        assert "critically low on 1 disk(s)" in result.message

    def test_entries_are_stripped(self, run_check):
        """The documented 'Disk 1, Disk 2' spelling must work, not just 'Disk 1,Disk 2'."""
        result = run_check("disk", DISKS, "-f", "/, /var")

        assert result.state is CheckState.UNKNOWN
        assert "No disks found" in result.message

    def test_entries_without_spaces(self, run_check):
        result = run_check("disk", DISKS, "-f", "/,/var")

        assert result.state is CheckState.UNKNOWN

    def test_empty_entries_are_dropped(self, run_check):
        """A trailing comma must not filter items with an empty name."""
        result = run_check("disk", DISKS, "-f", "/,")

        assert result.state is CheckState.CRITICAL
        assert "critically low on 1 disk(s)" in result.message

    def test_no_filter(self, run_check):
        result = run_check("disk", DISKS)

        assert result.state is CheckState.CRITICAL
        assert "critically low on 2 disk(s)" in result.message


class TestArgumentErrors:
    """Usage errors are a problem with the check, not with the firewall."""

    def test_missing_required_argument(self, run_cli):
        result = run_cli("-m", "cpu")

        assert result.state is CheckState.UNKNOWN

    def test_invalid_mode(self, run_cli):
        result = run_cli(*BASE_ARGS, "-m", "bogus")

        assert result.state is CheckState.UNKNOWN
        assert "invalid choice" in result.output

    def test_help_exits_ok(self, run_cli):
        result = run_cli("--help")

        assert result.state is CheckState.OK


class TestUnhandledErrors:
    """Anything unforeseen still has to look like a check result."""

    def test_unhandled_error_is_unknown(self, monkeypatch, run_cli):
        def boom(self, data):
            raise AttributeError("something changed upstream")

        monkeypatch.setattr("check_opnsense.CheckOPNsense.request", lambda *a, **k: {})
        monkeypatch.setattr("check_opnsense.CPUCheck.run", boom)
        result = run_cli(*BASE_ARGS, "-m", "cpu")

        assert result.state is CheckState.UNKNOWN
        assert "Unhandled error" in result.output


def test_every_mode_is_registered_with_an_endpoint():
    """A registered mode is only usable if it declares what to fetch and how to read it."""
    assert check_opnsense.CHECKS

    for mode, check in check_opnsense.CHECKS.items():
        assert check.name == mode
        assert check.endpoint
        assert check.run is not check_opnsense.CheckOPNsense.run


class TestFilterReporting:
    """Every mode reports what it left out, in the same way."""

    @pytest.mark.parametrize(
        ("mode", "responses", "excluded"),
        [
            pytest.param("disk", api.system_disk(api.disk_device("/")), "/", id="disk"),
            pytest.param(
                "swap",
                api.system_swap(api.swap_device(device="/dev/md0")),
                "/dev/md0",
                id="swap",
            ),
            pytest.param(
                "interfaces", api.interfaces(api.interface("em0")), "em0", id="interfaces"
            ),
            pytest.param("wireguard", api.wireguard(api.peer("peer-a")), "peer-a", id="wireguard"),
        ],
    )
    def test_filtered_items_are_reported(self, run_check, mode, responses, excluded):
        result = run_check(mode, responses, "-v", "-f", excluded)

        assert "--- FILTERED ---" in result.output
        assert f"[FILTER] {excluded} is excluded by --filter" in result.output

    def test_nothing_reported_without_verbose(self, run_check):
        result = run_check("disk", api.system_disk(api.disk_device("/")), "-f", "/")

        assert "--- FILTERED ---" not in result.output


class TestCredentials:
    """Credentials may come from the environment to keep them out of the process list."""

    ARGS_WITHOUT_CREDENTIALS = ["-H", "opnsense.example.com", "-m", "cpu"]

    def test_environment_is_used(self, monkeypatch):
        monkeypatch.setenv("OPNSENSE_API_KEY", "env-key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env-secret")
        options = check_opnsense.parse_args(self.ARGS_WITHOUT_CREDENTIALS)

        assert options.api_key == "env-key"
        assert options.api_secret == "env-secret"

    def test_command_line_wins_over_environment(self, monkeypatch):
        monkeypatch.setenv("OPNSENSE_API_KEY", "env-key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env-secret")
        options = check_opnsense.parse_args(BASE_ARGS + ["-m", "cpu"])

        assert options.api_key == "key"

    @pytest.mark.parametrize("missing", ["OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"])
    def test_missing_credential_is_unknown(self, monkeypatch, run_cli, missing):
        monkeypatch.setenv("OPNSENSE_API_KEY", "env-key")
        monkeypatch.setenv("OPNSENSE_API_SECRET", "env-secret")
        monkeypatch.delenv(missing)

        result = run_cli(*self.ARGS_WITHOUT_CREDENTIALS)

        assert result.state is CheckState.UNKNOWN
        assert missing in result.output
