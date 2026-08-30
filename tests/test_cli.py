"""Tests for command line argument handling."""

import api_responses as api

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
