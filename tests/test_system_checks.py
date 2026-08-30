"""Tests for the resource based check modes (cpu, load, memory, swap, disk)."""

import api_responses as api
import pytest

from check_opnsense import CheckState

# Payloads which the API may realistically return but which no check can work with.
UNUSABLE_PAYLOADS = [
    pytest.param({}, id="empty"),
    pytest.param({"headers": []}, id="no-headers"),
    pytest.param({"headers": ["truncated line"] * 5}, id="unparsable-headers"),
]


class TestCPU:
    """CPU usage check."""

    def test_ok(self, run_check):
        result = run_check("cpu", api.activity(idle=98.1))

        assert result.state is CheckState.OK
        assert "CPU usage is 1.9%" in result.message
        assert "cpu_usage=1.9%;80.0;90.0;0;100" in result.perfdata

    def test_warning(self, run_check):
        result = run_check("cpu", api.activity(idle=15.0), "-w", "80", "-c", "90")

        assert result.state is CheckState.WARNING

    def test_critical(self, run_check):
        result = run_check("cpu", api.activity(idle=5.0), "-w", "80", "-c", "90")

        assert result.state is CheckState.CRITICAL

    @pytest.mark.parametrize("payload", UNUSABLE_PAYLOADS)
    def test_unusable_data_is_unknown(self, run_check, payload):
        result = run_check("cpu", payload)

        assert result.state is CheckState.UNKNOWN
        assert "No CPU usage data received" in result.message


class TestLoad:
    """Load average check."""

    def test_ok(self, run_check):
        result = run_check("load", api.activity(load1=0.88, load5=0.72, load15=0.61))

        assert result.state is CheckState.OK
        assert "load1=0.88;3.0;4.0;0;" in result.perfdata

    def test_critical(self, run_check):
        result = run_check("load", api.activity(load1=5.0), "-w", "3", "-c", "4")

        assert result.state is CheckState.CRITICAL

    def test_warning(self, run_check):
        result = run_check("load", api.activity(load1=3.5), "-w", "3", "-c", "4")

        assert result.state is CheckState.WARNING

    @pytest.mark.parametrize("payload", UNUSABLE_PAYLOADS)
    def test_unusable_data_is_unknown(self, run_check, payload):
        """A check that cannot read its data must never report OK."""
        result = run_check("load", payload)

        assert result.state is CheckState.UNKNOWN
        assert "No load data received" in result.message


class TestMemory:
    """Memory usage check."""

    def test_ok(self, run_check):
        result = run_check("memory", api.system_resources(total=8192, used=2048))

        assert result.state is CheckState.OK
        assert "Memory usage is 25.0%" in result.message

    def test_arc_is_not_counted_as_used(self, run_check):
        result = run_check("memory", api.system_resources(total=8192, used=4096, arc=2048))

        assert result.state is CheckState.OK
        assert "Memory usage is 25.0%" in result.message
        assert "arc_size=2048MB" in result.perfdata

    def test_critical(self, run_check):
        result = run_check("memory", api.system_resources(total=8192, used=7800))

        assert result.state is CheckState.CRITICAL

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty"),
            pytest.param({"memory": {}}, id="no-values"),
            pytest.param({"memory": {"total_frmt": "0", "used_frmt": "0"}}, id="zero-total"),
        ],
    )
    def test_unusable_data_is_unknown(self, run_check, payload):
        result = run_check("memory", payload)

        assert result.state is CheckState.UNKNOWN
        assert "No memory data received" in result.message


class TestSwap:
    """Swap usage check."""

    def test_ok(self, run_check):
        result = run_check("swap", api.system_swap(api.swap_device(total=8192, used=82)))

        assert result.state is CheckState.OK
        assert "Total swap usage is 1.0%" in result.message

    def test_critical(self, run_check):
        result = run_check("swap", api.system_swap(api.swap_device(total=100, used=95)))

        assert result.state is CheckState.CRITICAL

    def test_usage_is_summed_over_all_devices(self, run_check):
        result = run_check(
            "swap",
            api.system_swap(
                api.swap_device(device="/dev/md0", total=100, used=100),
                api.swap_device(device="/dev/gpt/swapfs", total=100, used=0),
            ),
        )

        assert result.state is CheckState.OK
        assert "Total swap usage is 50.0%" in result.message

    def test_no_swap_is_unknown(self, run_check):
        result = run_check("swap", api.system_swap())

        assert result.state is CheckState.UNKNOWN
        assert "No swap found" in result.message

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="empty"),
            pytest.param({"swap": [{"device": "/dev/md0"}]}, id="missing-values"),
            pytest.param(
                {"swap": [{"device": "/dev/md0", "total": "0", "used": "0"}]}, id="zero-total"
            ),
        ],
    )
    def test_unusable_data_is_unknown(self, run_check, payload):
        result = run_check("swap", payload)

        assert result.state is CheckState.UNKNOWN


class TestDisk:
    """Disk usage check."""

    def test_ok(self, run_check):
        result = run_check("disk", api.system_disk(api.disk_device("/", used_pct=2)))

        assert result.state is CheckState.OK
        assert "Disk space is ok" in result.message
        assert "/=2%;80.0;90.0;0;100" in result.perfdata

    def test_warning(self, run_check):
        result = run_check("disk", api.system_disk(api.disk_device("/", used_pct=85)))

        assert result.state is CheckState.WARNING
        assert "Disk space is low on 1 disk(s)" in result.message

    def test_critical(self, run_check):
        result = run_check("disk", api.system_disk(api.disk_device("/", used_pct=95)))

        assert result.state is CheckState.CRITICAL

    def test_critical_disk_is_reported_regardless_of_device_order(self, run_check):
        """A healthy device listed last must not mask a full one listed first."""
        result = run_check(
            "disk",
            api.system_disk(
                api.disk_device("/", used_pct=95),
                api.disk_device("/var", used_pct=1),
            ),
        )

        assert result.state is CheckState.CRITICAL
        assert "critically low on 1 disk(s)" in result.message

    def test_no_devices_is_unknown(self, run_check):
        """An empty device list means the API told us nothing, not that all is well."""
        result = run_check("disk", api.system_disk())

        assert result.state is CheckState.UNKNOWN
        assert "No disks found" in result.message

    def test_all_devices_filtered_is_unknown(self, run_check):
        result = run_check("disk", api.system_disk(api.disk_device("/", used_pct=95)), "-f", "/")

        assert result.state is CheckState.UNKNOWN
        assert "No disks found" in result.message
