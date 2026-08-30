"""Tests for the contract a check mode has to fulfil, as documented in CONTRIBUTING.md."""

from typing import Dict

import pytest

from check_opnsense import CHECKS, CheckOPNsense, CheckState, parse_args
from conftest import BASE_ARGS


@pytest.fixture
def toy_check():
    """Define a check mode the way a contributor would, and unregister it afterwards."""

    class ToyCheck(CheckOPNsense):
        """Check toys."""

        name = "toys"
        endpoint = "toys/status"
        defaults = (2.0, 3.0)
        data_error = "No toy data received."

        def run(self, data: Dict) -> None:
            """Evaluate the toy response."""
            warn, crit = self.thresholds()

            for toy in data["items"]:
                if self.filtered(toy["name"]):
                    continue

                self.add(self.evaluate(toy["wear"], warn, crit), f"{toy['name']} is worn")

            self.check_message = f"{self.num_items} toy(s) checked"

    yield ToyCheck
    CHECKS.pop("toys", None)


def run_toy(payload, *extra_args, capsys):
    """Run the toy check against a canned payload."""
    check = CHECKS["toys"](parse_args(BASE_ARGS + ["-m", "toys"] + list(extra_args)))
    check.request = lambda *a, **k: payload

    with pytest.raises(SystemExit) as exc:
        check.check()

    return CheckState(exc.value.code), capsys.readouterr().out.strip()


def test_defining_a_subclass_registers_the_mode(toy_check):
    assert CHECKS["toys"] is toy_check


def test_the_mode_becomes_available_on_the_command_line(toy_check):
    assert parse_args(BASE_ARGS + ["-m", "toys"]).mode == "toys"


def test_the_base_class_fetches_the_endpoint(toy_check, capsys):
    state, output = run_toy({"items": [{"name": "ball", "wear": 0}]}, capsys=capsys)

    assert state is CheckState.OK
    assert "1 toy(s) checked" in output


def test_add_raises_the_overall_result(toy_check, capsys):
    payload = {"items": [{"name": "ball", "wear": 0}, {"name": "bear", "wear": 5}]}
    state, output = run_toy(payload, capsys=capsys)

    assert state is CheckState.CRITICAL
    assert "[OK] ball is worn" in output
    assert "[CRITICAL] bear is worn" in output


def test_declared_defaults_are_used(toy_check, capsys):
    state, _ = run_toy({"items": [{"name": "ball", "wear": 2}]}, capsys=capsys)

    assert state is CheckState.WARNING


def test_command_line_thresholds_win(toy_check, capsys):
    state, _ = run_toy(
        {"items": [{"name": "ball", "wear": 2}]}, "-w", "9", "-c", "10", capsys=capsys
    )

    assert state is CheckState.OK


def test_filter_applies_without_extra_work(toy_check, capsys):
    payload = {"items": [{"name": "ball", "wear": 9}]}
    state, output = run_toy(payload, "-f", "ball", "-v", capsys=capsys)

    assert state is CheckState.OK
    assert "0 toy(s) checked" in output
    assert "[FILTER] ball is excluded by --filter" in output


def test_unreadable_data_reports_the_declared_message(toy_check, capsys):
    state, output = run_toy({}, capsys=capsys)

    assert state is CheckState.UNKNOWN
    assert "No toy data received." in output
