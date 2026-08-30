"""Shared fixtures for the check_opnsense test suite."""

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Sequence, Union

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_opnsense  # noqa: E402
from check_opnsense import CHECKS, CheckOPNsense, CheckState, parse_args  # noqa: E402


class CheckOutcome(NamedTuple):
    """Result of a check run: exit state and everything written to stdout."""

    state: CheckState
    output: str

    @property
    def message(self) -> str:
        """Output without the trailing perfdata section."""
        return self.output.split(" | ")[0]

    @property
    def perfdata(self) -> str:
        """Perfdata section of the output, empty if the check emitted none."""
        parts = self.output.split(" | ", 1)
        return parts[1] if len(parts) > 1 else ""


BASE_ARGS = [
    "-H",
    "opnsense.example.com",
    "--api-key",
    "key",
    "--api-secret",
    "secret",
]


@pytest.fixture
def build_check() -> Callable[..., CheckOPNsense]:
    """Build a CheckOPNsense instance for a given mode and CLI arguments."""

    def _build(mode: str, *extra_args: str) -> CheckOPNsense:
        options = parse_args(BASE_ARGS + ["-m", mode] + list(extra_args))
        return CHECKS[mode](options)

    return _build


@pytest.fixture
def run_check(
    build_check: Callable[..., CheckOPNsense], capsys: pytest.CaptureFixture
) -> Callable[..., CheckOutcome]:
    """Run a check mode against canned API responses and capture its outcome.

    ``responses`` is either a single payload reused for every API call or a
    sequence of payloads handed out in call order.
    """

    def _run(
        mode: str,
        responses: Union[Dict, List[Dict], None],
        *extra_args: str,
    ) -> CheckOutcome:
        check = build_check(mode, *extra_args)

        queue: Sequence[Any] = responses if isinstance(responses, list) else [responses]
        calls = iter(queue)
        last = [queue[-1] if queue else None]

        def fake_request(url: str, method: str = "get", **kwargs: Any) -> Any:
            try:
                last[0] = next(calls)
            except StopIteration:
                pass
            return last[0]

        check.request = fake_request  # type: ignore[method-assign]

        with pytest.raises(SystemExit) as exc:
            check.check()

        return CheckOutcome(CheckState(exc.value.code), capsys.readouterr().out.strip())

    return _run


@pytest.fixture
def run_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> Callable[..., CheckOutcome]:
    """Run the plugin entry point with a raw command line."""

    def _run(*args: str) -> CheckOutcome:
        monkeypatch.setattr(sys, "argv", ["check_opnsense.py", *args])

        with pytest.raises(SystemExit) as exc:
            check_opnsense.main()

        captured = capsys.readouterr()
        return CheckOutcome(CheckState(exc.value.code), (captured.out + captured.err).strip())

    return _run
