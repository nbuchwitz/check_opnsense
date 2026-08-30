"""Tests for the API transport layer."""

from pathlib import Path
from typing import Any, Optional
from unittest import mock

import pytest
import requests

import check_opnsense
from check_opnsense import CheckState


class FakeResponse:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code: int = 200, payload: Optional[Any] = None, valid_json=True):
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload if payload is not None else {}
        self._valid_json = valid_json

    def json(self) -> Any:
        """Return the decoded payload or fail like requests does on garbage."""
        if not self._valid_json:
            raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        return self._payload


@pytest.fixture
def check(build_check):
    """Build a check instance which does not run any mode on its own."""
    return build_check("updates")


def call_request(check_instance, response=None, exception=None, method="get"):
    """Invoke request() with the HTTP layer replaced by a canned result."""
    target = f"requests.{method}"
    kwargs = {"side_effect": exception} if exception else {"return_value": response}
    with mock.patch(target, **kwargs) as request_mock:
        return check_instance.request(check_instance.get_url("core/firmware/status"), method), (
            request_mock
        )


class TestUrl:
    """API URL construction."""

    def test_default_port(self, check):
        assert (
            check.get_url("core/firmware/status")
            == "https://opnsense.example.com:443/api/core/firmware/status"
        )

    def test_custom_port(self, build_check):
        check = build_check("updates", "-p", "8443")

        assert check.get_url("x").startswith("https://opnsense.example.com:8443/api/")


class TestSuccess:
    """Successful API responses."""

    def test_get_returns_payload(self, check):
        data, _ = call_request(check, FakeResponse(payload={"status": "ok"}))

        assert data == {"status": "ok"}

    def test_post_returns_payload(self, check):
        data, _ = call_request(check, FakeResponse(payload={"status": "ok"}), method="post")

        assert data == {"status": "ok"}

    def test_certificate_is_verified_by_default(self, check):
        _, request_mock = call_request(check, FakeResponse())

        assert request_mock.call_args.kwargs["verify"] is True

    def test_insecure_disables_verification(self, build_check):
        check = build_check("updates", "-k")
        _, request_mock = call_request(check, FakeResponse())

        assert request_mock.call_args.kwargs["verify"] is False


class TestHttpErrors:
    """HTTP level failures must map to UNKNOWN, never to a traceback."""

    @pytest.mark.parametrize(
        ("status_code", "expected"),
        [
            (401, "invalid API key or secret"),
            (403, "sufficient permissions"),
            (500, "HTTP error code was 500"),
        ],
    )
    def test_error_code(self, check, capsys, status_code, expected):
        with pytest.raises(SystemExit) as exc:
            call_request(check, FakeResponse(status_code=status_code))

        assert CheckState(exc.value.code) is CheckState.UNKNOWN
        assert expected in capsys.readouterr().out

    def test_non_json_body(self, check, capsys):
        """An error page or captive portal response must not crash the check."""
        with pytest.raises(SystemExit) as exc:
            call_request(check, FakeResponse(valid_json=False))

        assert CheckState(exc.value.code) is CheckState.UNKNOWN
        assert "Could not fetch data from API" in capsys.readouterr().out


class TestTransportErrors:
    """Connection level failures must map to UNKNOWN, never to a traceback."""

    @pytest.mark.parametrize(
        ("exception", "expected"),
        [
            pytest.param(requests.exceptions.ConnectTimeout(), "timeout", id="connect-timeout"),
            pytest.param(requests.exceptions.ReadTimeout(), "timeout", id="read-timeout"),
            pytest.param(requests.exceptions.SSLError(), "Certificate validation failed", id="ssl"),
            pytest.param(
                requests.exceptions.ConnectionError(), "Could not connect", id="connection"
            ),
            pytest.param(
                requests.exceptions.TooManyRedirects(), "Could not connect", id="redirects"
            ),
        ],
    )
    def test_transport_error(self, check, capsys, exception, expected):
        with pytest.raises(SystemExit) as exc:
            call_request(check, exception=exception)

        assert CheckState(exc.value.code) is CheckState.UNKNOWN
        assert expected.lower() in capsys.readouterr().out.lower()


class TestUnsupportedMethod:
    """Guard against a typo in a call site silently doing nothing."""

    def test_unsupported_method(self, check, capsys):
        with pytest.raises(SystemExit) as exc:
            check.request(check.get_url("x"), method="delete")

        assert CheckState(exc.value.code) is CheckState.UNKNOWN
        assert "request method" in capsys.readouterr().out


def test_version_is_consistent():
    """The advertised version must match the one documented in the file header."""
    source = Path(check_opnsense.__file__).read_text(encoding="utf-8")
    header_version = next(
        line.split(":", 1)[1].strip()
        for line in source.splitlines()
        if line.startswith("# Version")
    )

    assert check_opnsense.CheckOPNsense.VERSION == header_version
