import io
import json
from pathlib import Path
import runpy
from urllib.error import HTTPError, URLError

import pytest


DEMO_AGENT = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "examples" / "demo_agent.py")
)
local_api_url = DEMO_AGENT["local_api_url"]


def test_local_api_url_accepts_loopback_http():
    assert local_api_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert local_api_url("http://localhost:8000") == "http://localhost:8000"


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "http://example.com:8000",
        "http://127.0.0.1:8000/path",
        "http://user:password@127.0.0.1:8000",
        "http://127.0.0.1:8000/?redirect=example.com",
        "http://127.0.0.1:99999",
    ],
)
def test_local_api_url_rejects_non_local_or_ambiguous_urls(value):
    with pytest.raises(ValueError):
        local_api_url(value)


api_request = DEMO_AGENT["api_request"]
run_demo = DEMO_AGENT["run_demo"]
main = DEMO_AGENT["main"]


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self.body


def call_api_request():
    return api_request(
        "http://127.0.0.1:8000",
        "/test",
        {"amount": "1"},
        "admin-secret-token",
    )


def test_api_request_reports_http_error_without_exposing_bearer_token(monkeypatch):
    admin_token = "admin-secret-token"
    captured = {}

    def raise_http_error(request, timeout):
        captured["request"] = request
        raise HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"detail": "Request is forbidden"}'),
        )

    monkeypatch.setitem(api_request.__globals__, "urlopen", raise_http_error)

    with pytest.raises(RuntimeError, match="HTTP 403") as error:
        call_api_request()

    assert "Request is forbidden" in str(error.value)
    assert admin_token not in str(error.value)
    assert captured["request"].get_header("Authorization") == f"Bearer {admin_token}"


def test_api_request_rejects_invalid_json_response(monkeypatch):
    monkeypatch.setitem(
        api_request.__globals__,
        "urlopen",
        lambda request, timeout: FakeResponse(b"{not valid json"),
    )

    with pytest.raises(RuntimeError, match="invalid JSON") as error:
        call_api_request()

    assert "admin-secret-token" not in str(error.value)


@pytest.mark.parametrize("body", [b"[]", b"null", b'"text"', b"123"])
def test_api_request_rejects_non_object_json_response(monkeypatch, body):
    monkeypatch.setitem(
        DEMO_AGENT,
        "urlopen",
        lambda request, timeout: FakeResponse(body),
    )

    with pytest.raises(RuntimeError, match="unexpected response"):
        call_api_request()


@pytest.mark.parametrize(
    ("policy_response", "missing_field"),
    [
        ({"agent_token": "agent-secret-token"}, "policy_id"),
        ({"policy_id": "policy-1"}, "agent_token"),
    ],
)
def test_run_demo_reports_missing_policy_fields_without_printing_credentials(
    monkeypatch, capsys, policy_response, missing_field
):
    admin_token = "admin-secret-token"
    agent_token = "agent-secret-token"
    monkeypatch.setitem(
        run_demo.__globals__,
        "api_request",
        lambda *args, **kwargs: policy_response,
    )

    with pytest.raises(KeyError, match=missing_field):
        run_demo("http://127.0.0.1:8000", admin_token)

    output = capsys.readouterr().out
    assert admin_token not in output
    assert agent_token not in output


def test_main_handles_connection_failure_without_printing_admin_token(
    monkeypatch, capsys
):
    admin_token = "admin-secret-token"
    monkeypatch.setenv("AGENTGUARD_ADMIN_TOKEN", admin_token)

    def raise_connection_error(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setitem(main.__globals__, "urlopen", raise_connection_error)

    assert main() == 1

    output = capsys.readouterr().out
    assert "Demo failed:" in output
    assert "Connection refused" in output
    assert admin_token not in output
