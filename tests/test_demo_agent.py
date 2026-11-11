import io
from pathlib import Path
import runpy
from urllib.error import HTTPError, URLError

import pytest


DEMO_AGENT = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "examples" / "demo_agent.py")
)
local_api_url = DEMO_AGENT["local_api_url"]
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
        api_request.__globals__,
        "urlopen",
        lambda request, timeout: FakeResponse(body),
    )

    with pytest.raises(RuntimeError, match="unexpected response"):
        call_api_request()


def test_api_request_adds_idempotency_header_without_overriding_auth(monkeypatch):
    captured = {}

    def return_response(request, timeout):
        captured["request"] = request
        return FakeResponse(b'{"ok": true}')

    monkeypatch.setitem(api_request.__globals__, "urlopen", return_response)
    result = api_request(
        "http://127.0.0.1:8000",
        "/gateway/operations",
        {"amount": "1"},
        "agent-token",
        idempotency_key="unique-key",
    )

    assert result == {"ok": True}
    assert captured["request"].get_header("Authorization") == "Bearer agent-token"
    assert captured["request"].get_header("Idempotency-key") == "unique-key"


def test_run_demo_submits_both_proposals_through_gateway_endpoint(monkeypatch, capsys):
    calls = []
    policy_id = "123e4567-e89b-12d3-a456-426614174000"
    agent_token = "agent-secret-token"

    def fake_api_request(base_url, path, payload, bearer_token, idempotency_key=None):
        assert base_url == "http://127.0.0.1:8000"
        if path == "/policies":
            assert bearer_token == "admin-secret-token"
            return {"policy_id": policy_id, "agent_token": agent_token}

        assert path == "/gateway/operations"
        assert bearer_token == agent_token
        assert isinstance(idempotency_key, str) and idempotency_key.startswith("demo-")
        calls.append((payload, idempotency_key))
        index = len(calls)
        return {
            "operation_id": f"operation-{index}",
            "status": "APPROVED" if index == 1 else "DENIED",
            "execution_status": "QUEUED" if index == 1 else "NOT_QUEUED",
            "allowed": index == 1,
            "reason": "test decision",
        }

    monkeypatch.setitem(run_demo.__globals__, "api_request", fake_api_request)

    run_demo("http://127.0.0.1:8000", "admin-secret-token")

    output = capsys.readouterr().out
    assert "APPROVED" in output
    assert "QUEUED" in output
    assert "DENIED" in output
    assert len(calls) == 2
    assert calls[0][0] == {
        "policy_id": policy_id,
        "amount": "25",
        "recipient": "0xdemorecipient",
    }
    assert calls[1][0] == {
        "policy_id": policy_id,
        "amount": "75",
        "recipient": "0xdemorecipient",
    }
    assert calls[0][1] != calls[1][1]
    assert agent_token not in output


@pytest.mark.parametrize(
    ("policy_response", "missing_field"),
    [
        ({"agent_token": "agent-secret-token"}, "policy ID or agent token"),
        ({"policy_id": "not-a-policy"}, "policy ID or agent token"),
    ],
)
def test_run_demo_rejects_incomplete_policy_response_without_printing_credentials(
    monkeypatch, capsys, policy_response, missing_field
):
    monkeypatch.setitem(
        run_demo.__globals__,
        "api_request",
        lambda *args, **kwargs: policy_response,
    )

    with pytest.raises(RuntimeError, match=missing_field):
        run_demo("http://127.0.0.1:8000", "admin-secret-token")

    output = capsys.readouterr().out
    assert "admin-secret-token" not in output
    assert "agent-secret-token" not in output


def test_run_demo_stops_when_gateway_request_fails(monkeypatch):
    def failing_api_request(base_url, path, payload, token, idempotency_key=None):
        if path == "/policies":
            return {
                "policy_id": "123e4567-e89b-12d3-a456-426614174000",
                "agent_token": "agent-secret-token",
            }
        raise RuntimeError("Gateway unavailable")

    monkeypatch.setitem(run_demo.__globals__, "api_request", failing_api_request)

    with pytest.raises(RuntimeError, match="Gateway unavailable"):
        run_demo("http://127.0.0.1:8000", "admin-secret-token")


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
    assert "connection refused" in output.lower()
    assert admin_token not in output
