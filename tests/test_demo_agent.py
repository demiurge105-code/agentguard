import hashlib
import io
from pathlib import Path
import runpy
from urllib.error import HTTPError, URLError

import pytest

from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore


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


def make_demo_database(path):
    token = "agent-secret-token"
    store = SQLitePolicyStore(path)
    policy_id = store.create_policy(
        Policy("50", "100", ["0xDemoRecipient"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    return store, policy_id, token


def test_run_demo_uses_gateway_and_only_executes_allowed_proposal(
    tmp_path, monkeypatch, capsys
):
    db_path = tmp_path / "demo.db"
    store, policy_id, token = make_demo_database(db_path)

    def fake_api_request(base_url, path, payload, bearer_token):
        assert path == "/policies"
        assert bearer_token == "admin-secret-token"
        assert payload["max_transaction"] == "50"
        return {"policy_id": policy_id, "agent_token": token}

    executions = []

    class CountingExecutor:
        def __call__(self, intent, operation_id):
            executions.append((intent, operation_id))
            return None

    monkeypatch.setitem(run_demo.__globals__, "api_request", fake_api_request)
    monkeypatch.setitem(run_demo.__globals__, "PrintOnlyExecutor", CountingExecutor)

    run_demo("http://127.0.0.1:8000", "admin-secret-token", db_path)

    output = capsys.readouterr().out
    assert "SUCCEEDED" in output
    assert "DENIED" in output
    assert len(executions) == 1
    assert executions[0][0].amount == 25
    assert executions[0][0].recipient == "0xdemoRecipient".lower()

    connection = store._connect()
    try:
        operations = connection.execute(
            "SELECT status FROM gateway_operations ORDER BY created_at"
        ).fetchall()
    finally:
        connection.close()
    assert len(operations) == 2
    assert {row["status"] for row in operations} == {"SUCCEEDED", "DENIED"}


def test_run_demo_stops_if_api_and_demo_use_different_databases(tmp_path, monkeypatch):
    _, policy_id, token = make_demo_database(tmp_path / "api.db")
    monkeypatch.setitem(
        run_demo.__globals__,
        "api_request",
        lambda *args, **kwargs: {"policy_id": policy_id, "agent_token": token},
    )

    with pytest.raises(RuntimeError, match="same database path"):
        run_demo(
            "http://127.0.0.1:8000",
            "admin-secret-token",
            tmp_path / "different.db",
        )


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


def test_run_demo_does_not_continue_when_policy_creation_fails(monkeypatch):
    def failing_api_request(*args, **kwargs):
        raise RuntimeError("AgentGuard unavailable")

    monkeypatch.setitem(run_demo.__globals__, "api_request", failing_api_request)

    with pytest.raises(RuntimeError, match="AgentGuard unavailable"):
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
