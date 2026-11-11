"""Run a deterministic, simulation-only agent through the local Gateway v1.

Start the API first, then run: python examples/demo_agent.py
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from agentguard.gateway import (
    OperationStatus,
    PrintOnlyExecutor,
    TrustedExecutionGateway,
)
from agentguard.intent import ActionIntent
from agentguard.storage import SQLitePolicyStore


_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def local_api_url(value: str) -> str:
    """Accept only a plain HTTP URL on loopback to avoid leaking the admin token."""
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _ALLOWED_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "AGENTGUARD_API_URL must be a local URL such as http://127.0.0.1:8000"
        )
    # Accessing .port also validates malformed/out-of-range ports.
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("AGENTGUARD_API_URL contains an invalid port.") from error
    return value.strip().rstrip("/")


def api_request(
    base_url: str,
    path: str,
    payload: dict[str, object],
    bearer_token: str,
) -> dict[str, object]:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            detail = json.loads(error.read().decode("utf-8")).get("detail", "Request failed")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            detail = "Request failed"
        raise RuntimeError(f"AgentGuard API returned HTTP {error.code}: {detail}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("AgentGuard API returned an invalid JSON response.") from error

    if not isinstance(result, dict):
        raise RuntimeError("AgentGuard API returned an unexpected response.")
    return result


def run_demo(
    base_url: str,
    admin_token: str,
    db_path: str | Path = "agentguard.db",
) -> None:
    print("Creating a demo policy...")
    policy = api_request(
        base_url,
        "/policies",
        {
            "max_transaction": "50",
            "daily_limit": "100",
            "allowed_recipients": ["0xDemoRecipient"],
        },
        admin_token,
    )
    policy_id = policy.get("policy_id")
    agent_token = policy.get("agent_token")
    if not isinstance(policy_id, str) or not isinstance(agent_token, str):
        raise RuntimeError("Policy creation response is missing its policy ID or agent token.")

    # The API and this local demo must use the same configured SQLite database.
    store = SQLitePolicyStore(db_path)
    if store.get_policy(policy_id) is None:
        raise RuntimeError(
            "The created policy was not found in AGENTGUARD_DB_PATH. "
            "Start the API and demo with the same database path."
        )

    gateway = TrustedExecutionGateway(store, PrintOnlyExecutor())
    print(f"Policy created: {policy_id}")
    print("Agent token received and kept in memory (not displayed).")
    print()

    # The proposal logic receives the gateway, not an executor reference.
    proposals = (
        ("Small transfer to an approved recipient", "25", "0xDemoRecipient"),
        ("Transfer above the per-transaction limit", "75", "0xDemoRecipient"),
    )

    for description, amount, recipient in proposals:
        intent = ActionIntent(policy_id, amount, recipient)
        print(f"Agent proposal: {description}")
        print(f"  Amount: {intent.amount}")
        print(f"  Recipient: {intent.recipient}")

        result = gateway.submit(
            intent,
            agent_token,
            idempotency_key=f"demo-{uuid.uuid4().hex}",
        )
        label = "ALLOW" if result.allowed is True else "DENY"
        print(f"  AgentGuard: {label} ({result.status.value})")
        print(f"  Reason: {result.reason}")
        print(f"  Operation ID: {result.operation_id}")

        if result.status is OperationStatus.SUCCEEDED:
            print("  Gateway: simulated execution completed.")
        elif result.status is OperationStatus.DENIED:
            print("  Gateway: executor was not called.")
        else:
            print(
                "  Gateway: operation is unresolved; it will not be "
                "automatically executed again."
            )
        print()

    print("Demo complete. No wallet was connected and no transaction was sent.")


def main() -> int:
    admin_token = os.getenv("AGENTGUARD_ADMIN_TOKEN", "")
    if not admin_token:
        print("Set AGENTGUARD_ADMIN_TOKEN before running this demo.")
        return 1

    try:
        base_url = local_api_url(
            os.getenv("AGENTGUARD_API_URL", "http://127.0.0.1:8000")
        )
        db_path = os.getenv("AGENTGUARD_DB_PATH", "agentguard.db")
        run_demo(base_url, admin_token, db_path)
    except (
        ValueError,
        RuntimeError,
        PermissionError,
        URLError,
        OSError,
        sqlite3.Error,
    ) as error:
        print(f"Demo failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
