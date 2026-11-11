"""Run a deterministic, simulation-only agent through the local Gateway v1.

Start the API first, then run: python examples/demo_agent.py
"""

from __future__ import annotations

import json
import os
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from agentguard.intent import ActionIntent


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
    extra_headers: dict[str, str] | None = None,
) -> dict[str, object]:
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
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


def run_demo(base_url: str, admin_token: str) -> None:
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
    chain_id = policy.get("chain_id")
    if not isinstance(policy_id, str) or not isinstance(agent_token, str):
        raise RuntimeError("Policy creation response is missing its policy ID or agent token.")
    if chain_id is not None and not isinstance(chain_id, str):
        raise RuntimeError("Policy creation response contains an invalid chain ID.")

    print(f"Policy created: {policy_id}")
    print("Agent token received and kept in memory (not displayed).")
    print()

    # The agent sends an intent to the API; it never receives an executor reference.
    proposals = (
        ("Small transfer to an approved recipient", "25", "0xDemoRecipient"),
        ("Transfer above the per-transaction limit", "75", "0xDemoRecipient"),
    )

    for description, amount, recipient in proposals:
        intent = ActionIntent(policy_id, amount, recipient, chain_id=chain_id)
        print(f"Agent proposal: {description}")
        print(f"  Amount: {intent.amount}")
        print(f"  Recipient: {intent.recipient}")

        result = api_request(
            base_url,
            "/gateway/operations",
            {
                "policy_id": intent.policy_id,
                "amount": format(intent.amount, "f"),
                "recipient": intent.recipient,
            },
            agent_token,
            extra_headers={"Idempotency-Key": f"demo-{uuid.uuid4().hex}"},
        )
        allowed = result.get("allowed") is True
        status_value = result.get("status")
        if not isinstance(status_value, str):
            raise RuntimeError("Gateway response is missing its operation status.")

        label = "ALLOW" if allowed else "DENY"
        print(f"  AgentGuard: {label} ({status_value})")
        print(f"  Reason: {result.get('reason', 'No reason returned')}")
        print(f"  Operation ID: {result.get('operation_id', 'Unavailable')}")

        if status_value == "SUCCEEDED":
            print("  Gateway: simulated execution completed.")
        elif status_value == "DENIED":
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
        run_demo(base_url, admin_token)
    except (
        ValueError,
        RuntimeError,
        PermissionError,
        URLError,
        OSError,
    ) as error:
        print(f"Demo failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
