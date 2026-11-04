"""A deterministic demo agent that asks AgentGuard before simulated actions.

Run the API separately, then execute:
    python examples/agent_demo.py

This example never connects to a wallet or submits a blockchain transaction.
"""
from __future__ import annotations

import json
import os
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_URL = os.getenv("AGENTGUARD_API_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_TOKEN = os.getenv("AGENTGUARD_ADMIN_TOKEN")


def post_json(path: str, token: str, payload: dict[str, object]) -> dict[str, object]:
    """Send one authenticated JSON request to the local AgentGuard API."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        f"{API_URL}{path}",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"AgentGuard API returned HTTP {error.code}: {details}"
        ) from error
    except URLError as error:
        raise RuntimeError(
            f"Cannot reach AgentGuard at {API_URL}: {error.reason}"
        ) from error
    except TimeoutError as error:
        raise RuntimeError(f"AgentGuard request timed out: {error}") from error

    if not isinstance(result, dict):
        raise RuntimeError("AgentGuard returned an unexpected response.")
    return result


def main() -> None:
    if not ADMIN_TOKEN:
        raise SystemExit(
            "Set AGENTGUARD_ADMIN_TOKEN to the same owner token used by the API."
        )

    policy = post_json(
        "/policies",
        ADMIN_TOKEN,
        {
            "max_transaction": "50",
            "daily_limit": "60",
            "allowed_recipients": ["0xDemoTreasury"],
        },
    )
    policy_id = str(policy["policy_id"])
    agent_token = str(policy["agent_token"])

    print("AgentGuard demo agent")
    print(f"Policy created: {policy_id}")
    print("All actions below are simulations; no funds move.\n")

    proposed_actions = [
        {
            "description": "Pay 25 units to the approved treasury",
            "amount": "25",
            "recipient": "0xDemoTreasury",
        },
        {
            "description": "Pay 5 units to an unapproved address",
            "amount": "5",
            "recipient": "0xUnknownRecipient",
        },
        {
            "description": "Pay 40 units to the approved treasury",
            "amount": "40",
            "recipient": "0xDemoTreasury",
        },
    ]

    for index, action in enumerate(proposed_actions, start=1):
        decision = post_json(
            "/check-transaction",
            agent_token,
            {
                "policy_id": policy_id,
                "request_id": f"demo-{uuid.uuid4()}",
                "amount": action["amount"],
                "recipient": action["recipient"],
            },
        )
        outcome = "ALLOW" if decision.get("allowed") is True else "DENY"
        print(f"{index}. {action['description']}")
        print(f"   AgentGuard: {outcome}")
        print(f"   Reason: {decision.get('reason', 'No reason provided.')}")
        print()

    print("Demo complete. The agent followed AgentGuard's API decisions.")


if __name__ == "__main__":
    main()
