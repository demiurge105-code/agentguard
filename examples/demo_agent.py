"""Run a deterministic, simulation-only agent against a local AgentGuard API.

Start the API first, then run: python examples/demo_agent.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import os
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


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


@dataclass(frozen=True)
class TransactionIntent:
    """Immutable transaction data shared by the policy check and executor."""

    description: str
    amount: Decimal
    recipient: str

    def __init__(
        self,
        description: str,
        amount: Decimal | str,
        recipient: str,
    ) -> None:
        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must not be empty.")
        if isinstance(amount, (bool, float)):
            raise ValueError("amount must be a Decimal or decimal string, not a float.")
        try:
            parsed_amount = Decimal(amount)
        except (InvalidOperation, TypeError, ValueError) as error:
            raise ValueError("amount must be a valid decimal value.") from error
        if not parsed_amount.is_finite() or parsed_amount <= 0:
            raise ValueError("amount must be a finite decimal value greater than zero.")
        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("recipient must not be empty.")

        object.__setattr__(self, "description", description.strip())
        object.__setattr__(self, "amount", parsed_amount)
        object.__setattr__(self, "recipient", recipient.strip())

    @property
    def amount_text(self) -> str:
        """Return an exact, non-exponent decimal representation for the API."""
        return format(self.amount, "f")


def simulate_execution(intent: TransactionIntent) -> None:
    """Represent a downstream executor without performing external side effects."""
    print(
        f"  Simulated executor: would execute {intent.amount_text} units "
        f"to {intent.recipient} ({intent.description})."
    )


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
    policy_id = policy["policy_id"]
    agent_token = policy["agent_token"]
    print(f"Policy created: {policy_id}")
    print("Agent token received and kept in memory (not displayed).")
    print()

    # This deterministic demo agent proposes hypothetical actions.
    proposals = (
        TransactionIntent(
            "Small transfer to an approved recipient", "25", "0xDemoRecipient"
        ),
        TransactionIntent(
            "Transfer above the per-transaction limit", "75", "0xDemoRecipient"
        ),
    )

    for intent in proposals:
        print(f"Agent proposal: {intent.description}")
        print(f"  Amount: {intent.amount_text}")
        print(f"  Recipient: {intent.recipient}")
        decision = api_request(
            base_url,
            "/check-transaction",
            {
                "policy_id": policy_id,
                "request_id": f"demo-{uuid.uuid4().hex}",
                "amount": intent.amount_text,
                "recipient": intent.recipient,
            },
            agent_token,
        )
        allowed = decision.get("allowed") is True
        label = "ALLOW" if allowed else "DENY"
        print(f"  AgentGuard: {label}")
        print(f"  Reason: {decision.get('reason', 'No reason returned')}")

        # Fail closed: only the literal boolean True reaches the simulated executor.
        if allowed:
            simulate_execution(intent)
        else:
            print("  Simulated executor: skipped (AgentGuard did not explicitly allow).")
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
    except (ValueError, RuntimeError, URLError) as error:
        print(f"Demo failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
