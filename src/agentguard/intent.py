"""Immutable, validated action intent for the future execution gateway."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from agentguard.chains import normalize_chain_id, normalize_recipient
from agentguard.policy import _as_decimal


def _canonical_amount(amount: Decimal) -> str:
    """Render an exact Decimal without exponent or insignificant trailing zeros.

    Decimal formatting with the fixed-point specifier is exact and does not
    consult the active arithmetic context. Removing zeros only after the
    decimal point makes numerically equivalent forms share one identity.
    """
    rendered = format(amount, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


@dataclass(frozen=True, slots=True)
class ActionIntent:
    """Validated immutable description of one proposed policy-scoped action.

    The idempotency key is deliberately not part of this value. A future
    operation record must bind that key to both policy_id and canonical_json.
    """

    policy_id: str
    amount: Decimal
    recipient: str
    chain_id: str | None

    def __init__(
        self,
        policy_id: str,
        amount: Decimal | str,
        recipient: str,
        chain_id: str | None = None,
    ) -> None:
        if not isinstance(policy_id, str):
            raise ValueError("policy_id must be a UUID string.")
        try:
            parsed_policy_id = str(UUID(policy_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("policy_id must be a valid UUID.") from error

        parsed_amount = _as_decimal(amount, "amount")
        if parsed_amount <= 0:
            raise ValueError("amount must be greater than zero.")

        normalized_chain_id = normalize_chain_id(chain_id)
        normalized_recipient = normalize_recipient(recipient, normalized_chain_id)

        object.__setattr__(self, "policy_id", parsed_policy_id)
        object.__setattr__(self, "amount", parsed_amount)
        object.__setattr__(self, "recipient", normalized_recipient)
        object.__setattr__(self, "chain_id", normalized_chain_id)

    @property
    def canonical_json(self) -> str:
        """Return the stable canonical representation used for later hashing."""
        payload = {
            "amount": _canonical_amount(self.amount),
            "chain_id": self.chain_id,
            "policy_id": self.policy_id,
            "recipient": self.recipient,
            "version": 1,
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    @property
    def canonical_bytes(self) -> bytes:
        """Return canonical UTF-8 bytes suitable as hash input."""
        return self.canonical_json.encode("utf-8")
