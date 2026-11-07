"""Deterministic, simulation-only transaction policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Iterable

from agentguard.chains import normalize_chain_id, normalize_recipient


class DecisionReason(str, Enum):
    """Stable machine-readable reasons returned by the policy engine."""

    ALLOWED = "allowed"
    AMOUNT_EXCEEDS_MAXIMUM = "amount_exceeds_maximum"
    DAILY_LIMIT_EXCEEDED = "daily_limit_exceeded"
    RECIPIENT_NOT_ALLOWED = "recipient_not_allowed"


@dataclass(frozen=True)
class Policy:
    """Rules that apply to a simulated transaction.

    Monetary values use Decimal to avoid float rounding errors. Recipient
    normalization is selected by chain_id. Policies without a chain_id retain
    the legacy case-insensitive identifier behavior.
    """

    max_transaction: Decimal
    daily_limit: Decimal
    allowed_recipients: frozenset[str]
    chain_id: str | None

    def __init__(
        self,
        max_transaction: Decimal | str,
        daily_limit: Decimal | str,
        allowed_recipients: Iterable[str],
        chain_id: str | None = None,
    ) -> None:
        max_amount = _as_decimal(max_transaction, "max_transaction")
        daily_amount = _as_decimal(daily_limit, "daily_limit")
        if max_amount < 0 or daily_amount < 0:
            raise ValueError("Policy limits must be non-negative.")

        normalized_chain_id = normalize_chain_id(chain_id)
        recipients = frozenset(
            normalize_recipient(value, normalized_chain_id)
            for value in allowed_recipients
        )
        object.__setattr__(self, "max_transaction", max_amount)
        object.__setattr__(self, "daily_limit", daily_amount)
        object.__setattr__(self, "allowed_recipients", recipients)
        object.__setattr__(self, "chain_id", normalized_chain_id)


@dataclass(frozen=True)
class TransactionRequest:
    """A proposed transaction and the amount already spent in the current day."""

    amount: Decimal
    recipient: str
    daily_spent: Decimal

    def __init__(
        self,
        amount: Decimal | str,
        recipient: str,
        daily_spent: Decimal | str,
    ) -> None:
        transaction_amount = _as_decimal(amount, "amount")
        spent_today = _as_decimal(daily_spent, "daily_spent")
        if transaction_amount <= 0:
            raise ValueError("amount must be greater than zero.")
        if spent_today < 0:
            raise ValueError("daily_spent must be non-negative.")
        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("recipient identifiers must not be empty.")

        object.__setattr__(self, "amount", transaction_amount)
        # Preserve the public legacy behavior; chain-aware validation runs again
        # against the policy before the recipient is compared with its allowlist.
        object.__setattr__(self, "recipient", recipient.strip().lower())
        object.__setattr__(self, "daily_spent", spent_today)


@dataclass(frozen=True)
class Decision:
    """The result of a policy evaluation."""

    allowed: bool
    reason_code: DecisionReason
    reason: str

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code.value,
            "reason": self.reason,
        }


def check_transaction(request: TransactionRequest, policy: Policy) -> Decision:
    """Evaluate a proposed transaction against a policy.

    Checks run in this fixed order: per-transaction limit, daily limit, then
    recipient allowlist. This gives one deterministic denial reason when more
    than one rule fails.
    """

    recipient = normalize_recipient(request.recipient, policy.chain_id)
    if request.amount > policy.max_transaction:
        return _deny(
            DecisionReason.AMOUNT_EXCEEDS_MAXIMUM,
            "Transaction exceeds the maximum transaction limit.",
        )
    if request.daily_spent + request.amount > policy.daily_limit:
        return _deny(
            DecisionReason.DAILY_LIMIT_EXCEEDED,
            "Transaction would exceed the daily spending limit.",
        )
    if recipient not in policy.allowed_recipients:
        return _deny(
            DecisionReason.RECIPIENT_NOT_ALLOWED,
            "Recipient is not in the allowed-recipient list.",
        )
    return Decision(True, DecisionReason.ALLOWED, "Transaction is allowed by the policy.")


def _deny(reason_code: DecisionReason, reason: str) -> Decision:
    return Decision(False, reason_code, reason)


def _as_decimal(value: Decimal | str, field_name: str) -> Decimal:
    try:
        amount = Decimal(value)
    except Exception as error:
        raise ValueError(f"{field_name} must be a valid decimal value.") from error
    # Reject NaN / ±Infinity / sNaN so policy math stays total and comparable (#9).
    if not amount.is_finite():
        raise ValueError(f"{field_name} must be a finite decimal value.")
    return amount
