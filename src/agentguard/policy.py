"""Deterministic, simulation-only transaction policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Iterable


class DecisionReason(str, Enum):
    """Stable machine-readable reasons returned by the policy engine."""

    ALLOWED = "allowed"
    AMOUNT_EXCEEDS_MAXIMUM = "amount_exceeds_maximum"
    DAILY_LIMIT_EXCEEDED = "daily_limit_exceeded"
    RECIPIENT_NOT_ALLOWED = "recipient_not_allowed"


@dataclass(frozen=True)
class Policy:
    """Rules that apply to a simulated transaction.

    Monetary values use ``Decimal`` to avoid float rounding errors. Recipient
    identifiers are compared case-insensitively in this simulator.
    """

    max_transaction: Decimal
    daily_limit: Decimal
    allowed_recipients: frozenset[str]

    def __init__(
        self,
        max_transaction: Decimal | str,
        daily_limit: Decimal | str,
        allowed_recipients: Iterable[str],
    ) -> None:
        max_amount = _as_decimal(max_transaction, "max_transaction")
        daily_amount = _as_decimal(daily_limit, "daily_limit")
        if max_amount < 0 or daily_amount < 0:
            raise ValueError("Policy limits must be non-negative.")

        recipients = frozenset(_normalise_recipient(value) for value in allowed_recipients)
        object.__setattr__(self, "max_transaction", max_amount)
        object.__setattr__(self, "daily_limit", daily_amount)
        object.__setattr__(self, "allowed_recipients", recipients)


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

        object.__setattr__(self, "amount", transaction_amount)
        object.__setattr__(self, "recipient", _normalise_recipient(recipient))
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
    if request.recipient not in policy.allowed_recipients:
        return _deny(
            DecisionReason.RECIPIENT_NOT_ALLOWED,
            "Recipient is not in the allowed-recipient list.",
        )
    return Decision(True, DecisionReason.ALLOWED, "Transaction is allowed by the policy.")


def _deny(reason_code: DecisionReason, reason: str) -> Decision:
    return Decision(False, reason_code, reason)


def _as_decimal(value: Decimal | str, field_name: str) -> Decimal:
    try:
        return Decimal(value)
    except Exception as error:
        raise ValueError(f"{field_name} must be a valid decimal value.") from error


def _normalise_recipient(value: str) -> str:
    normalised = value.strip().lower()
    if not normalised:
        raise ValueError("recipient identifiers must not be empty.")
    return normalised


