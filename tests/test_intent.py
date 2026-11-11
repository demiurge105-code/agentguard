from dataclasses import FrozenInstanceError
from decimal import Decimal
import json

import pytest

from agentguard.intent import ActionIntent


POLICY_ID = "123e4567-e89b-12d3-a456-426614174000"
EVM_RECIPIENT = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"


def test_action_intent_is_immutable():
    intent = ActionIntent(POLICY_ID, "1.25", "Alice")

    with pytest.raises(FrozenInstanceError):
        intent.amount = Decimal("2")

    with pytest.raises(FrozenInstanceError):
        intent.recipient = "Bob"


def test_canonical_amount_equates_decimal_spellings_with_same_value():
    first = ActionIntent(POLICY_ID, "1.2300", "Alice")
    second = ActionIntent(POLICY_ID, Decimal("1.23"), "ALICE")

    assert first.canonical_json == second.canonical_json
    assert first.amount == Decimal("1.2300")
    assert json.loads(first.canonical_json)["amount"] == "1.23"


def test_canonical_amount_keeps_different_values_distinct():
    first = ActionIntent(POLICY_ID, "1.23", "Alice")
    second = ActionIntent(POLICY_ID, "1.2301", "Alice")

    assert first.canonical_json != second.canonical_json


def test_canonical_representation_is_stable_and_has_utf8_bytes():
    intent = ActionIntent(POLICY_ID, "1E-8", "Alice", chain_id=None)

    assert intent.canonical_json == intent.canonical_json
    assert intent.canonical_bytes == intent.canonical_json.encode("utf-8")
    assert json.loads(intent.canonical_json) == {
        "amount": "0.00000001",
        "chain_id": None,
        "policy_id": POLICY_ID,
        "recipient": "alice",
        "version": 1,
    }


def test_policy_uuid_is_canonicalized():
    intent = ActionIntent(POLICY_ID.upper(), "1", "Alice")

    assert intent.policy_id == POLICY_ID


@pytest.mark.parametrize("policy_id", ["", "not-a-uuid", "123e4567e89b12d3a456426614174000", None, 123])
def test_rejects_malformed_policy_identifiers(policy_id):
    with pytest.raises(ValueError, match="policy_id"):
        ActionIntent(policy_id, "1", "Alice")


@pytest.mark.parametrize("amount", [True, False, 0.1, float("nan"), float("inf")])
def test_rejects_boolean_and_float_amounts(amount):
    with pytest.raises(ValueError, match="amount"):
        ActionIntent(POLICY_ID, amount, "Alice")


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-Infinity", "0", "-1"])
def test_rejects_non_finite_or_non_positive_amounts(amount):
    with pytest.raises(ValueError, match="amount"):
        ActionIntent(POLICY_ID, amount, "Alice")


def test_rejects_amount_outside_existing_decimal_bounds():
    too_many_digits = "1" * 129

    with pytest.raises(ValueError, match="supported Decimal"):
        ActionIntent(POLICY_ID, too_many_digits, "Alice")

    with pytest.raises(ValueError, match="supported Decimal"):
        ActionIntent(POLICY_ID, "1E-129", "Alice")


def test_legacy_recipient_is_normalized_using_existing_rules():
    intent = ActionIntent(POLICY_ID, "1", "  Alice  ")

    assert intent.recipient == "alice"


def test_evm_recipient_is_normalized_using_chain_context():
    intent = ActionIntent(POLICY_ID, "1", EVM_RECIPIENT, "eip155:1")

    assert intent.recipient == EVM_RECIPIENT.lower()
    assert intent.chain_id == "eip155:1"


@pytest.mark.parametrize(
    ("recipient", "chain_id"),
    [
        ("", None),
        ("   ", None),
        ("not-an-address", "eip155:1"),
        (EVM_RECIPIENT, "eip155:0"),
        (123, None),
    ],
)
def test_rejects_malformed_recipient_or_chain_context(recipient, chain_id):
    with pytest.raises(ValueError):
        ActionIntent(POLICY_ID, "1", recipient, chain_id)


def test_canonical_identity_includes_every_operation_context_field():
    base = ActionIntent(POLICY_ID, "1", "Alice")
    different_policy = ActionIntent(
        "123e4567-e89b-12d3-a456-426614174001", "1", "Alice"
    )
    different_amount = ActionIntent(POLICY_ID, "2", "Alice")
    different_recipient = ActionIntent(POLICY_ID, "1", "Bob")
    different_chain = ActionIntent(POLICY_ID, "1", EVM_RECIPIENT, "eip155:1")

    assert len(
        {
            base.canonical_json,
            different_policy.canonical_json,
            different_amount.canonical_json,
            different_recipient.canonical_json,
            different_chain.canonical_json,
        }
    ) == 5
