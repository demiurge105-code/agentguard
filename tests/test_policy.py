from decimal import Decimal
import pytest
from agentguard import (
    Decision,
    DecisionReason,
    Policy,
    TransactionRequest,
    check_transaction,
)


@pytest.fixture
def policy() -> Policy:
    return Policy(
        max_transaction="50",
        daily_limit="200",
        allowed_recipients=["0xABC", "0xDEF"],
    )


def test_allows_a_valid_transaction(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("35", "0xABC", "100"), policy)

    assert decision.allowed is True
    assert decision.reason_code is DecisionReason.ALLOWED


def test_denies_an_amount_above_the_per_transaction_limit(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("50.01", "0xABC", "100"), policy)

    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.AMOUNT_EXCEEDS_MAXIMUM


def test_denies_a_transaction_that_would_exceed_the_daily_limit(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("35", "0xABC", "170"), policy)

    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED


def test_denies_a_recipient_outside_the_allowlist(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("35", "0xNOT_ALLOWED", "100"), policy)

    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.RECIPIENT_NOT_ALLOWED


def test_uses_a_deterministic_reason_when_multiple_rules_fail(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("75", "0xNOT_ALLOWED", "190"), policy)

    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.AMOUNT_EXCEEDS_MAXIMUM


def test_recipient_comparison_is_case_insensitive(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("35", "0xabc", "100"), policy)

    assert decision.allowed is True


@pytest.mark.parametrize(
    ("amount", "daily_spent"),
    [("0", "0"), ("-1", "0"), ("1", "-1")],
)
def test_rejects_invalid_transaction_amounts(amount: str, daily_spent: str) -> None:
    with pytest.raises(ValueError):
        TransactionRequest(amount, "0xABC", daily_spent)


def test_uses_decimal_not_float_for_amounts(policy: Policy) -> None:
    decision = check_transaction(
        TransactionRequest(Decimal("0.1") + Decimal("0.2"), "0xABC", "0"), policy
    )

    assert decision.allowed is True


def test_allows_amount_exactly_equal_to_max_transaction(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("50", "0xABC", "0"), policy)

    assert decision.allowed is True
    assert decision.reason_code is DecisionReason.ALLOWED


def test_allows_when_daily_spent_plus_amount_equals_daily_limit(policy: Policy) -> None:
    decision = check_transaction(TransactionRequest("30", "0xABC", "170"), policy)

    assert decision.allowed is True
    assert decision.reason_code is DecisionReason.ALLOWED


def test_empty_allowlist_denies_every_recipient() -> None:
    empty_policy = Policy(
        max_transaction="50",
        daily_limit="200",
        allowed_recipients=[],
    )
    decision = check_transaction(TransactionRequest("10", "0xABC", "0"), empty_policy)

    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.RECIPIENT_NOT_ALLOWED


@pytest.mark.parametrize("recipient", ["", "   ", "\t"])
def test_rejects_empty_recipient_identifiers(recipient: str) -> None:
    with pytest.raises(ValueError, match="recipient identifiers must not be empty"):
        TransactionRequest("10", recipient, "0")


@pytest.mark.parametrize(
    ("max_transaction", "daily_limit"),
    [("-1", "200"), ("50", "-1"), ("-5", "-10")],
)
def test_rejects_negative_limits(max_transaction: str, daily_limit: str) -> None:
    with pytest.raises(ValueError, match="Policy limits must be non-negative"):
        Policy(max_transaction, daily_limit, ["0xABC"])


@pytest.mark.parametrize(
    ("value", "field"),
    [
        ("not-a-number", "max_transaction"),
        ("", "daily_limit"),
        ("12.34.56", "amount"),
        ("abc", "daily_spent"),
    ],
)
def test_rejects_invalid_decimal_values(value: str, field: str) -> None:
    if field in ("max_transaction", "daily_limit"):
        kwargs = {
            "max_transaction": value if field == "max_transaction" else "50",
            "daily_limit": value if field == "daily_limit" else "200",
            "allowed_recipients": ["0xABC"],
        }
        with pytest.raises(ValueError, match="must be a valid decimal value"):
            Policy(**kwargs)
    else:
        amount = value if field == "amount" else "10"
        daily_spent = value if field == "daily_spent" else "0"
        with pytest.raises(ValueError, match="must be a valid decimal value"):
            TransactionRequest(amount, "0xABC", daily_spent)


def test_rule_order_prefers_amount_over_daily_and_recipient(policy: Policy) -> None:
    """Documented order: max amount, then daily limit, then recipient."""
    # amount exceeds max AND would exceed daily AND recipient not allowed
    decision = check_transaction(
        TransactionRequest("100", "0xNOT_ALLOWED", "150"), policy
    )
    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.AMOUNT_EXCEEDS_MAXIMUM

    # amount ok, daily exceeded, recipient not allowed -> daily first
    decision = check_transaction(
        TransactionRequest("40", "0xNOT_ALLOWED", "170"), policy
    )
    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED

    # only recipient fails
    decision = check_transaction(
        TransactionRequest("40", "0xNOT_ALLOWED", "100"), policy
    )
    assert decision.allowed is False
    assert decision.reason_code is DecisionReason.RECIPIENT_NOT_ALLOWED


def test_decision_to_dict_allowed():
    decision = Decision(
        allowed=True,
        reason_code=DecisionReason.ALLOWED,
        reason="Transaction is allowed by the policy."
    )

    result = decision.to_dict()

    assert result == {
        "allowed": True,
        "reason_code": "allowed",
        "reason": "Transaction is allowed by the policy."
    }


def test_decision_to_dict_denied():
    decision = Decision(
        allowed=False,
        reason_code=DecisionReason.AMOUNT_EXCEEDS_MAXIMUM,
        reason="Transaction exceeds the maximum transaction limit."
    )

    result = decision.to_dict()

    assert result == {
        "allowed": False,
        "reason_code": "amount_exceeds_maximum",
        "reason": "Transaction exceeds the maximum transaction limit."
    }
