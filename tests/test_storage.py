from decimal import Decimal

from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore


def make_policy() -> Policy:
    return Policy(
        max_transaction="100.50",
        daily_limit="500.75",
        allowed_recipients=["Alice", "Bob"],
    )


def test_create_and_get_policy(tmp_path):
    store = SQLitePolicyStore(tmp_path / "policies.db")

    policy_id = store.create_policy(make_policy())
    stored = store.get_policy(policy_id)

    assert stored is not None
    assert stored.max_transaction == Decimal("100.50")
    assert stored.daily_limit == Decimal("500.75")
    assert stored.allowed_recipients == frozenset({"alice", "bob"})


def test_policy_persists_after_reopening_store(tmp_path):
    db_path = tmp_path / "policies.db"

    first_store = SQLitePolicyStore(db_path)
    policy_id = first_store.create_policy(make_policy())

    second_store = SQLitePolicyStore(db_path)
    stored = second_store.get_policy(policy_id)

    assert stored is not None
    assert stored.max_transaction == Decimal("100.50")


def test_each_policy_gets_a_unique_id(tmp_path):
    store = SQLitePolicyStore(tmp_path / "policies.db")

    first_id = store.create_policy(make_policy())
    second_id = store.create_policy(make_policy())

    assert first_id != second_id


def test_unknown_policy_returns_none(tmp_path):
    store = SQLitePolicyStore(tmp_path / "policies.db")

    assert store.get_policy("unknown-id") is None
