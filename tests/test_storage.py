from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
import pytest
from agentguard.policy import DecisionReason, Policy
from agentguard.storage import IdempotencyConflict, SQLitePolicyStore

def make_policy(daily_limit="500.75"):
    return Policy("100.50", daily_limit, ["Alice", "Bob"])

def test_create_and_get_policy(tmp_path):
    store=SQLitePolicyStore(tmp_path/"p.db"); pid=store.create_policy(make_policy()); p=store.get_policy(pid)
    assert p is not None and p.max_transaction==Decimal("100.50")
    assert p.daily_limit==Decimal("500.75") and p.allowed_recipients==frozenset({"alice","bob"})

def test_policy_persists_after_reopening_store(tmp_path):
    path=tmp_path/"p.db"; pid=SQLitePolicyStore(path).create_policy(make_policy())
    assert SQLitePolicyStore(path).get_policy(pid).max_transaction==Decimal("100.50")

def test_each_policy_gets_a_unique_id(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); assert s.create_policy(make_policy())!=s.create_policy(make_policy())

def test_unknown_policy_returns_none(tmp_path):
    assert SQLitePolicyStore(tmp_path/"p.db").get_policy("unknown") is None

def test_allowed_amount_is_reserved_and_persists(tmp_path):
    path=tmp_path/"p.db"; s=SQLitePolicyStore(path); pid=s.create_policy(make_policy("100"))
    assert s.evaluate_and_reserve(pid,"60","Alice","r1").allowed
    second=SQLitePolicyStore(path).evaluate_and_reserve(pid,"50","Bob","r2")
    assert not second.allowed and second.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED

def test_denied_requests_do_not_consume_daily_budget(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy("100"))
    assert not s.evaluate_and_reserve(pid,"10","Mallory","bad").allowed
    assert s.evaluate_and_reserve(pid,"100","Alice","good").allowed

def test_idempotent_retry_does_not_reserve_twice(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy("100"))
    first=s.evaluate_and_reserve(pid,"60","Alice","same")
    assert first==s.evaluate_and_reserve(pid,"60","Alice","same")
    assert not s.evaluate_and_reserve(pid,"50","Bob","next").allowed

def test_reusing_key_with_different_payload_conflicts(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy())
    s.evaluate_and_reserve(pid,"10","Alice","same")
    with pytest.raises(IdempotencyConflict): s.evaluate_and_reserve(pid,"11","Alice","same")

def test_idempotency_replays_across_utc_day_boundary(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy())
    d1=datetime(2026,11,3,23,59,tzinfo=timezone.utc); d2=datetime(2026,11,4,0,1,tzinfo=timezone.utc)
    first=s.evaluate_and_reserve(pid,"10","Alice","key",now=d1)
    assert first==s.evaluate_and_reserve(pid,"10","Alice","key",now=d2)
    assert s.evaluate_and_reserve(pid,"10","Alice","new",now=d2).allowed

def test_usage_resets_at_utc_midnight(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy("100"))
    d1=datetime(2026,11,3,23,59,tzinfo=timezone.utc); d2=datetime(2026,11,4,0,1,tzinfo=timezone.utc)
    assert s.evaluate_and_reserve(pid,"100","Alice","d1",now=d1).allowed
    assert s.evaluate_and_reserve(pid,"100","Alice","d2",now=d2).allowed

def test_concurrent_requests_cannot_over_reserve(tmp_path):
    s=SQLitePolicyStore(tmp_path/"p.db"); pid=s.create_policy(make_policy("100"))
    def reserve(i): return s.evaluate_and_reserve(pid,"60","Alice",f"parallel-{i}")
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(reserve,range(8)))
    assert sum(x.allowed for x in results if x is not None)==1

def test_concurrent_retries_with_same_request_id_reserve_budget_once(tmp_path):
    store = SQLitePolicyStore(tmp_path / "p.db")
    policy_id = store.create_policy(make_policy("100"))

    def reserve(_):
        return store.evaluate_and_reserve(policy_id, "60", "Alice", "same-request")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))

    assert all(result == results[0] for result in results)
    assert results[0].allowed

    # A replay must not create another reservation: only 60 of the 100
    # daily units are reserved, so a further request for 50 must be denied.
    next_request = store.evaluate_and_reserve(
        policy_id, "50", "Bob", "after-replay"
    )
    assert not next_request.allowed
    assert next_request.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED
