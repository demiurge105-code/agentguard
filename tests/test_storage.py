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


def test_evm_chain_id_and_canonical_allowlist_persist(tmp_path):
    store = SQLitePolicyStore(tmp_path / "evm.db")
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    policy_id = store.create_policy(
        Policy("100", "200", [address], chain_id="eip155:8453")
    )

    loaded = store.get_policy(policy_id)

    assert loaded is not None
    assert loaded.chain_id == "eip155:8453"
    assert loaded.allowed_recipients == frozenset({address.lower()})


def test_evm_idempotency_compares_canonical_addresses(tmp_path):
    store = SQLitePolicyStore(tmp_path / "evm.db")
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    policy_id = store.create_policy(
        Policy("100", "100", [address], chain_id="eip155:1")
    )

    first = store.evaluate_and_reserve(policy_id, "60", address, "same")
    replay = store.evaluate_and_reserve(policy_id, "60", address.lower(), "same")
    next_request = store.evaluate_and_reserve(
        policy_id, "50", address, "after-replay"
    )

    assert first == replay
    assert first.allowed is True
    assert next_request.allowed is False
    assert next_request.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED


def test_evm_storage_rejects_malformed_recipient_before_reserving(tmp_path):
    store = SQLitePolicyStore(tmp_path / "evm.db")
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    policy_id = store.create_policy(
        Policy("100", "200", [address], chain_id="eip155:1")
    )

    with pytest.raises(ValueError, match="20-byte hexadecimal"):
        store.evaluate_and_reserve(policy_id, "10", "Alice", "invalid")

    # The rejected input did not create an idempotency record.
    allowed = store.evaluate_and_reserve(policy_id, "10", address, "invalid")
    assert allowed.allowed is True


def test_existing_schema_migrates_chain_id_as_legacy(tmp_path):
    import sqlite3

    path = tmp_path / "before-chain-id.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """CREATE TABLE policies (
                policy_id TEXT PRIMARY KEY,
                max_transaction TEXT NOT NULL,
                daily_limit TEXT NOT NULL,
                allowed_recipients TEXT NOT NULL,
                created_at TEXT NOT NULL,
                agent_token_hash TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO policies VALUES (?, ?, ?, ?, ?, ?)",
            ("legacy-policy", "100", "200", '["alice"]', "2026-11-07T00:00:00+00:00", None),
        )
        connection.commit()
    finally:
        connection.close()

    migrated = SQLitePolicyStore(path)
    policy = migrated.get_policy("legacy-policy")

    assert policy is not None
    assert policy.chain_id is None
    assert migrated.evaluate_and_reserve(
        "legacy-policy", "10", "ALICE", "legacy"
    ).allowed


def test_authenticated_reservation_checks_current_token_inside_transaction(tmp_path):
    import hashlib

    store = SQLitePolicyStore(tmp_path / "authenticated.db")
    old_token = "old-agent-token"
    new_token = "new-agent-token"
    policy_id = store.create_policy(
        make_policy("100"),
        hashlib.sha256(old_token.encode("utf-8")).hexdigest(),
    )

    first = store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "60", "Alice", "authenticated"
    )
    assert first is not None and first.allowed

    assert store.rotate_agent_token(
        policy_id, hashlib.sha256(new_token.encode("utf-8")).hexdigest()
    )

    # A request arriving with the revoked token after rotation cannot reserve.
    assert store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "10", "Alice", "revoked"
    ) is None

    # The replacement token remains usable and prior reservations still count.
    denied = store.evaluate_and_reserve_authenticated(
        policy_id, new_token, "50", "Bob", "new-token-request"
    )
    assert denied is not None
    assert denied.allowed is False
    assert denied.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED


def test_authenticated_idempotent_retry_requires_current_token(tmp_path):
    import hashlib

    store = SQLitePolicyStore(tmp_path / "authenticated-retry.db")
    old_token = "old-agent-token"
    new_token = "new-agent-token"
    policy_id = store.create_policy(
        make_policy("100"),
        hashlib.sha256(old_token.encode("utf-8")).hexdigest(),
    )

    first = store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "60", "Alice", "same-request"
    )
    replay = store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "60", "Alice", "same-request"
    )
    assert first == replay

    store.rotate_agent_token(
        policy_id, hashlib.sha256(new_token.encode("utf-8")).hexdigest()
    )
    assert store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "60", "Alice", "same-request"
    ) is None
    assert store.evaluate_and_reserve_authenticated(
        policy_id, new_token, "60", "Alice", "same-request"
    ) == first


def test_concurrent_rotation_and_authenticated_reservation_are_serialized(tmp_path):
    import hashlib
    from threading import Barrier

    store = SQLitePolicyStore(tmp_path / "rotation-race.db")
    old_token = "old-agent-token"
    new_token = "new-agent-token"
    policy_id = store.create_policy(
        make_policy("500"),
        hashlib.sha256(old_token.encode("utf-8")).hexdigest(),
    )
    start = Barrier(3)

    def reserve_with_old_token():
        start.wait()
        return store.evaluate_and_reserve_authenticated(
            policy_id, old_token, "10", "Alice", "racing-request"
        )

    def rotate():
        start.wait()
        return store.rotate_agent_token(
            policy_id, hashlib.sha256(new_token.encode("utf-8")).hexdigest()
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        reserve_future = pool.submit(reserve_with_old_token)
        rotate_future = pool.submit(rotate)
        start.wait()
        reservation = reserve_future.result()
        assert rotate_future.result() is True

    # The in-flight request either committed before rotation or observed the
    # replacement token. Once rotation returns, the old token must always fail.
    assert reservation is None or reservation.allowed
    assert store.evaluate_and_reserve_authenticated(
        policy_id, old_token, "10", "Alice", "after-rotation-old"
    ) is None
    assert store.evaluate_and_reserve_authenticated(
        policy_id, new_token, "10", "Alice", "after-rotation-new"
    ) is not None


def test_in_memory_database_is_rejected():
    with pytest.raises(ValueError, match="file-based database path"):
        SQLitePolicyStore(":memory:")


def test_path_object_for_in_memory_database_is_rejected():
    from pathlib import Path

    with pytest.raises(ValueError, match="file-based database path"):
        SQLitePolicyStore(Path(":memory:"))
