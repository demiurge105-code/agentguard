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



@pytest.mark.parametrize("amount", [0.1, 1.5, True, False])
def test_storage_rejects_float_and_boolean_amounts_before_reserving(tmp_path, amount):
    store = SQLitePolicyStore(tmp_path / "strict-decimal.db")
    policy_id = store.create_policy(make_policy("100"))

    with pytest.raises(ValueError, match="Decimal or decimal string"):
        store.evaluate_and_reserve(policy_id, amount, "Alice", "invalid-number")

    # Reusing the same key with a valid decimal proves the rejected input
    # did not create an idempotency reservation.
    decision = store.evaluate_and_reserve(
        policy_id, "10", "Alice", "invalid-number"
    )
    assert decision.allowed is True



def test_daily_reservation_aggregation_does_not_round_away_prior_spending(tmp_path):
    store = SQLitePolicyStore(tmp_path / "exact-daily-total.db")
    policy_id = store.create_policy(
        Policy("1E+28", "10000000000000000000000000001", ["Alice"])
    )

    first = store.evaluate_and_reserve(policy_id, "1E+28", "Alice", "large")
    second = store.evaluate_and_reserve(policy_id, "1", "Alice", "small-1")
    third = store.evaluate_and_reserve(policy_id, "1", "Alice", "small-2")

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert third.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED



def test_exact_aggregate_at_daily_limit_is_denied_without_validation_error(tmp_path):
    store = SQLitePolicyStore(tmp_path / "aggregate-coefficient-boundary.db")
    policy_id = store.create_policy(Policy("1", "1", ["Alice"]))

    almost_one = "0." + "9" * 128
    first = store.evaluate_and_reserve(policy_id, almost_one, "Alice", "almost-one")
    second = store.evaluate_and_reserve(policy_id, "1E-128", "Alice", "complete-one")
    third = store.evaluate_and_reserve(policy_id, "1E-128", "Alice", "over-limit")

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert third.reason_code is DecisionReason.DAILY_LIMIT_EXCEEDED


def test_gateway_audit_events_record_each_state_transition_atomically(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent

    store = SQLitePolicyStore(tmp_path / "audit.db")
    token = "audit-agent-token"
    policy_id = store.create_policy(
        Policy("100", "200", ["Alice"]),
        hashlib.sha256(token.encode()).hexdigest(),
    )
    operation = store.begin_gateway_operation(
        ActionIntent(policy_id, "10", "Alice"), token, "audit-key"
    )
    assert [event["new_status"] for event in store.list_gateway_operation_events(operation["operation_id"])] == ["APPROVED"]
    assert store.claim_gateway_operation(operation["operation_id"], token) is True
    assert store.complete_gateway_operation(operation["operation_id"], "SUCCEEDED", "Execution completed.") is True
    events = store.list_gateway_operation_events(operation["operation_id"])
    assert [(event["previous_status"], event["new_status"]) for event in events] == [
        (None, "APPROVED"), ("APPROVED", "EXECUTING"),
        ("EXECUTING", "SUCCEEDED"), ("SUCCEEDED", "SUCCEEDED"),
    ]


def test_gateway_audit_insert_failure_rolls_back_operation_and_reservation(tmp_path, monkeypatch):
    import hashlib
    from agentguard.intent import ActionIntent

    store = SQLitePolicyStore(tmp_path / "audit-atomic.db")
    token = "audit-agent-token"
    policy_id = store.create_policy(Policy("100", "200", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    original = store._insert_gateway_event
    monkeypatch.setattr(store, "_insert_gateway_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("audit insert failed")))
    with pytest.raises(RuntimeError, match="audit insert failed"):
        store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "audit-rollback")
    monkeypatch.setattr(store, "_insert_gateway_event", original)
    connection = store._connect()
    try:
        assert connection.execute("SELECT COUNT(*) FROM gateway_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM daily_reservations").fetchone()[0] == 0
    finally:
        connection.close()


def test_owner_reconciliation_records_reason_and_never_retries(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent

    store = SQLitePolicyStore(tmp_path / "audit-reconcile.db")
    token = "audit-agent-token"
    policy_id = store.create_policy(Policy("100", "200", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "reconcile-key")
    assert store.claim_gateway_operation(operation["operation_id"], token) is True
    assert store.reconcile_gateway_operation_unknown(operation["operation_id"], "owner", "Process restarted; outcome unknown.") is True
    assert store.reconcile_gateway_operation_unknown(operation["operation_id"], "owner", "Duplicate reconciliation.") is False
    assert store.claim_gateway_operation(operation["operation_id"], token) is False
    events = store.list_gateway_operation_events(operation["operation_id"])
    assert events[-1]["event_type"] == "MANUAL_RECONCILIATION"
    assert events[-1]["actor_type"] == "owner"
    assert events[-1]["reason"] == "Process restarted; outcome unknown."


def test_reconciliation_requires_bounded_nonempty_reason(tmp_path):
    store = SQLitePolicyStore(tmp_path / "audit-reason.db")
    with pytest.raises(ValueError, match="reason"):
        store.reconcile_gateway_operation_unknown("missing", "owner", "  ")
    with pytest.raises(ValueError, match="reason"):
        store.reconcile_gateway_operation_unknown("missing", "owner", "x" * 501)


def test_concurrent_owner_reconciliation_creates_only_one_event(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent

    store = SQLitePolicyStore(tmp_path / "audit-race.db")
    token = "audit-agent-token"
    policy_id = store.create_policy(Policy("100", "200", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "reconcile-race")
    store.claim_gateway_operation(operation["operation_id"], token)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(
            lambda i: store.reconcile_gateway_operation_unknown(operation["operation_id"], "owner", f"Operator review {i}."),
            range(8),
        ))
    assert sum(results) == 1
    events = store.list_gateway_operation_events(operation["operation_id"])
    assert sum(event["event_type"] == "MANUAL_RECONCILIATION" for event in events) == 1


def test_gateway_success_settles_reservation_and_keeps_daily_usage(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "settle-success.db")
    token = "settle-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "settle-success")
    assert operation["reservation_status"] == "RESERVED"
    assert store.claim_gateway_operation(operation["operation_id"], token)
    assert store.complete_gateway_operation(operation["operation_id"], "SUCCEEDED", "Execution completed.")
    inspected = store.get_gateway_operation_by_id(operation["operation_id"])
    assert inspected["reservation_status"] == "SETTLED"
    denied = store.begin_gateway_operation(ActionIntent(policy_id, "11", "Alice"), token, "after-settlement")
    assert denied["status"] == "DENIED"
    assert store.list_gateway_operation_events(operation["operation_id"])[-1]["event_type"] == "RESERVATION_SETTLED"


def test_verified_failure_releases_reservation_and_allows_new_budget(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "release-failure.db")
    token = "release-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "release-failure")
    assert store.claim_gateway_operation(operation["operation_id"], token)
    assert store.complete_gateway_operation(operation["operation_id"], "FAILED", "Trusted executor confirmed no side effect occurred.", no_side_effect_confirmed=True)
    inspected = store.get_gateway_operation_by_id(operation["operation_id"])
    assert inspected["status"] == "FAILED" and inspected["reservation_status"] == "RELEASED"
    next_operation = store.begin_gateway_operation(ActionIntent(policy_id, "15", "Alice"), token, "after-release")
    assert next_operation["status"] == "APPROVED"


def test_released_gateway_budget_is_available_to_legacy_endpoint(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "legacy-after-release.db")
    token = "legacy-release-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "legacy-release")
    store.claim_gateway_operation(operation["operation_id"], token)
    assert store.complete_gateway_operation(operation["operation_id"], "FAILED", no_side_effect_confirmed=True)
    decision = store.evaluate_and_reserve(policy_id, "15", "Alice", "legacy-after-release")
    assert decision.allowed is True

def test_failed_status_requires_explicit_no_side_effect_confirmation(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "failed-proof-required.db")
    token = "proof-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "proof-required")
    store.claim_gateway_operation(operation["operation_id"], token)
    with pytest.raises(ValueError, match="no side effect"):
        store.complete_gateway_operation(operation["operation_id"], "FAILED")
    inspected = store.get_gateway_operation_by_id(operation["operation_id"])
    assert inspected["status"] == "EXECUTING" and inspected["reservation_status"] == "RESERVED"


def test_unknown_keeps_reservation_active(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "unknown-reservation.db")
    token = "unknown-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "unknown-reservation")
    store.claim_gateway_operation(operation["operation_id"], token)
    assert store.complete_gateway_operation(operation["operation_id"], "UNKNOWN")
    assert store.get_gateway_operation_by_id(operation["operation_id"])["reservation_status"] == "RESERVED"


def test_gateway_completion_is_atomic_with_audit_and_reservation(tmp_path, monkeypatch):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "completion-rollback.db")
    token = "rollback-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "completion-rollback")
    store.claim_gateway_operation(operation["operation_id"], token)
    monkeypatch.setattr(store, "_insert_gateway_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("audit write failed")))
    with pytest.raises(RuntimeError, match="audit write failed"):
        store.complete_gateway_operation(operation["operation_id"], "SUCCEEDED")
    inspected = store.get_gateway_operation_by_id(operation["operation_id"])
    assert inspected["status"] == "EXECUTING" and inspected["reservation_status"] == "RESERVED"


def test_concurrent_completion_settles_reservation_once(tmp_path):
    import hashlib
    from agentguard.intent import ActionIntent
    store = SQLitePolicyStore(tmp_path / "completion-race.db")
    token = "race-token"
    policy_id = store.create_policy(Policy("100", "20", ["Alice"]), hashlib.sha256(token.encode()).hexdigest())
    operation = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, "completion-race")
    store.claim_gateway_operation(operation["operation_id"], token)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.complete_gateway_operation(operation["operation_id"], "SUCCEEDED"), range(8)))
    assert sum(results) == 1
    events = store.list_gateway_operation_events(operation["operation_id"])
    assert sum(event["event_type"] == "RESERVATION_SETTLED" for event in events) == 1
    assert store.get_gateway_operation_by_id(operation["operation_id"])["reservation_status"] == "SETTLED"


def test_old_reservation_schema_migrates_conservatively(tmp_path):
    import sqlite3
    path = tmp_path / "old-reservations.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE policies (policy_id TEXT PRIMARY KEY, max_transaction TEXT NOT NULL, daily_limit TEXT NOT NULL, allowed_recipients TEXT NOT NULL, created_at TEXT NOT NULL, chain_id TEXT, agent_token_hash TEXT)")
        connection.execute("INSERT INTO policies VALUES (?, ?, ?, ?, ?, ?, ?)", ("policy", "100", "200", '["alice"]', "2026-11-11T00:00:00+00:00", None, None))
        connection.execute("CREATE TABLE daily_reservations (policy_id TEXT NOT NULL, request_id TEXT NOT NULL, utc_day TEXT NOT NULL, amount TEXT NOT NULL, recipient TEXT NOT NULL, allowed INTEGER NOT NULL, reason_code TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY (policy_id, request_id))")
        connection.execute("INSERT INTO daily_reservations VALUES ('policy', 'gateway:pending-op', '2026-11-11', '10', 'alice', 1, 'allowed', 'ok')")
        connection.execute("INSERT INTO daily_reservations VALUES ('policy', 'legacy-check', '2026-11-11', '5', 'alice', 1, 'allowed', 'ok')")
        connection.execute("CREATE TABLE gateway_operations (operation_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, canonical_intent TEXT NOT NULL, status TEXT NOT NULL, allowed INTEGER NOT NULL, reason_code TEXT NOT NULL, reason TEXT NOT NULL, result TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE (idempotency_key))")
        connection.execute("INSERT INTO gateway_operations VALUES ('pending-op', 'policy', 'pending-key', '{}', 'EXECUTING', 1, 'allowed', 'ok', NULL, '2026-11-11T00:00:00+00:00', '2026-11-11T00:00:00+00:00')")
        connection.commit()
    finally:
        connection.close()
    migrated = SQLitePolicyStore(path)
    connection = migrated._connect()
    try:
        states = {row["request_id"]: row["reservation_status"] for row in connection.execute("SELECT request_id, reservation_status FROM daily_reservations")}
    finally:
        connection.close()
    assert states == {"gateway:pending-op": "RESERVED", "legacy-check": "SETTLED"}
