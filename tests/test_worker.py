from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib

from agentguard.gateway import ExecutionOutcome, OperationStatus
from agentguard.intent import ActionIntent
from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore
from agentguard.worker import ExecutionWorker


def setup_operation(tmp_path, *, amount="10", daily_limit="100"):
    store = SQLitePolicyStore(tmp_path / "worker.db")
    token = "worker-agent-secret"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    policy_id = store.create_policy(Policy("100", daily_limit, ["Alice"]), token_hash)
    intent = ActionIntent(policy_id, amount, "Alice")
    operation = store.begin_gateway_operation(intent, token, "worker-key")
    assert operation is not None
    return store, policy_id, token, intent, operation


def test_worker_executes_queued_job_and_settles_reservation(tmp_path):
    store, policy_id, _, intent, operation = setup_operation(tmp_path)
    calls = []
    worker = ExecutionWorker(
        store,
        lambda action, operation_id: calls.append((action, operation_id)),
        "worker-a",
    )

    assert operation["status"] == "APPROVED"
    assert store.get_gateway_execution_status(operation["operation_id"]) == "QUEUED"
    assert worker.run_once() == operation["operation_id"]
    assert worker.run_once() is None
    assert len(calls) == 1
    assert calls[0][0] == intent

    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "SUCCEEDED"
    assert final["reservation_status"] == "SETTLED"
    assert store.get_gateway_execution_status(operation["operation_id"]) == "COMPLETED"


def test_denied_operation_does_not_create_execution_job(tmp_path):
    store = SQLitePolicyStore(tmp_path / "denied.db")
    token = "worker-agent-secret"
    policy_id = store.create_policy(
        Policy("5", "100", ["Alice"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    operation = store.begin_gateway_operation(
        ActionIntent(policy_id, "10", "Alice"), token, "denied-key"
    )

    assert operation is not None
    assert operation["status"] == "DENIED"
    assert store.get_gateway_execution_status(operation["operation_id"]) is None


def test_only_one_concurrent_worker_can_lease_a_queued_job(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(
            pool.map(
                lambda index: store.claim_execution_job(f"worker-{index}"),
                range(8),
            )
        )

    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1
    assert successful[0]["operation_id"] == operation["operation_id"]


def test_expired_pre_dispatch_lease_can_be_reclaimed_with_new_fence(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    base = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

    first = store.claim_execution_job("worker-old", lease_seconds=5, now=base)
    second = store.claim_execution_job(
        "worker-new", lease_seconds=5, now=base + timedelta(seconds=6)
    )

    assert first is not None and second is not None
    assert second["fencing_token"] == first["fencing_token"] + 1
    assert store.start_execution_job(
        operation["operation_id"],
        "worker-old",
        first["fencing_token"],
        now=base + timedelta(seconds=7),
    ) is False
    assert store.start_execution_job(
        operation["operation_id"],
        "worker-new",
        second["fencing_token"],
        now=base + timedelta(seconds=7),
    ) is True


def test_dispatch_started_job_is_never_released_for_automatic_replay(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    base = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    claim = store.claim_execution_job("worker-a", lease_seconds=5, now=base)
    assert claim is not None
    assert store.start_execution_job(
        operation["operation_id"],
        "worker-a",
        claim["fencing_token"],
        now=base + timedelta(seconds=1),
    ) is True

    later = store.claim_execution_job(
        "worker-b", lease_seconds=5, now=base + timedelta(hours=1)
    )
    assert later is None
    assert store.get_gateway_execution_status(operation["operation_id"]) == "DISPATCH_STARTED"


def test_reconciliation_fences_late_worker_completion_and_keeps_reservation(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    claim = store.claim_execution_job("worker-a", lease_seconds=30, now=base)
    assert claim is not None
    assert store.start_execution_job(
        operation["operation_id"],
        "worker-a",
        claim["fencing_token"],
        now=base + timedelta(seconds=1),
    ) is True

    recovered = store.recover_stale_gateway_operations(
        60,
        now=base + timedelta(hours=1),
        reason="Worker outcome could not be recovered.",
    )
    assert recovered == [operation["operation_id"]]
    assert store.complete_execution_job(
        operation["operation_id"],
        "worker-a",
        claim["fencing_token"],
        "SUCCEEDED",
        "Execution completed.",
    ) is False

    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "UNKNOWN"
    assert final["reservation_status"] == "RESERVED"
    assert store.get_gateway_execution_status(operation["operation_id"]) == "UNKNOWN"


def test_worker_exception_becomes_unknown_without_replay(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    calls = []

    def executor(intent, operation_id):
        calls.append(operation_id)
        raise RuntimeError("private executor detail")

    worker = ExecutionWorker(store, executor, "worker-a")
    assert worker.run_once() == operation["operation_id"]
    assert worker.run_once() is None
    assert calls == [operation["operation_id"]]
    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "UNKNOWN"
    assert final["reservation_status"] == "RESERVED"


def test_worker_result_persistence_failure_requires_unknown_recovery(tmp_path, monkeypatch):
    from datetime import timedelta

    store, _, _, _, operation = setup_operation(tmp_path)
    calls = []
    worker = ExecutionWorker(
        store,
        lambda intent, operation_id: calls.append(operation_id),
        "worker-a",
    )
    original_complete = store.complete_execution_job

    def fail_persist(*args, **kwargs):
        return False

    monkeypatch.setattr(store, "complete_execution_job", fail_persist)
    assert worker.run_once() is None
    assert calls == [operation["operation_id"]]
    pending = store.get_gateway_operation_by_id(operation["operation_id"])
    assert pending["status"] == "EXECUTING"
    assert pending["reservation_status"] == "RESERVED"
    assert store.get_gateway_execution_status(operation["operation_id"]) == "DISPATCH_STARTED"

    monkeypatch.setattr(store, "complete_execution_job", original_complete)
    recovered = store.recover_stale_gateway_operations(
        60,
        now=datetime.now(timezone.utc) + timedelta(minutes=2),
        reason="Worker returned but durable result persistence failed.",
    )
    assert recovered == [operation["operation_id"]]
    assert worker.run_once() is None
    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "UNKNOWN"
    assert final["reservation_status"] == "RESERVED"
    assert calls == [operation["operation_id"]]


def test_worker_typed_verified_failure_releases_reservation(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path, daily_limit="20")
    worker = ExecutionWorker(
        store,
        lambda intent, operation_id: ExecutionOutcome(
            OperationStatus.FAILED,
            no_side_effect_confirmed=True,
        ),
        "worker-a",
    )

    assert worker.run_once() == operation["operation_id"]
    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "FAILED"
    assert final["reservation_status"] == "RELEASED"


def test_unsupported_worker_output_is_unknown_and_not_persisted(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    worker = ExecutionWorker(
        store, lambda intent, operation_id: "must-not-be-persisted", "worker-a"
    )

    assert worker.run_once() == operation["operation_id"]
    final = store.get_gateway_operation_by_id(operation["operation_id"])
    assert final["status"] == "UNKNOWN"
    assert "must-not-be-persisted" not in (final["result"] or "")



def test_worker_rejects_malformed_intent_without_dispatch_and_continues_queue(tmp_path):
    store, _, _, _, malformed = setup_operation(tmp_path)
    token = "worker-agent-secret"
    policy_id = store.create_policy(
        Policy("100", "100", ["Alice"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    valid = store.begin_gateway_operation(
        ActionIntent(policy_id, "11", "Alice"), token, "worker-key-valid"
    )
    assert valid is not None

    # Make the malformed operation deterministically older so it is claimed first.
    connection = store._connect()
    try:
        connection.execute(
            "UPDATE gateway_operations SET canonical_intent = ? WHERE operation_id = ?",
            ("{not-json", malformed["operation_id"]),
        )
        connection.execute(
            "UPDATE gateway_operations SET created_at = '2000-01-01T00:00:00+00:00' WHERE operation_id = ?",
            (malformed["operation_id"],),
        )
        connection.execute(
            "UPDATE gateway_execution_jobs SET created_at = '2000-01-01T00:00:00+00:00' WHERE operation_id = ?",
            (malformed["operation_id"],),
        )
        connection.commit()
    finally:
        connection.close()

    calls = []
    worker = ExecutionWorker(
        store,
        lambda intent, operation_id: calls.append(operation_id),
        "worker-a",
    )

    assert worker.run_once() == malformed["operation_id"]
    rejected = store.get_gateway_operation_by_id(malformed["operation_id"])
    assert rejected["status"] == "FAILED"
    assert rejected["reservation_status"] == "RELEASED"
    assert store.get_gateway_execution_status(malformed["operation_id"]) == "COMPLETED"
    events = store.list_gateway_operation_events(malformed["operation_id"])
    assert events[-1]["event_type"] == "PRE_DISPATCH_VALIDATION_FAILED"
    assert calls == []

    assert worker.run_once() == valid["operation_id"]
    assert calls == [valid["operation_id"]]


def test_worker_rejects_non_object_and_unsupported_intent_versions(tmp_path):
    import json
    import pytest

    _, _, _, _, operation = setup_operation(tmp_path)

    with pytest.raises(ValueError, match="object shape"):
        ExecutionWorker._load_intent("[]")

    payload = json.loads(operation["canonical_intent"])
    payload["version"] = 2
    with pytest.raises(ValueError, match="version"):
        ExecutionWorker._load_intent(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def test_worker_rejects_invalid_intent_field_types_and_noncanonical_json(tmp_path):
    import json
    import pytest

    store, _, _, _, operation = setup_operation(tmp_path)
    payload = json.loads(operation["canonical_intent"])

    wrong_type = dict(payload)
    wrong_type["amount"] = 10
    with pytest.raises(ValueError, match="field types"):
        ExecutionWorker._load_intent(json.dumps(wrong_type, separators=(",", ":"), sort_keys=True))

    missing_field = dict(payload)
    del missing_field["recipient"]
    with pytest.raises(ValueError, match="object shape"):
        ExecutionWorker._load_intent(json.dumps(missing_field, separators=(",", ":"), sort_keys=True))

    noncanonical = json.dumps(payload)
    with pytest.raises(ValueError, match="canonical representation"):
        ExecutionWorker._load_intent(noncanonical)


def test_pre_dispatch_failure_is_fenced_from_reclaimed_worker(tmp_path):
    store, _, _, _, operation = setup_operation(tmp_path)
    base = datetime.now(timezone.utc)
    first = store.claim_execution_job("worker-old", lease_seconds=5, now=base)
    second = store.claim_execution_job(
        "worker-new", lease_seconds=30, now=base + timedelta(seconds=6)
    )
    assert first is not None and second is not None

    assert store.fail_pre_dispatch_validation(
        operation["operation_id"], "worker-old", first["fencing_token"]
    ) is False
    current = store.get_gateway_operation_by_id(operation["operation_id"])
    assert current["status"] == "APPROVED"
    assert current["reservation_status"] == "RESERVED"
    assert store.get_gateway_execution_status(operation["operation_id"]) == "LEASED"
