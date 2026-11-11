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
