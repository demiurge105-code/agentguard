from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import hashlib
from threading import Lock
import time

import pytest

from agentguard.gateway import (
    GatewayAuthenticationError,
    OperationStatus,
    TrustedExecutionGateway,
)
from agentguard.intent import ActionIntent
from agentguard.policy import Policy
from agentguard.storage import IdempotencyConflict, SQLitePolicyStore


def make_store(tmp_path, *, max_transaction="100", daily_limit="200"):
    store = SQLitePolicyStore(tmp_path / "gateway.db")
    token = "gateway-agent-secret"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    policy_id = store.create_policy(
        Policy(max_transaction, daily_limit, ["Alice", "Bob"]),
        token_hash,
    )
    return store, policy_id, token


def make_intent(policy_id, amount="10", recipient="Alice"):
    return ActionIntent(policy_id, amount, recipient)


def test_gateway_executes_approved_intent_and_persists_success(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    calls = []

    def executor(intent, operation_id):
        calls.append((intent, operation_id))
        return None

    gateway = TrustedExecutionGateway(store, executor)
    intent = make_intent(policy_id)

    result = gateway.submit(intent, token, "operation-1")

    assert result.status is OperationStatus.SUCCEEDED
    assert result.allowed is True
    assert result.result == "Execution completed."
    assert len(calls) == 1
    assert calls[0] == (intent, result.operation_id)
    assert store.get_gateway_operation(policy_id, "operation-1")["status"] == "SUCCEEDED"


def test_exact_retry_returns_stored_result_without_second_execution(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    intent = make_intent(policy_id)

    first = gateway.submit(intent, token, "same-key")
    retry = gateway.submit(intent, token, "same-key")

    assert retry == first
    assert len(calls) == 1


@pytest.mark.parametrize(
    "different_intent",
    [
        "amount",
        "recipient",
        "chain",
    ],
)
def test_same_key_with_different_intent_conflicts(tmp_path, different_intent):
    store, policy_id, token = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    first_intent = make_intent(policy_id)
    gateway.submit(first_intent, token, "conflicting-key")

    if different_intent == "amount":
        changed = make_intent(policy_id, amount="11")
    elif different_intent == "recipient":
        changed = make_intent(policy_id, recipient="Bob")
    else:
        changed = ActionIntent(
            policy_id,
            "10",
            "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
            chain_id="eip155:1",
        )

    with pytest.raises(IdempotencyConflict):
        gateway.submit(changed, token, "conflicting-key")

    assert len(calls) == 1


def test_same_idempotency_key_under_different_policy_conflicts(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    gateway.submit(make_intent(policy_id), token, "global-key")

    second_policy_id = store.create_policy(
        Policy("100", "200", ["Alice", "Bob"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    with pytest.raises(IdempotencyConflict):
        gateway.submit(make_intent(second_policy_id), token, "global-key")

    assert len(calls) == 1


def test_invalid_token_does_not_reserve_or_execute(tmp_path):
    store, policy_id, _ = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id)
    )

    with pytest.raises(GatewayAuthenticationError):
        gateway.submit(make_intent(policy_id), "wrong-token", "invalid-auth")

    assert calls == []
    connection = store._connect()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM gateway_operations"
        ).fetchone()[0]
        reservations = connection.execute(
            "SELECT COUNT(*) FROM daily_reservations"
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == 0
    assert reservations == 0


def test_token_revoked_between_reservation_and_claim_blocks_execution(tmp_path):
    store, policy_id, old_token = make_store(tmp_path)
    intent = make_intent(policy_id)
    record = store.begin_gateway_operation(intent, old_token, "revoke-before-claim")

    new_token = "new-token-before-claim"
    store.rotate_agent_token(
        policy_id,
        hashlib.sha256(new_token.encode("utf-8")).hexdigest(),
    )

    assert store.authenticate_agent(policy_id, old_token) is False
    assert store.authenticate_agent(policy_id, new_token) is True
    assert store.claim_gateway_operation(record["operation_id"], old_token) is None
    assert store.get_gateway_operation(policy_id, "revoke-before-claim")["status"] == "CANCELLED"

    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda action, operation_id: calls.append(operation_id) or None
    )
    result = gateway.submit(intent, new_token, "revoke-before-claim")

    # The idempotency key is already bound to the cancelled operation.
    # A retry with the rotated token must return that terminal result,
    # not create a replacement operation or invoke the executor.
    assert result.status is OperationStatus.CANCELLED
    assert result.operation_id == record["operation_id"]
    assert calls == []


def test_revoked_token_cannot_replay_existing_operation(tmp_path):
    store, policy_id, old_token = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    intent = make_intent(policy_id)
    gateway.submit(intent, old_token, "rotate-before-retry")

    new_token = "replacement-token"
    store.rotate_agent_token(
        policy_id,
        hashlib.sha256(new_token.encode("utf-8")).hexdigest(),
    )

    with pytest.raises(GatewayAuthenticationError):
        gateway.submit(intent, old_token, "rotate-before-retry")

    assert len(calls) == 1


def test_failed_execution_claim_never_invokes_executor(tmp_path, monkeypatch):
    store, policy_id, token = make_store(tmp_path)
    calls = []

    def fail_claim(operation_id, agent_token):
        raise OSError("database unavailable")

    monkeypatch.setattr(store, "claim_gateway_operation", fail_claim)
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )

    with pytest.raises(OSError, match="database unavailable"):
        gateway.submit(make_intent(policy_id), token, "claim-failure")

    assert calls == []


def test_failed_completion_persistence_does_not_retry_executor(tmp_path, monkeypatch):
    store, policy_id, token = make_store(tmp_path)
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    original_complete = store.complete_gateway_operation

    def fail_completion(operation_id, status, result=None):
        return False

    monkeypatch.setattr(store, "complete_gateway_operation", fail_completion)
    with pytest.raises(RuntimeError, match="could not be persisted"):
        gateway.submit(make_intent(policy_id), token, "completion-failure")

    monkeypatch.setattr(store, "complete_gateway_operation", original_complete)
    retry = gateway.submit(make_intent(policy_id), token, "completion-failure")

    assert retry.status is OperationStatus.EXECUTING
    assert len(calls) == 1


def test_policy_denial_never_calls_executor(tmp_path):
    store, policy_id, token = make_store(tmp_path, max_transaction="5")
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id)
    )

    result = gateway.submit(make_intent(policy_id, amount="10"), token, "denied")

    assert result.status is OperationStatus.DENIED
    assert result.allowed is False
    assert calls == []


def test_executor_exception_becomes_unknown_and_is_not_retried(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    calls = []

    def broken_executor(intent, operation_id):
        calls.append(operation_id)
        raise RuntimeError("sensitive executor details must not be stored")

    gateway = TrustedExecutionGateway(store, broken_executor)
    intent = make_intent(policy_id)

    first = gateway.submit(intent, token, "executor-error")
    retry = gateway.submit(intent, token, "executor-error")

    assert first.status is OperationStatus.UNKNOWN
    assert retry == first
    assert len(calls) == 1
    assert first.result == "Executor raised an exception; outcome may be unknown."


def test_unsupported_executor_output_is_not_persisted(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: "secret-looking-output"
    )

    result = gateway.submit(make_intent(policy_id), token, "unsupported-output")

    assert result.status is OperationStatus.UNKNOWN
    assert result.result == "Executor returned unsupported data; outcome may be unknown."
    assert "secret-looking-output" not in (result.result or "")


def test_successful_operation_reserves_budget_only_once(tmp_path):
    store, policy_id, token = make_store(tmp_path, daily_limit="20")
    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    intent = make_intent(policy_id, amount="10")

    first = gateway.submit(intent, token, "budget-once")
    retry = gateway.submit(intent, token, "budget-once")
    second_operation = gateway.submit(
        make_intent(policy_id, amount="11"), token, "budget-next"
    )

    assert first == retry
    assert first.status is OperationStatus.SUCCEEDED
    assert second_operation.status is OperationStatus.DENIED
    assert len(calls) == 1


def test_crash_after_durable_claim_never_triggers_automatic_retry(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    intent = make_intent(policy_id)
    record = store.begin_gateway_operation(intent, token, "crash-after-claim")
    assert record["status"] == "APPROVED"
    assert store.claim_gateway_operation(record["operation_id"], token) is True

    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda action, operation_id: calls.append(operation_id)
    )
    result = gateway.submit(intent, token, "crash-after-claim")

    assert result.status is OperationStatus.EXECUTING
    assert calls == []


def test_concurrent_exact_retries_invoke_executor_at_most_once(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    calls = []
    lock = Lock()

    def executor(intent, operation_id):
        with lock:
            calls.append(operation_id)
        time.sleep(0.05)
        return None

    gateway = TrustedExecutionGateway(store, executor)
    intent = make_intent(policy_id)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: gateway.submit(intent, token, "concurrent-key"),
                range(8),
            )
        )

    assert len(calls) == 1
    assert {result.operation_id for result in results} == {results[0].operation_id}
    assert store.get_gateway_operation(policy_id, "concurrent-key")["status"] == "SUCCEEDED"


def test_executor_receives_the_same_immutable_intent_that_was_canonicalized(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    observed = []
    gateway = TrustedExecutionGateway(
        store,
        lambda intent, operation_id: observed.append(
            (intent, intent.canonical_json, operation_id)
        ) and None,
    )
    intent = make_intent(policy_id, amount="10.00")

    result = gateway.submit(intent, token, "same-object")

    assert observed == [(intent, intent.canonical_json, result.operation_id)]
    assert Decimal(intent.amount) == Decimal("10.00")
    assert result.status is OperationStatus.SUCCEEDED


def test_chain_context_must_match_stored_policy(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    intent = ActionIntent(
        policy_id,
        "1",
        "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
        chain_id="eip155:1",
    )
    gateway = TrustedExecutionGateway(store, lambda action, operation_id: "never")

    with pytest.raises(ValueError, match="chain_id"):
        gateway.submit(intent, token, "wrong-chain")


def test_operation_key_is_separate_from_legacy_reservation_ids(tmp_path):
    store, policy_id, token = make_store(tmp_path)
    legacy = store.evaluate_and_reserve(
        policy_id, "10", "Alice", "shared-key"
    )
    assert legacy is not None and legacy.allowed

    calls = []
    gateway = TrustedExecutionGateway(
        store, lambda intent, operation_id: calls.append(operation_id) or None
    )
    result = gateway.submit(make_intent(policy_id), token, "shared-key")

    assert result.status is OperationStatus.SUCCEEDED
    assert len(calls) == 1


def test_typed_verified_failure_releases_daily_budget(tmp_path):
    from agentguard.gateway import ExecutionOutcome
    store, policy_id, token = make_store(tmp_path, daily_limit="20")
    gateway = TrustedExecutionGateway(store, lambda intent, operation_id: ExecutionOutcome(OperationStatus.FAILED, no_side_effect_confirmed=True))
    failed = gateway.submit(make_intent(policy_id, "10"), token, "verified-failure")
    assert failed.status is OperationStatus.FAILED
    assert store.get_gateway_operation_by_id(failed.operation_id)["reservation_status"] == "RELEASED"
    successful = TrustedExecutionGateway(store, lambda intent, operation_id: None).submit(make_intent(policy_id, "15"), token, "after-verified-failure")
    assert successful.status is OperationStatus.SUCCEEDED


def test_unknown_executor_outcome_keeps_budget_reserved(tmp_path):
    from agentguard.gateway import ExecutionOutcome
    store, policy_id, token = make_store(tmp_path, daily_limit="20")
    gateway = TrustedExecutionGateway(store, lambda intent, operation_id: ExecutionOutcome(OperationStatus.UNKNOWN))
    unknown = gateway.submit(make_intent(policy_id, "10"), token, "unknown-outcome")
    assert unknown.status is OperationStatus.UNKNOWN
    assert store.get_gateway_operation_by_id(unknown.operation_id)["reservation_status"] == "RESERVED"
    denied = TrustedExecutionGateway(store, lambda intent, operation_id: None).submit(make_intent(policy_id, "11"), token, "after-unknown")
    assert denied.status is OperationStatus.DENIED


def test_execution_outcome_rejects_failed_without_no_side_effect_proof():
    from agentguard.gateway import ExecutionOutcome
    with pytest.raises(ValueError, match="no side effect"):
        ExecutionOutcome(OperationStatus.FAILED)
