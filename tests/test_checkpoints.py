import hashlib
import json
import sqlite3

import pytest

from agentguard.checkpoints import CheckpointError, create_gateway_checkpoint, verify_gateway_checkpoint
from agentguard.intent import ActionIntent
from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore


def make_store(path):
    store = SQLitePolicyStore(path)
    token = "checkpoint-test-agent-token"
    policy_id = store.create_policy(
        Policy("100", "500", ["Alice"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    return store, policy_id, token


def create_operation(store, policy_id, token, key):
    result = store.begin_gateway_operation(ActionIntent(policy_id, "10", "Alice"), token, key)
    assert result is not None
    return result["operation_id"]


def test_checkpoint_export_and_verification_uses_opaque_refs(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint.db")
    operation_id = create_operation(store, policy_id, token, "checkpoint-first")
    checkpoint_json = create_gateway_checkpoint(store)
    checkpoint = json.loads(checkpoint_json)

    assert checkpoint["sequence"] == 1
    assert checkpoint["operation_count"] == 1
    assert checkpoint["operations"][0]["event_count"] == 1
    assert operation_id not in checkpoint_json
    assert policy_id not in checkpoint_json
    assert "Alice" not in checkpoint_json
    assert token not in checkpoint_json
    assert verify_gateway_checkpoint(store, checkpoint_json)["valid"] is True


def test_checkpoint_allows_appended_events_and_new_operations(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint-append.db")
    operation_id = create_operation(store, policy_id, token, "checkpoint-append")
    checkpoint_json = create_gateway_checkpoint(store)

    assert store.claim_gateway_operation(operation_id, token) is True
    create_operation(store, policy_id, token, "operation-created-after-checkpoint")
    assert verify_gateway_checkpoint(store, checkpoint_json)["valid"] is True


def test_checkpoint_detects_coordinated_rewrite_of_event_and_local_head(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint-rewrite.db")
    operation_id = create_operation(store, policy_id, token, "checkpoint-rewrite")
    checkpoint_json = create_gateway_checkpoint(store)

    connection = store._connect()
    try:
        event = connection.execute(
            """SELECT event_id, operation_id, previous_status, new_status, event_type,
                      actor_type, actor_id, created_at, previous_hash
            FROM gateway_operation_events WHERE operation_id = ? ORDER BY event_id LIMIT 1""",
            (operation_id,),
        ).fetchone()
        reason = "rewritten by database administrator"
        event_hash = store._gateway_event_hash(
            event["event_id"], event["operation_id"], event["previous_status"],
            event["new_status"], event["event_type"], event["actor_type"],
            event["actor_id"], reason, event["created_at"], event["previous_hash"],
        )
        connection.execute(
            "UPDATE gateway_operation_events SET reason = ?, event_hash = ? WHERE event_id = ?",
            (reason, event_hash, event["event_id"]),
        )
        connection.execute(
            "UPDATE gateway_operations SET audit_head_hash = ? WHERE operation_id = ?",
            (event_hash, operation_id),
        )
        connection.commit()
    finally:
        connection.close()

    assert store.verify_gateway_operation_events(operation_id)["valid"] is True
    result = verify_gateway_checkpoint(store, checkpoint_json)
    assert result["valid"] is False
    assert result["reason_code"] == "CHECKPOINT_MISMATCH"
    assert result["detail"] == "CHECKPOINTED_EVENT_PREFIX_MISMATCH"


def test_checkpoint_detects_deleted_previously_recorded_operation(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint-delete.db")
    operation_id = create_operation(store, policy_id, token, "checkpoint-delete")
    checkpoint_json = create_gateway_checkpoint(store)

    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DELETE FROM gateway_operation_events WHERE operation_id = ?", (operation_id,))
        connection.execute("DELETE FROM gateway_operations WHERE operation_id = ?", (operation_id,))
        connection.commit()
    finally:
        connection.close()

    result = verify_gateway_checkpoint(store, checkpoint_json)
    assert result["valid"] is False
    assert result["reason_code"] == "CHECKPOINT_MISMATCH"
    assert result["detail"] == "CHECKPOINTED_OPERATION_MISSING"


def test_checkpoint_chain_requires_and_checks_predecessor(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint-chain.db")
    create_operation(store, policy_id, token, "checkpoint-chain-first")
    first_json = create_gateway_checkpoint(store)
    second_json = create_gateway_checkpoint(store, first_json)

    assert json.loads(second_json)["sequence"] == 2
    assert verify_gateway_checkpoint(store, second_json)["reason_code"] == "CHECKPOINT_INVALID"
    assert verify_gateway_checkpoint(store, second_json, first_json)["valid"] is True

    altered = json.loads(first_json)
    altered["sequence"] = 7
    assert verify_gateway_checkpoint(store, second_json, json.dumps(altered))["valid"] is False


def test_checkpoint_rejects_duplicate_json_keys_and_boolean_integer(tmp_path):
    store, _, _ = make_store(tmp_path / "checkpoint-invalid.db")
    assert verify_gateway_checkpoint(
        store, '{"format_version":1,"format_version":1}'
    )["reason_code"] == "CHECKPOINT_INVALID"

    checkpoint = json.loads(create_gateway_checkpoint(store))
    checkpoint["sequence"] = True
    assert verify_gateway_checkpoint(store, json.dumps(checkpoint))["reason_code"] == "CHECKPOINT_INVALID"


def test_checkpoint_rejects_installation_identity_mismatch(tmp_path):
    store_a, _, _ = make_store(tmp_path / "checkpoint-a.db")
    store_b, _, _ = make_store(tmp_path / "checkpoint-b.db")
    result = verify_gateway_checkpoint(store_b, create_gateway_checkpoint(store_a))
    assert result["valid"] is False
    assert result["reason_code"] == "INSTALLATION_ID_MISMATCH"


def test_checkpoint_reports_missing_local_installation_identity(tmp_path):
    store, _, _ = make_store(tmp_path / "checkpoint-missing-id.db")
    checkpoint_json = create_gateway_checkpoint(store)
    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("DROP TABLE agentguard_metadata")
        connection.commit()
    finally:
        connection.close()

    result = verify_gateway_checkpoint(store, checkpoint_json)
    assert result["valid"] is False
    assert result["reason_code"] == "INSTALLATION_ID_MISSING"


def test_checkpoint_export_fails_closed_on_invalid_local_chain(tmp_path):
    store, policy_id, token = make_store(tmp_path / "checkpoint-bad-chain.db")
    operation_id = create_operation(store, policy_id, token, "checkpoint-bad-chain")
    connection = store._connect()
    try:
        connection.execute(
            "UPDATE gateway_operation_events SET reason = 'changed' WHERE operation_id = ?",
            (operation_id,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(CheckpointError):
        create_gateway_checkpoint(store)


def test_empty_database_can_be_checkpointed(tmp_path):
    store = SQLitePolicyStore(tmp_path / "checkpoint-empty.db")
    checkpoint_json = create_gateway_checkpoint(store)
    checkpoint = json.loads(checkpoint_json)
    assert checkpoint["operation_count"] == 0
    assert checkpoint["operations"] == []
    assert verify_gateway_checkpoint(store, checkpoint_json)["valid"] is True
