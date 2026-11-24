"""Export and verify externally retained Gateway audit checkpoints."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from agentguard.storage import SQLitePolicyStore

GENESIS_HASH = "0" * 64
_CHECKPOINT_DOMAIN_V1 = b"agentguard.gateway-checkpoint.v1:"
_CHECKPOINT_DOMAIN_V2 = b"agentguard.gateway-checkpoint.v2:"
_OPERATION_REF_DOMAIN = b"agentguard.gateway-checkpoint-operation-ref.v1:"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCUMENT_FIELDS_V1 = {
    "format_version", "installation_id", "checkpoint_id", "sequence",
    "created_at", "hash_algorithm", "event_chain_version", "operation_count",
    "operations", "previous_checkpoint_hash", "checkpoint_hash",
}
_DOCUMENT_FIELDS_V2 = _DOCUMENT_FIELDS_V1 | {"snapshot_event_id"}
_OPERATION_FIELDS = {"operation_ref", "event_count", "head_hash"}


class CheckpointError(ValueError):
    """A checkpoint document is invalid or cannot be linked to its predecessor."""


class CheckpointIntegrityError(CheckpointError):
    """The local event history is inconsistent and cannot be checkpointed."""


def _reject_constant(value: str) -> None:
    raise CheckpointError(f"Non-standard JSON constant is not allowed: {value}.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CheckpointError("Duplicate JSON object keys are not allowed.")
        result[key] = value
    return result


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise CheckpointError("Floating-point values are not allowed.")
    if isinstance(value, list):
        for item in value:
            _reject_floats(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)


def _canonical_json(value: dict[str, Any]) -> bytes:
    _reject_floats(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CheckpointError("Checkpoint cannot be canonically encoded.") from error


def _checkpoint_hash(document: dict[str, Any]) -> str:
    payload = {key: value for key, value in document.items() if key != "checkpoint_hash"}
    version = document.get("format_version")
    domain = _CHECKPOINT_DOMAIN_V2 if version == 2 else _CHECKPOINT_DOMAIN_V1
    return hashlib.sha256(domain + _canonical_json(payload)).hexdigest()


def _operation_ref(operation_id: str) -> str:
    digest = hashlib.sha256(
        _OPERATION_REF_DOMAIN + operation_id.encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def _require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise CheckpointError(f"{field} must be 64 lowercase hexadecimal characters.")
    return value


def _require_int(value: Any, field: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CheckpointError(f"{field} must be an integer greater than or equal to {minimum}.")
    return value


def _parse_document(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw) > 10_000_000:
        raise CheckpointError("Checkpoint JSON must be a non-empty string no larger than 10 MB.")
    try:
        value = json.loads(
            raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except CheckpointError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, RecursionError) as error:
        raise CheckpointError("Checkpoint is not valid JSON.") from error
    if not isinstance(value, dict):
        raise CheckpointError("Checkpoint root must be a JSON object.")
    try:
        _reject_floats(value)
        _validate_document(value)
    except RecursionError as error:
        raise CheckpointError("Checkpoint nesting is too deep.") from error
    return value


def _validate_document(document: dict[str, Any]) -> None:
    version = _require_int(document.get("format_version"), "format_version", 1)
    expected_fields = _DOCUMENT_FIELDS_V1 if version == 1 else _DOCUMENT_FIELDS_V2 if version == 2 else None
    if expected_fields is None:
        raise CheckpointError("Unsupported checkpoint format_version.")
    if set(document) != expected_fields:
        raise CheckpointError("Checkpoint has missing or unknown fields.")
    if version == 2:
        _require_int(document["snapshot_event_id"], "snapshot_event_id", 0)
    if document["hash_algorithm"] != "sha256":
        raise CheckpointError("Unsupported checkpoint hash_algorithm.")
    if _require_int(document["event_chain_version"], "event_chain_version", 1) != 1:
        raise CheckpointError("Unsupported event_chain_version.")

    for field in ("installation_id", "checkpoint_id"):
        value = document[field]
        if not isinstance(value, str):
            raise CheckpointError(f"{field} must be a canonical UUID.")
        try:
            canonical = str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError) as error:
            raise CheckpointError(f"{field} must be a canonical UUID.") from error
        if value != canonical:
            raise CheckpointError(f"{field} must be a canonical lowercase UUID.")

    _require_int(document["sequence"], "sequence", 1)
    created_at = document["created_at"]
    if not isinstance(created_at, str):
        raise CheckpointError("created_at must be a timezone-aware ISO 8601 timestamp.")
    try:
        parsed_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise CheckpointError("created_at must be a timezone-aware ISO 8601 timestamp.") from error
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise CheckpointError("created_at must include a timezone.")

    operations = document["operations"]
    if not isinstance(operations, list):
        raise CheckpointError("operations must be an array.")
    if _require_int(document["operation_count"], "operation_count", 0) != len(operations):
        raise CheckpointError("operation_count does not match operations.")
    previous_ref: str | None = None
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != _OPERATION_FIELDS:
            raise CheckpointError("Operation entries have missing or unknown fields.")
        operation_ref = operation["operation_ref"]
        if not isinstance(operation_ref, str) or _OPERATION_REF_RE.fullmatch(operation_ref) is None:
            raise CheckpointError("operation_ref is invalid.")
        if previous_ref is not None and operation_ref <= previous_ref:
            raise CheckpointError("Operations must be uniquely sorted by operation_ref.")
        previous_ref = operation_ref
        event_count = _require_int(operation["event_count"], "event_count", 0)
        head_hash = _require_hash(operation["head_hash"], "head_hash")
        if event_count == 0 and head_hash != GENESIS_HASH:
            raise CheckpointError("An empty event chain must use the genesis hash.")

    _require_hash(document["previous_checkpoint_hash"], "previous_checkpoint_hash")
    supplied_hash = _require_hash(document["checkpoint_hash"], "checkpoint_hash")
    if supplied_hash != _checkpoint_hash(document):
        raise CheckpointError("checkpoint_hash does not match the canonical document.")


def _validated_predecessor(
    raw: str | None, installation_id: str
) -> dict[str, Any] | None:
    if raw is None:
        return None
    predecessor = _parse_document(raw)
    if predecessor["installation_id"] != installation_id:
        raise CheckpointError("Predecessor belongs to a different installation.")
    if predecessor["sequence"] == 1:
        _check_chain_link(predecessor, None)
    return predecessor


def _verify_registered_predecessor(
    connection: sqlite3.Connection, predecessor: dict[str, Any]
) -> bool:
    """Verify local provenance for v2 predecessors; report v1 as unanchored."""
    if predecessor["format_version"] == 1:
        return False

    record = connection.execute(
        """SELECT checkpoint_id, installation_id, sequence, snapshot_event_id,
                  operation_count, checkpoint_hash, previous_checkpoint_hash, created_at
        FROM gateway_checkpoints WHERE checkpoint_id = ?""",
        (predecessor["checkpoint_id"],),
    ).fetchone()
    if record is None or any((
        record["checkpoint_id"] != predecessor["checkpoint_id"],
        record["installation_id"] != predecessor["installation_id"],
        record["sequence"] != predecessor["sequence"],
        record["snapshot_event_id"] != predecessor["snapshot_event_id"],
        record["operation_count"] != predecessor["operation_count"],
        record["checkpoint_hash"] != predecessor["checkpoint_hash"],
        record["previous_checkpoint_hash"] != predecessor["previous_checkpoint_hash"],
        record["created_at"] != predecessor["created_at"],
    )):
        raise CheckpointError("Predecessor is not anchored in the local checkpoint registry.")
    return True


def _check_chain_link(
    document: dict[str, Any], predecessor: dict[str, Any] | None
) -> None:
    if document["sequence"] == 1:
        if document["previous_checkpoint_hash"] != GENESIS_HASH or predecessor is not None:
            raise CheckpointError("Genesis checkpoint has an invalid predecessor link.")
        return
    if predecessor is None:
        raise CheckpointError("A predecessor checkpoint is required for non-genesis checkpoints.")
    if predecessor["installation_id"] != document["installation_id"]:
        raise CheckpointError("Checkpoint predecessor installation does not match.")
    if document["sequence"] != predecessor["sequence"] + 1:
        raise CheckpointError("Checkpoint sequence is not consecutive.")
    if document["previous_checkpoint_hash"] != predecessor["checkpoint_hash"]:
        raise CheckpointError("Checkpoint predecessor hash does not match.")


def _read_installation_id(connection: sqlite3.Connection) -> str:
    try:
        row = connection.execute(
            "SELECT value FROM agentguard_metadata WHERE key = 'installation_id'"
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("INSTALLATION_ID_MISSING") from error
    if row is None:
        raise RuntimeError("INSTALLATION_ID_MISSING")
    try:
        value = str(uuid.UUID(row["value"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise RuntimeError("INSTALLATION_ID_MISSING") from error
    if value != row["value"]:
        raise RuntimeError("INSTALLATION_ID_MISSING")
    return value


def _read_and_verify_operation(
    store: SQLitePolicyStore, connection: sqlite3.Connection, operation: sqlite3.Row
) -> tuple[list[sqlite3.Row], str]:
    rows = connection.execute(
        """SELECT event_id, operation_id, previous_status, new_status, event_type,
                  actor_type, actor_id, reason, created_at, previous_hash, event_hash
        FROM gateway_operation_events WHERE operation_id = ? ORDER BY event_id""",
        (operation["operation_id"],),
    ).fetchall()
    previous_hash = GENESIS_HASH
    for row in rows:
        if row["previous_hash"] != previous_hash:
            raise CheckpointError("Local event chain has a broken previous_hash link.")
        try:
            expected = store._gateway_event_hash(
                row["event_id"], row["operation_id"], row["previous_status"],
                row["new_status"], row["event_type"], row["actor_type"],
                row["actor_id"], row["reason"], row["created_at"], previous_hash,
            )
        except (TypeError, ValueError, UnicodeError) as error:
            raise CheckpointError("Local event chain contains invalid event data.") from error
        if not isinstance(row["event_hash"], str) or row["event_hash"] != expected:
            raise CheckpointError("Local event chain contains an invalid event hash.")
        previous_hash = expected

    if len(rows) != operation["audit_event_count"]:
        raise CheckpointError("Local event count does not match its stored audit count.")
    if previous_hash != operation["audit_head_hash"]:
        raise CheckpointError("Local event head does not match its stored audit head.")
    return rows, previous_hash


def create_gateway_checkpoint(
    store: SQLitePolicyStore, previous_checkpoint_json: str | None = None
) -> str:
    """Create canonical checkpoint JSON from one consistent SQLite read snapshot."""
    connection = store._connect()
    try:
        # Serialize snapshot capture and registry insertion against all Gateway
        # writers. The registry is the trusted local anchor for completeness.
        connection.execute("BEGIN IMMEDIATE")
        installation_id = _read_installation_id(connection)
        predecessor = _validated_predecessor(previous_checkpoint_json, installation_id)
        if predecessor is None:
            sequence, previous_hash = 1, GENESIS_HASH
        else:
            if predecessor["format_version"] == 1:
                raise CheckpointError(
                    "Legacy v1 predecessors cannot anchor a new v2 checkpoint."
                )
            _verify_registered_predecessor(connection, predecessor)
            sequence = predecessor["sequence"] + 1
            previous_hash = predecessor["checkpoint_hash"]

        snapshot_event_id = connection.execute(
            "SELECT COALESCE(MAX(event_id), 0) FROM gateway_operation_events"
        ).fetchone()[0]
        operation_rows = connection.execute(
            """SELECT operation_id, audit_event_count, audit_head_hash
            FROM gateway_operations AS operations
            WHERE EXISTS (
                SELECT 1 FROM gateway_operation_events AS events
                WHERE events.operation_id = operations.operation_id
                  AND events.event_id <= ?
            )
            ORDER BY operation_id""",
            (snapshot_event_id,),
        ).fetchall()
        entries = []
        for operation in operation_rows:
            try:
                events, head_hash = _read_and_verify_operation(store, connection, operation)
            except CheckpointError as error:
                raise CheckpointIntegrityError(
                    "Local Gateway event history is inconsistent; refusing to export."
                ) from error
            entries.append({
                "operation_ref": _operation_ref(operation["operation_id"]),
                "event_count": len(events),
                "head_hash": head_hash,
            })
        entries.sort(key=lambda item: item["operation_ref"])

        document: dict[str, Any] = {
            "format_version": 2,
            "installation_id": installation_id,
            "snapshot_event_id": snapshot_event_id,
            "checkpoint_id": str(uuid.uuid4()),
            "sequence": sequence,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hash_algorithm": "sha256",
            "event_chain_version": 1,
            "operation_count": len(entries),
            "operations": entries,
            "previous_checkpoint_hash": previous_hash,
        }
        document["checkpoint_hash"] = _checkpoint_hash(document)
        _validate_document(document)
        connection.execute(
            """INSERT INTO gateway_checkpoints (
                checkpoint_id, installation_id, sequence, snapshot_event_id,
                operation_count, checkpoint_hash, previous_checkpoint_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                document["checkpoint_id"], installation_id, sequence,
                snapshot_event_id, len(entries), document["checkpoint_hash"],
                previous_hash, document["created_at"],
            ),
        )
        connection.commit()
        return json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def verify_gateway_checkpoint(
    store: SQLitePolicyStore,
    checkpoint_json: str,
    previous_checkpoint_json: str | None = None,
) -> dict[str, Any]:
    """Verify checkpoint hash, chain link, installation and committed event prefixes."""
    try:
        document = _parse_document(checkpoint_json)
        predecessor = _validated_predecessor(
            previous_checkpoint_json, document["installation_id"]
        )
        _check_chain_link(document, predecessor)
    except CheckpointError:
        return {"valid": False, "reason_code": "CHECKPOINT_INVALID"}

    connection = store._connect()
    try:
        connection.execute("BEGIN")
        try:
            installation_id = _read_installation_id(connection)
        except RuntimeError:
            return {"valid": False, "reason_code": "INSTALLATION_ID_MISSING"}
        if installation_id != document["installation_id"]:
            return {"valid": False, "reason_code": "INSTALLATION_ID_MISMATCH"}

        predecessor_provenance_verified = predecessor is None
        if predecessor is not None:
            try:
                predecessor_provenance_verified = _verify_registered_predecessor(
                    connection, predecessor
                )
            except CheckpointError:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "PREDECESSOR_REGISTRY_MISMATCH",
                }

        checkpoint_record = None
        if document["format_version"] == 2:
            checkpoint_record = connection.execute(
                """SELECT installation_id, sequence, snapshot_event_id,
                          operation_count, checkpoint_hash,
                          previous_checkpoint_hash, created_at
                FROM gateway_checkpoints WHERE checkpoint_id = ?""",
                (document["checkpoint_id"],),
            ).fetchone()
            if checkpoint_record is None or any((
                checkpoint_record["installation_id"] != document["installation_id"],
                checkpoint_record["sequence"] != document["sequence"],
                checkpoint_record["snapshot_event_id"] != document["snapshot_event_id"],
                checkpoint_record["operation_count"] != document["operation_count"],
                checkpoint_record["checkpoint_hash"] != document["checkpoint_hash"],
                checkpoint_record["previous_checkpoint_hash"] != document["previous_checkpoint_hash"],
                checkpoint_record["created_at"] != document["created_at"],
            )):
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "CHECKPOINT_REGISTRY_MISMATCH",
                }
            local_operations = connection.execute(
                """SELECT operation_id, audit_event_count, audit_head_hash
                FROM gateway_operations AS operations
                WHERE EXISTS (
                    SELECT 1 FROM gateway_operation_events AS events
                    WHERE events.operation_id = operations.operation_id
                      AND events.event_id <= ?
                )""",
                (document["snapshot_event_id"],),
            ).fetchall()
        else:
            # v1 remains readable for compatibility, but its snapshot boundary
            # was never anchored locally, so completeness cannot be established.
            local_operations = connection.execute(
                "SELECT operation_id, audit_event_count, audit_head_hash FROM gateway_operations"
            ).fetchall()
        by_ref: dict[str, sqlite3.Row] = {}
        for operation in local_operations:
            ref = _operation_ref(operation["operation_id"])
            if ref in by_ref:
                return {"valid": False, "reason_code": "CHECKPOINT_MISMATCH"}
            by_ref[ref] = operation

        document_by_ref = {
            item["operation_ref"]: item for item in document["operations"]
        }
        predecessor_by_ref = (
            {item["operation_ref"]: item for item in predecessor["operations"]}
            if predecessor is not None else {}
        )
        if document["format_version"] == 2:
            local_refs = set(by_ref)
            checkpoint_refs = set(document_by_ref)
            if (
                len(local_operations) != document["operation_count"]
                or local_refs != checkpoint_refs
            ):
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "CHECKPOINT_OPERATION_SET_MISMATCH",
                }
        for previous_ref, previous_item in predecessor_by_ref.items():
            current_item = document_by_ref.get(previous_ref)
            if current_item is None:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "PREVIOUSLY_CHECKPOINTED_OPERATION_MISSING",
                }
            if current_item["event_count"] < previous_item["event_count"]:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "PREVIOUSLY_CHECKPOINTED_EVENT_PREFIX_MISSING",
                }

        for item in document["operations"]:
            operation = by_ref.get(item["operation_ref"])
            if operation is None:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "CHECKPOINTED_OPERATION_MISSING",
                }
            try:
                events, _ = _read_and_verify_operation(store, connection, operation)
            except CheckpointError:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "LOCAL_EVENT_CHAIN_INVALID",
                }
            if len(events) < item["event_count"]:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "CHECKPOINTED_EVENT_PREFIX_MISSING",
                }
            prefix_hash = (
                GENESIS_HASH if item["event_count"] == 0
                else events[item["event_count"] - 1]["event_hash"]
            )
            if prefix_hash != item["head_hash"]:
                return {
                    "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                    "detail": "CHECKPOINTED_EVENT_PREFIX_MISMATCH",
                }

            previous_item = predecessor_by_ref.get(item["operation_ref"])
            if previous_item is not None:
                previous_count = previous_item["event_count"]
                previous_prefix_hash = (
                    GENESIS_HASH if previous_count == 0
                    else events[previous_count - 1]["event_hash"]
                )
                if previous_prefix_hash != previous_item["head_hash"]:
                    return {
                        "valid": False, "reason_code": "CHECKPOINT_MISMATCH",
                        "detail": "PREVIOUSLY_CHECKPOINTED_EVENT_PREFIX_MISMATCH",
                    }

        return {
            "valid": True,
            "reason_code": None,
            "sequence": document["sequence"],
            "operation_count": document["operation_count"],
            "checkpoint_hash": document["checkpoint_hash"],
            "completeness_verified": document["format_version"] == 2,
            "predecessor_provenance_verified": predecessor_provenance_verified,
        }
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()
