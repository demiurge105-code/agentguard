"""Trusted, simulation-only orchestration for policy-approved actions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from agentguard.intent import ActionIntent
from agentguard.storage import SQLitePolicyStore


class OperationStatus(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class GatewayAuthenticationError(PermissionError):
    """The supplied agent credential is not valid for the action policy."""


@dataclass(frozen=True, slots=True)
class OperationResult:
    operation_id: str
    policy_id: str
    idempotency_key: str
    status: OperationStatus
    allowed: bool
    reason_code: str
    reason: str
    result: str | None
    created_at: str
    updated_at: str


Executor = Callable[[ActionIntent, str], None]


def _result_from_record(record: dict[str, object]) -> OperationResult:
    return OperationResult(
        operation_id=str(record["operation_id"]),
        policy_id=str(record["policy_id"]),
        idempotency_key=str(record["idempotency_key"]),
        status=OperationStatus(str(record["status"])),
        allowed=record["allowed"] is True,
        reason_code=str(record["reason_code"]),
        reason=str(record["reason"]),
        result=record["result"] if isinstance(record["result"], str) else None,
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
    )


class TrustedExecutionGateway:
    """Own the only executor reference and gate each operation exactly once.

    The SQLite state transition APPROVED -> EXECUTING is the durable execution
    claim. A retry never reclaims EXECUTING or terminal operations. If the
    process dies after the claim, the operation remains unresolved and must be
    reconciled manually; it is never automatically executed again.
    """

    def __init__(self, store: SQLitePolicyStore, executor: Executor) -> None:
        if not isinstance(store, SQLitePolicyStore):
            raise TypeError("store must be a SQLitePolicyStore.")
        if not callable(executor):
            raise TypeError("executor must be callable.")
        self._store = store
        self.__executor = executor

    def submit(
        self,
        intent: ActionIntent,
        agent_token: str,
        idempotency_key: str,
    ) -> OperationResult:
        """Validate, reserve, claim, and at most once invoke the owned executor."""
        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be an ActionIntent.")
        record = self._store.begin_gateway_operation(
            intent,
            agent_token,
            idempotency_key,
        )
        if record is None:
            raise GatewayAuthenticationError(
                "Invalid agent token or policy not found."
            )

        if record.get("canonical_intent") != intent.canonical_json:
            raise RuntimeError("Stored operation intent does not match the submitted ActionIntent.")

        operation = _result_from_record(record)
        if operation.status is not OperationStatus.APPROVED:
            return operation
        if operation.allowed is not True or operation.reason_code != "allowed":
            raise RuntimeError("Gateway refused an inconsistent or malformed approval record.")

        claimed = self._store.claim_gateway_operation(
            operation.operation_id,
            agent_token,
        )
        if claimed is None:
            raise GatewayAuthenticationError(
                "Agent token is invalid or was revoked before execution."
            )
        if not claimed:
            current = self._store.get_gateway_operation(
                operation.policy_id,
                operation.idempotency_key,
            )
            if current is None:
                raise RuntimeError("Gateway operation disappeared after its claim attempt.")
            return _result_from_record(current)

        try:
            execution_result = self.__executor(intent, operation.operation_id)
        except Exception as error:
            # An executor exception may happen after a side effect. UNKNOWN is
            # safer than FAILED because a retry must never repeat the action.
            stored = self._store.complete_gateway_operation(
                operation.operation_id,
                OperationStatus.UNKNOWN.value,
                "Executor raised an exception; outcome may be unknown.",
            )
            if not stored:
                raise RuntimeError(
                    "Executor outcome is uncertain and could not be persisted."
                ) from error
        else:
            if execution_result is not None:
                terminal_status = OperationStatus.UNKNOWN
                stored_result = "Executor returned unsupported data; outcome may be unknown."
            else:
                terminal_status = OperationStatus.SUCCEEDED
                # Persist only a fixed status message, never arbitrary executor
                # output that could accidentally contain credentials or secrets.
                stored_result = "Execution completed."

            stored = self._store.complete_gateway_operation(
                operation.operation_id,
                terminal_status.value,
                stored_result,
            )
            if not stored:
                raise RuntimeError(
                    "Executor returned but its outcome could not be persisted."
                )

        current = self._store.get_gateway_operation(
            operation.policy_id,
            operation.idempotency_key,
        )
        if current is None:
            raise RuntimeError("Gateway operation is missing after execution.")
        return _result_from_record(current)


class PrintOnlyExecutor:
    """Minimal executor that prints a simulation and performs no external action."""

    def __call__(self, intent: ActionIntent, operation_id: str) -> None:
        print(
            f"Simulated operation {operation_id}: "
            f"{intent.amount} units to {intent.recipient}."
        )
        return None
