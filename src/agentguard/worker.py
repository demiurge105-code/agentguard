"""Durable single-host worker for simulation-only gateway execution."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from typing import Callable

from agentguard.gateway import ExecutionOutcome, OperationStatus, PrintOnlyExecutor
from agentguard.intent import ActionIntent
from agentguard.storage import SQLitePolicyStore


Executor = Callable[[ActionIntent, str], object]


class ExecutionWorker:
    """Claim and execute at most one durably queued operation per run_once call.

    The worker lease protects only the pre-dispatch phase. Before invoking the
    executor, the worker atomically crosses DISPATCH_STARTED. That state is
    never automatically re-leased: a crash after this boundary is ambiguous
    and must be reconciled to UNKNOWN rather than replayed.
    """

    def __init__(
        self,
        store: SQLitePolicyStore,
        executor: Executor,
        worker_id: str,
        *,
        lease_seconds: int = 30,
    ) -> None:
        if not isinstance(store, SQLitePolicyStore):
            raise TypeError("store must be a SQLitePolicyStore.")
        if not callable(executor):
            raise TypeError("executor must be callable.")
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 100:
            raise ValueError("worker_id must contain 1-100 non-whitespace characters.")
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be an integer between 5 and 300.")
        self._store = store
        self._executor = executor
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds

    def run_once(self) -> str | None:
        """Process one available job and return its operation ID, if any."""
        job = self._store.claim_execution_job(
            self._worker_id,
            lease_seconds=self._lease_seconds,
        )
        if job is None:
            return None

        operation_id = str(job["operation_id"])
        fencing_token = int(job["fencing_token"])
        payload = json.loads(str(job["canonical_intent"]))
        intent = ActionIntent(
            str(payload["policy_id"]),
            str(payload["amount"]),
            str(payload["recipient"]),
            chain_id=payload["chain_id"],
        )

        if not self._store.start_execution_job(
            operation_id,
            self._worker_id,
            fencing_token,
        ):
            return None

        try:
            execution_result = self._executor(intent, operation_id)
        except Exception:
            terminal_status = OperationStatus.UNKNOWN
            no_side_effect_confirmed = False
            stored_result = "Executor raised an exception; outcome may be unknown."
        else:
            if isinstance(execution_result, ExecutionOutcome):
                terminal_status = execution_result.status
                no_side_effect_confirmed = execution_result.no_side_effect_confirmed
                stored_result = {
                    OperationStatus.SUCCEEDED: "Execution completed.",
                    OperationStatus.FAILED: "Trusted executor confirmed no side effect occurred.",
                    OperationStatus.UNKNOWN: "Execution outcome is uncertain.",
                }[terminal_status]
            elif execution_result is None:
                terminal_status = OperationStatus.SUCCEEDED
                no_side_effect_confirmed = False
                stored_result = "Execution completed."
            else:
                terminal_status = OperationStatus.UNKNOWN
                no_side_effect_confirmed = False
                stored_result = "Executor returned unsupported data; outcome may be unknown."

        persisted = self._store.complete_execution_job(
            operation_id,
            self._worker_id,
            fencing_token,
            terminal_status.value,
            stored_result,
            no_side_effect_confirmed=no_side_effect_confirmed,
        )
        if not persisted:
            # Recovery or another state transition may have fenced this worker.
            # Never attempt to execute or persist the operation again.
            return None
        return operation_id


def main() -> None:
    """Run the print-only worker until stopped by its process supervisor."""
    parser = argparse.ArgumentParser(description="Run the AgentGuard simulation worker.")
    parser.add_argument(
        "--db-path",
        default=os.getenv("AGENTGUARD_DB_PATH", "agentguard.db"),
        help="SQLite database path (defaults to AGENTGUARD_DB_PATH or agentguard.db).",
    )
    parser.add_argument(
        "--worker-id",
        default=f"worker-{uuid.uuid4()}",
        help="Unique identifier for this worker process.",
    )
    parser.add_argument("--lease-seconds", type=int, default=30)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true", help="Process at most one queued job and exit.")
    args = parser.parse_args()

    if not 0.1 <= args.poll_interval <= 60:
        parser.error("--poll-interval must be between 0.1 and 60 seconds.")

    worker = ExecutionWorker(
        SQLitePolicyStore(args.db_path),
        PrintOnlyExecutor(),
        args.worker_id,
        lease_seconds=args.lease_seconds,
    )
    while True:
        operation_id = worker.run_once()
        if args.once:
            if operation_id:
                print(f"Processed operation {operation_id}.")
            return
        if operation_id is None:
            time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
