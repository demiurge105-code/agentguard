"""SQLite persistence for policies and atomic daily-budget reservations."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from pathlib import Path

from agentguard.chains import normalize_recipient
from agentguard.policy import (
    EXACT_ARITHMETIC_PRECISION,
    Decision,
    DecisionReason,
    Policy,
    TransactionRequest,
    check_transaction,
)


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a different request."""


class SQLitePolicyStore:
    """Persist policies and serialize daily-budget reservations in SQLite."""

    def __init__(self, db_path: str | Path) -> None:
        if str(db_path) == ":memory:":
            raise ValueError(
                "SQLitePolicyStore requires a file-based database path; "
                "':memory:' is not supported."
            )
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS policies (
                        policy_id TEXT PRIMARY KEY,
                        max_transaction TEXT NOT NULL,
                        daily_limit TEXT NOT NULL,
                        allowed_recipients TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        chain_id TEXT,
                        agent_token_hash TEXT
                    )"""
                )
                # Add nullable columns when upgrading older databases. A missing
                # chain_id keeps an existing policy in backwards-compatible legacy mode.
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(policies)").fetchall()
                }
                if "agent_token_hash" not in columns:
                    connection.execute(
                        "ALTER TABLE policies ADD COLUMN agent_token_hash TEXT"
                    )
                if "chain_id" not in columns:
                    connection.execute(
                        "ALTER TABLE policies ADD COLUMN chain_id TEXT"
                    )

                connection.execute(
                    """CREATE TABLE IF NOT EXISTS daily_reservations (
                        policy_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        utc_day TEXT NOT NULL,
                        amount TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        allowed INTEGER NOT NULL,
                        reason_code TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        reservation_status TEXT NOT NULL DEFAULT 'SETTLED'
                            CHECK (reservation_status IN ('RESERVED', 'SETTLED', 'RELEASED', 'NOT_RESERVED')),
                        PRIMARY KEY (policy_id, request_id),
                        FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
                    )"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_daily_reservations_usage
                    ON daily_reservations(policy_id, utc_day, allowed)"""
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS gateway_operations (
                        operation_id TEXT PRIMARY KEY,
                        policy_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        canonical_intent TEXT NOT NULL,
                        status TEXT NOT NULL,
                        allowed INTEGER NOT NULL,
                        reason_code TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        result TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE (idempotency_key),
                        FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
                    )"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_gateway_operations_status
                    ON gateway_operations(status, updated_at)"""
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS gateway_operation_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation_id TEXT NOT NULL,
                        previous_status TEXT,
                        new_status TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        actor_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (operation_id) REFERENCES gateway_operations(operation_id)
                    )"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_gateway_operation_events_operation
                    ON gateway_operation_events(operation_id, event_id)"""
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS gateway_execution_jobs (
                        operation_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL CHECK (status IN (
                            'QUEUED', 'LEASED', 'DISPATCH_STARTED', 'COMPLETED', 'UNKNOWN'
                        )),
                        fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
                        worker_id TEXT,
                        lease_expires_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (operation_id) REFERENCES gateway_operations(operation_id)
                    )"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_gateway_execution_jobs_claim
                    ON gateway_execution_jobs(status, lease_expires_at, created_at)"""
                )
                reservation_columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info(daily_reservations)"
                    ).fetchall()
                }
                if "reservation_status" not in reservation_columns:
                    connection.execute(
                        """ALTER TABLE daily_reservations
                        ADD COLUMN reservation_status TEXT NOT NULL DEFAULT 'SETTLED'
                        CHECK (reservation_status IN (
                            'RESERVED', 'SETTLED', 'RELEASED', 'NOT_RESERVED'
                        ))"""
                    )
                    # Historical FAILED rows remain charged: the old code had no proof contract.
                    connection.execute(
                        """UPDATE daily_reservations AS reservation
                        SET reservation_status = CASE
                            WHEN reservation.allowed = 0 THEN 'NOT_RESERVED'
                            WHEN EXISTS (
                                SELECT 1 FROM gateway_operations AS operation
                                WHERE operation.policy_id = reservation.policy_id
                                  AND reservation.request_id = 'gateway:' || operation.operation_id
                                  AND operation.status IN ('APPROVED', 'EXECUTING', 'UNKNOWN')
                            ) THEN 'RESERVED'
                            ELSE 'SETTLED'
                        END
                        WHERE reservation.request_id LIKE 'gateway:%'"""
                    )

                connection.execute(
                    """INSERT INTO gateway_operation_events (
                        operation_id, previous_status, new_status, event_type,
                        actor_type, actor_id, reason, created_at
                    )
                    SELECT operation_id, NULL, status, 'LEGACY_IMPORT',
                           'system', 'schema-migration',
                           'Imported existing operation; prior transitions are unavailable.',
                           updated_at
                    FROM gateway_operations AS operations
                    WHERE NOT EXISTS (
                        SELECT 1 FROM gateway_operation_events AS events
                        WHERE events.operation_id = operations.operation_id
                    )"""
                )
        finally:
            connection.close()

    def create_policy(self, policy: Policy, agent_token_hash: str | None = None) -> str:
        """Persist a policy and optional SHA-256 agent-token hash."""
        policy_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        recipients = json.dumps(sorted(policy.allowed_recipients), separators=(",", ":"))
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """INSERT INTO policies (
                        policy_id, max_transaction, daily_limit,
                        allowed_recipients, created_at, chain_id, agent_token_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        policy_id,
                        str(policy.max_transaction),
                        str(policy.daily_limit),
                        recipients,
                        created_at,
                        policy.chain_id,
                        agent_token_hash,
                    ),
                )
        finally:
            connection.close()
        return policy_id

    def authenticate_agent(self, policy_id: str, token: str) -> bool:
        """Check a raw agent token against the hash stored for this policy."""
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT agent_token_hash FROM policies WHERE policy_id = ?",
                (policy_id,),
            ).fetchone()
        finally:
            connection.close()

        if row is None or not row["agent_token_hash"]:
            return False
        supplied_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(row["agent_token_hash"], supplied_hash)

    def rotate_agent_token(self, policy_id: str, token_hash: str) -> bool:
        """Atomically replace a policy's agent-token hash; return False if absent."""
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    "UPDATE policies SET agent_token_hash = ? WHERE policy_id = ?",
                    (token_hash, policy_id),
                )
                return cursor.rowcount == 1
        finally:
            connection.close()

    @staticmethod
    def _policy(row: sqlite3.Row) -> Policy:
        return Policy(
            row["max_transaction"],
            row["daily_limit"],
            json.loads(row["allowed_recipients"]),
            chain_id=row["chain_id"],
        )

    @staticmethod
    def _decision(row: sqlite3.Row) -> Decision:
        return Decision(
            bool(row["allowed"]),
            DecisionReason(row["reason_code"]),
            row["reason"],
        )

    def get_policy(self, policy_id: str) -> Policy | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT max_transaction, daily_limit, allowed_recipients, chain_id
                FROM policies WHERE policy_id = ?""",
                (policy_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._policy(row)

    def get_policy_authenticated(
        self,
        policy_id: str,
        token: str,
    ) -> Policy | None:
        """Return policy context only for a currently valid agent token.

        This read is used to obtain the stored chain_id before constructing an
        ActionIntent. It is not an execution authorization: the gateway
        reauthenticates inside its atomic reservation transaction and again
        when claiming execution.
        """
        if not isinstance(token, str) or not token or token.strip() != token:
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT max_transaction, daily_limit, allowed_recipients,
                          chain_id, agent_token_hash
                FROM policies WHERE policy_id = ?""",
                (policy_id,),
            ).fetchone()
        finally:
            connection.close()

        if row is None or not row["agent_token_hash"]:
            return None
        supplied_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(row["agent_token_hash"], supplied_hash):
            return None
        return self._policy(row)

    def evaluate_and_reserve(
        self,
        policy_id: str,
        amount: Decimal | str,
        recipient: str,
        request_id: str,
        now: datetime | None = None,
    ) -> Decision | None:
        """Evaluate and reserve for trusted in-process callers.

        API requests must use evaluate_and_reserve_authenticated so token
        verification and reservation share one SQLite write transaction.
        """
        return self._evaluate_and_reserve(
            policy_id, amount, recipient, request_id, now=now
        )

    def evaluate_and_reserve_authenticated(
        self,
        policy_id: str,
        token: str,
        amount: Decimal | str,
        recipient: str,
        request_id: str,
        now: datetime | None = None,
    ) -> Decision | None:
        """Authenticate and reserve atomically; return None for invalid credentials."""
        return self._evaluate_and_reserve(
            policy_id, amount, recipient, request_id, now=now, agent_token=token
        )

    @staticmethod
    def _gateway_operation(row: sqlite3.Row) -> dict[str, object]:
        return {
            "operation_id": row["operation_id"],
            "policy_id": row["policy_id"],
            "idempotency_key": row["idempotency_key"],
            "canonical_intent": row["canonical_intent"],
            "status": row["status"],
            "allowed": bool(row["allowed"]),
            "reason_code": row["reason_code"],
            "reason": row["reason"],
            "result": row["result"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "reservation_status": (
                row["reservation_status"] if "reservation_status" in row.keys() else None
            ),
            "execution_status": (
                row["execution_status"] if "execution_status" in row.keys() else None
            ),
        }

    @staticmethod
    def _insert_gateway_event(
        connection: sqlite3.Connection,
        operation_id: str,
        previous_status: str | None,
        new_status: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        reason: str,
        created_at: str,
    ) -> None:
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError("Audit reason must contain 1-500 non-whitespace characters.")
        connection.execute(
            """INSERT INTO gateway_operation_events (
                operation_id, previous_status, new_status, event_type,
                actor_type, actor_id, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (operation_id, previous_status, new_status, event_type,
             actor_type, actor_id, reason.strip(), created_at),
        )

    def begin_gateway_operation(
        self,
        intent: object,
        agent_token: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        """Authenticate, bind an idempotency key, evaluate, and reserve atomically.

        intent is duck-typed here to avoid a storage -> gateway import cycle.
        The gateway passes a validated ActionIntent instance.
        """
        policy_id = getattr(intent, "policy_id", None)
        amount = getattr(intent, "amount", None)
        recipient = getattr(intent, "recipient", None)
        chain_id = getattr(intent, "chain_id", None)
        canonical_intent = getattr(intent, "canonical_json", None)
        if (
            not isinstance(policy_id, str)
            or not isinstance(amount, Decimal)
            or not isinstance(recipient, str)
            or not isinstance(canonical_intent, str)
        ):
            raise ValueError("intent must be a validated ActionIntent.")
        if not isinstance(agent_token, str) or not agent_token or agent_token.strip() != agent_token:
            return None
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key
            or idempotency_key.strip() != idempotency_key
            or len(idempotency_key) > 200
        ):
            raise ValueError("idempotency_key must be 1-200 non-whitespace characters.")

        utc_day = (
            (now or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .date()
            .isoformat()
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            policy_row = connection.execute(
                """SELECT max_transaction, daily_limit, allowed_recipients, chain_id,
                          agent_token_hash
                FROM policies WHERE policy_id = ?""",
                (policy_id,),
            ).fetchone()
            if policy_row is None:
                connection.commit()
                return None
            stored_hash = policy_row["agent_token_hash"]
            supplied_hash = hashlib.sha256(agent_token.encode("utf-8")).hexdigest()
            if not stored_hash or not hmac.compare_digest(stored_hash, supplied_hash):
                connection.commit()
                return None

            previous = connection.execute(
                """SELECT operations.*, reservations.reservation_status AS reservation_status,
                       jobs.status AS execution_status
                FROM gateway_operations AS operations
                LEFT JOIN daily_reservations AS reservations
                  ON reservations.policy_id = operations.policy_id
                 AND reservations.request_id = 'gateway:' || operations.operation_id
                LEFT JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = operations.operation_id
                WHERE operations.idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if previous is not None:
                if (
                    previous["policy_id"] != policy_id
                    or previous["canonical_intent"] != canonical_intent
                ):
                    raise IdempotencyConflict(
                        "idempotency_key has already been used with a different policy or action intent."
                    )
                operation = self._gateway_operation(previous)
                connection.commit()
                return operation

            policy = self._policy(policy_row)
            if policy.chain_id != chain_id:
                raise ValueError("ActionIntent chain_id does not match the stored policy.")
            normalized_recipient = normalize_recipient(recipient, policy.chain_id)
            if normalized_recipient != recipient:
                raise ValueError("ActionIntent recipient is not normalized for the stored policy.")

            # Use a random operation-scoped reservation ID rather than the
            # caller's key so legacy API request_id values cannot collide.
            operation_id = str(uuid.uuid4())
            reservation_id = f"gateway:{operation_id}"

            usage = connection.execute(
                """SELECT amount FROM daily_reservations
                WHERE policy_id = ? AND utc_day = ? AND allowed = 1
                  AND reservation_status IN ('RESERVED', 'SETTLED')""",
                (policy_id, utc_day),
            ).fetchall()
            with localcontext() as context:
                context.prec = EXACT_ARITHMETIC_PRECISION
                daily_reserved = sum(
                    (Decimal(row["amount"]) for row in usage), Decimal("0")
                )
            request = TransactionRequest(amount, normalized_recipient, daily_reserved)
            decision = check_transaction(request, policy)
            connection.execute(
                """INSERT INTO daily_reservations
                (policy_id, request_id, utc_day, amount, recipient, allowed, reason_code, reason, reservation_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy_id,
                    reservation_id,
                    utc_day,
                    str(amount),
                    normalized_recipient,
                    int(decision.allowed),
                    decision.reason_code.value,
                    decision.reason,
                    "RESERVED" if decision.allowed else "NOT_RESERVED",
                ),
            )
            status = "APPROVED" if decision.allowed else "DENIED"
            connection.execute(
                """INSERT INTO gateway_operations (
                    operation_id, policy_id, idempotency_key, canonical_intent,
                    status, allowed, reason_code, reason, result, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)""",
                (
                    operation_id,
                    policy_id,
                    idempotency_key,
                    canonical_intent,
                    status,
                    int(decision.allowed),
                    decision.reason_code.value,
                    decision.reason,
                    timestamp,
                    timestamp,
                ),
            )
            if decision.allowed:
                connection.execute(
                    """INSERT INTO gateway_execution_jobs (
                        operation_id, status, fencing_token, worker_id,
                        lease_expires_at, created_at, updated_at
                    ) VALUES (?, 'QUEUED', 0, NULL, NULL, ?, ?)""",
                    (operation_id, timestamp, timestamp),
                )
            row = connection.execute(
                """SELECT operations.*, reservations.reservation_status AS reservation_status,
                       jobs.status AS execution_status
                FROM gateway_operations AS operations
                LEFT JOIN daily_reservations AS reservations
                  ON reservations.policy_id = operations.policy_id
                 AND reservations.request_id = 'gateway:' || operations.operation_id
                LEFT JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = operations.operation_id
                WHERE operations.operation_id = ?""",
                (operation_id,),
            ).fetchone()
            self._insert_gateway_event(
                connection, operation_id, None, status, "OPERATION_CREATED",
                "system", "gateway",
                "Policy approved the action." if decision.allowed else "Policy denied the action.",
                timestamp,
            )
            connection.commit()
            return self._gateway_operation(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


    def claim_execution_job(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        """Lease one queued job; expired pre-dispatch leases may be reclaimed."""
        if (
            not isinstance(worker_id, str)
            or not worker_id
            or worker_id.strip() != worker_id
            or len(worker_id) > 100
        ):
            raise ValueError("worker_id must contain 1-100 non-whitespace characters without surrounding whitespace.")
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be an integer between 5 and 300.")
        reference_time = now or datetime.now(timezone.utc)
        if (
            not isinstance(reference_time, datetime)
            or reference_time.tzinfo is None
            or reference_time.utcoffset() is None
        ):
            raise ValueError("now must be a timezone-aware datetime.")
        timestamp_dt = reference_time.astimezone(timezone.utc)
        timestamp = timestamp_dt.isoformat()
        lease_expires_at = (timestamp_dt + timedelta(seconds=lease_seconds)).isoformat()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT jobs.operation_id, jobs.fencing_token,
                          operations.canonical_intent, operations.policy_id,
                          operations.status AS operation_status
                FROM gateway_execution_jobs AS jobs
                JOIN gateway_operations AS operations
                  ON operations.operation_id = jobs.operation_id
                WHERE operations.status = 'APPROVED'
                  AND (
                    jobs.status = 'QUEUED'
                    OR (jobs.status = 'LEASED'
                        AND jobs.lease_expires_at IS NOT NULL
                        AND jobs.lease_expires_at <= ?)
                  )
                ORDER BY jobs.created_at, jobs.operation_id
                LIMIT 1""",
                (timestamp,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None

            next_token = int(row["fencing_token"]) + 1
            cursor = connection.execute(
                """UPDATE gateway_execution_jobs
                SET status = 'LEASED', fencing_token = ?, worker_id = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE operation_id = ? AND fencing_token = ?
                  AND (status = 'QUEUED' OR
                       (status = 'LEASED' AND lease_expires_at <= ?))""",
                (next_token, worker_id, lease_expires_at, timestamp,
                 row["operation_id"], row["fencing_token"], timestamp),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return None
            self._insert_gateway_event(
                connection, row["operation_id"], "APPROVED", "APPROVED",
                "WORKER_LEASED", "worker", worker_id,
                "Worker acquired a bounded pre-dispatch lease.", timestamp,
            )
            connection.commit()
            return {
                "operation_id": row["operation_id"],
                "policy_id": row["policy_id"],
                "canonical_intent": row["canonical_intent"],
                "worker_id": worker_id,
                "fencing_token": next_token,
                "lease_expires_at": lease_expires_at,
            }
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def start_execution_job(
        self,
        operation_id: str,
        worker_id: str,
        fencing_token: int,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Cross the irreversible dispatch boundary while the lease is valid."""
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 100:
            raise ValueError("worker_id must contain 1-100 non-whitespace characters.")
        if type(fencing_token) is not int or fencing_token < 1:
            raise ValueError("fencing_token must be a positive integer.")
        reference_time = now or datetime.now(timezone.utc)
        if reference_time.tzinfo is None or reference_time.utcoffset() is None:
            raise ValueError("now must be timezone-aware.")
        timestamp = reference_time.astimezone(timezone.utc).isoformat()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute(
                """SELECT status, worker_id, fencing_token, lease_expires_at
                FROM gateway_execution_jobs WHERE operation_id = ?""",
                (operation_id,),
            ).fetchone()
            if (
                job is None
                or job["status"] != "LEASED"
                or job["worker_id"] != worker_id
                or job["fencing_token"] != fencing_token
                or not job["lease_expires_at"]
                or job["lease_expires_at"] <= timestamp
            ):
                connection.commit()
                return False
            operation = connection.execute(
                "SELECT status FROM gateway_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if operation is None or operation["status"] != "APPROVED":
                connection.commit()
                return False
            job_cursor = connection.execute(
                """UPDATE gateway_execution_jobs
                SET status = 'DISPATCH_STARTED', lease_expires_at = NULL,
                    updated_at = ?
                WHERE operation_id = ? AND status = 'LEASED'
                  AND worker_id = ? AND fencing_token = ?
                  AND lease_expires_at > ?""",
                (timestamp, operation_id, worker_id, fencing_token, timestamp),
            )
            if job_cursor.rowcount != 1:
                connection.commit()
                return False
            operation_cursor = connection.execute(
                """UPDATE gateway_operations SET status = 'EXECUTING', updated_at = ?
                WHERE operation_id = ? AND status = 'APPROVED'""",
                (timestamp, operation_id),
            )
            if operation_cursor.rowcount != 1:
                raise RuntimeError("Operation state changed while starting execution.")
            self._insert_gateway_event(
                connection, operation_id, "APPROVED", "EXECUTING",
                "DISPATCH_STARTED", "worker", worker_id,
                "Worker durably marked dispatch as started; this job must not be replayed.",
                timestamp,
            )
            connection.commit()
            return True
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def complete_execution_job(
        self,
        operation_id: str,
        worker_id: str,
        fencing_token: int,
        status: str,
        result: str | None = None,
        *,
        no_side_effect_confirmed: bool = False,
    ) -> bool:
        """Persist a worker result only while its dispatch fence is current."""
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError("Invalid terminal gateway operation status.")
        if result is not None and (not isinstance(result, str) or len(result) > 1000):
            raise ValueError("Gateway operation result must be a string of at most 1000 characters.")
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 100:
            raise ValueError("worker_id must contain 1-100 non-whitespace characters.")
        if type(fencing_token) is not int or fencing_token < 1:
            raise ValueError("fencing_token must be a positive integer.")
        if type(no_side_effect_confirmed) is not bool:
            raise ValueError("no_side_effect_confirmed must be a boolean.")
        if status == "FAILED" and not no_side_effect_confirmed:
            raise ValueError("FAILED requires confirmation that no side effect occurred.")
        if status != "FAILED" and no_side_effect_confirmed:
            raise ValueError("No-side-effect confirmation is valid only for FAILED.")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT operations.policy_id, operations.status,
                          jobs.status AS job_status, jobs.worker_id,
                          jobs.fencing_token
                FROM gateway_operations AS operations
                JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = operations.operation_id
                WHERE operations.operation_id = ?""",
                (operation_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "EXECUTING"
                or row["job_status"] != "DISPATCH_STARTED"
                or row["worker_id"] != worker_id
                or row["fencing_token"] != fencing_token
            ):
                connection.commit()
                return False

            timestamp = datetime.now(timezone.utc).isoformat()
            operation_cursor = connection.execute(
                """UPDATE gateway_operations
                SET status = ?, result = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'EXECUTING'""",
                (status, result, timestamp, operation_id),
            )
            if operation_cursor.rowcount != 1:
                connection.commit()
                return False
            job_cursor = connection.execute(
                """UPDATE gateway_execution_jobs
                SET status = ?, worker_id = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE operation_id = ? AND status = 'DISPATCH_STARTED'
                  AND worker_id = ? AND fencing_token = ?""",
                ("COMPLETED" if status in {"SUCCEEDED", "FAILED"} else "UNKNOWN",
                 timestamp, operation_id, worker_id, fencing_token),
            )
            if job_cursor.rowcount != 1:
                raise RuntimeError("Execution job fencing changed during completion.")

            safe_reason = (
                "Worker executor completed successfully." if status == "SUCCEEDED"
                else "Trusted worker executor confirmed no side effect occurred." if status == "FAILED"
                else "Worker execution outcome is uncertain."
            )
            self._insert_gateway_event(
                connection, operation_id, "EXECUTING", status,
                "EXECUTION_COMPLETED", "worker", worker_id, safe_reason, timestamp,
            )

            if status in {"SUCCEEDED", "FAILED"}:
                next_reservation_status = "SETTLED" if status == "SUCCEEDED" else "RELEASED"
                reservation = connection.execute(
                    """UPDATE daily_reservations SET reservation_status = ?
                    WHERE policy_id = ? AND request_id = ?
                      AND allowed = 1 AND reservation_status = 'RESERVED'""",
                    (next_reservation_status, row["policy_id"], f"gateway:{operation_id}"),
                )
                if reservation.rowcount != 1:
                    raise RuntimeError("Gateway operation has no active budget reservation to settle or release.")
                event_type = "RESERVATION_SETTLED" if status == "SUCCEEDED" else "RESERVATION_RELEASED"
                event_reason = (
                    "Approved budget reservation was committed after successful worker execution."
                    if status == "SUCCEEDED"
                    else "Budget reservation was released after the trusted worker confirmed no side effect."
                )
                self._insert_gateway_event(
                    connection, operation_id, status, status, event_type,
                    "worker", worker_id, event_reason, timestamp,
                )
            connection.commit()
            return True
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def get_gateway_execution_status(self, operation_id: str) -> str | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT status FROM gateway_execution_jobs WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else str(row["status"])

    def claim_gateway_operation(
        self,
        operation_id: str,
        agent_token: str,
    ) -> bool | None:
        """Authenticate the current token and claim APPROVED atomically.

        Return None when credentials are invalid, False when the operation is
        not claimable, and True only after the EXECUTING transition commits.
        """
        if not isinstance(agent_token, str) or not agent_token or agent_token.strip() != agent_token:
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT gateway_operations.status, policies.agent_token_hash,
                          jobs.status AS job_status
                FROM gateway_operations
                JOIN policies ON policies.policy_id = gateway_operations.policy_id
                LEFT JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = gateway_operations.operation_id
                WHERE gateway_operations.operation_id = ?""",
                (operation_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "APPROVED"
                or (row["job_status"] is not None and row["job_status"] != "QUEUED")
            ):
                connection.commit()
                return False
            supplied_hash = hashlib.sha256(agent_token.encode("utf-8")).hexdigest()
            stored_hash = row["agent_token_hash"]
            if not stored_hash or not hmac.compare_digest(stored_hash, supplied_hash):
                connection.commit()
                return None
            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = connection.execute(
                """UPDATE gateway_operations
                SET status = 'EXECUTING', updated_at = ?
                WHERE operation_id = ? AND status = 'APPROVED'""",
                (timestamp, operation_id),
            )
            if cursor.rowcount == 1:
                connection.execute(
                    """UPDATE gateway_execution_jobs
                    SET status = 'DISPATCH_STARTED',
                        fencing_token = fencing_token + 1,
                        worker_id = 'inline-gateway',
                        lease_expires_at = NULL,
                        updated_at = ?
                    WHERE operation_id = ? AND status = 'QUEUED'""",
                    (timestamp, operation_id),
                )
            if cursor.rowcount == 1:
                self._insert_gateway_event(
                    connection, operation_id, "APPROVED", "EXECUTING",
                    "EXECUTION_CLAIMED", "system", "gateway",
                    "Gateway atomically claimed the operation for execution.", timestamp,
                )
            connection.commit()
            return cursor.rowcount == 1
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def complete_gateway_operation(
        self,
        operation_id: str,
        status: str,
        result: str | None = None,
        *,
        no_side_effect_confirmed: bool = False,
    ) -> bool:
        """Persist an execution outcome and its budget effect atomically.

        FAILED is accepted only from a trusted executor path that explicitly
        confirms no side effect occurred. UNKNOWN deliberately keeps the
        reservation active.
        """
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError("Invalid terminal gateway operation status.")
        if result is not None and (not isinstance(result, str) or len(result) > 1000):
            raise ValueError("Gateway operation result must be a string of at most 1000 characters.")
        if type(no_side_effect_confirmed) is not bool:
            raise ValueError("no_side_effect_confirmed must be a boolean.")
        if status == "FAILED" and no_side_effect_confirmed is not True:
            raise ValueError("FAILED requires confirmation that no side effect occurred.")
        if status != "FAILED" and no_side_effect_confirmed:
            raise ValueError("No-side-effect confirmation is valid only for FAILED.")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """SELECT policy_id, status, allowed
                FROM gateway_operations WHERE operation_id = ?""",
                (operation_id,),
            ).fetchone()
            if operation is None or operation["status"] != "EXECUTING":
                connection.commit()
                return False

            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = connection.execute(
                """UPDATE gateway_operations
                SET status = ?, result = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'EXECUTING'""",
                (status, result, timestamp, operation_id),
            )
            if cursor.rowcount != 1:
                connection.commit()
                return False

            connection.execute(
                """UPDATE gateway_execution_jobs
                SET status = ?, worker_id = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE operation_id = ? AND status = 'DISPATCH_STARTED'""",
                ("COMPLETED" if status in {"SUCCEEDED", "FAILED"} else "UNKNOWN",
                 timestamp, operation_id),
            )

            safe_reason = (
                "Executor completed successfully." if status == "SUCCEEDED"
                else "Trusted executor confirmed that no side effect occurred." if status == "FAILED"
                else "Execution outcome is uncertain."
            )
            self._insert_gateway_event(
                connection, operation_id, "EXECUTING", status,
                "EXECUTION_COMPLETED", "system", "gateway", safe_reason, timestamp,
            )

            if status in {"SUCCEEDED", "FAILED"}:
                next_reservation_status = "SETTLED" if status == "SUCCEEDED" else "RELEASED"
                reservation = connection.execute(
                    """UPDATE daily_reservations
                    SET reservation_status = ?
                    WHERE policy_id = ? AND request_id = ?
                      AND allowed = 1 AND reservation_status = 'RESERVED'""",
                    (next_reservation_status, operation["policy_id"], f"gateway:{operation_id}"),
                )
                if reservation.rowcount != 1:
                    raise RuntimeError("Gateway operation has no active budget reservation to settle or release.")
                event_type = "RESERVATION_SETTLED" if status == "SUCCEEDED" else "RESERVATION_RELEASED"
                event_reason = (
                    "Approved budget reservation was committed after successful execution."
                    if status == "SUCCEEDED"
                    else "Budget reservation was released after the trusted executor confirmed no side effect."
                )
                self._insert_gateway_event(
                    connection, operation_id, status, status, event_type,
                    "system", "gateway", event_reason, timestamp,
                )

            connection.commit()
            return True
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def get_gateway_operation(
        self,
        policy_id: str,
        idempotency_key: str,
    ) -> dict[str, object] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT operations.*, reservations.reservation_status AS reservation_status,
                       jobs.status AS execution_status
                FROM gateway_operations AS operations
                LEFT JOIN daily_reservations AS reservations
                  ON reservations.policy_id = operations.policy_id
                 AND reservations.request_id = 'gateway:' || operations.operation_id
                LEFT JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = operations.operation_id
                WHERE operations.policy_id = ? AND operations.idempotency_key = ?""",
                (policy_id, idempotency_key),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._gateway_operation(row)

    def get_gateway_operation_by_id(self, operation_id: str) -> dict[str, object] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT operations.*, reservations.reservation_status AS reservation_status,
                       jobs.status AS execution_status
                FROM gateway_operations AS operations
                LEFT JOIN daily_reservations AS reservations
                  ON reservations.policy_id = operations.policy_id
                 AND reservations.request_id = 'gateway:' || operations.operation_id
                LEFT JOIN gateway_execution_jobs AS jobs
                  ON jobs.operation_id = operations.operation_id
                WHERE operations.operation_id = ?""",
                (operation_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._gateway_operation(row)

    def list_gateway_operation_events(self, operation_id: str) -> list[dict[str, object]] | None:
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM gateway_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if exists is None:
                return None
            rows = connection.execute(
                """SELECT event_id, operation_id, previous_status, new_status,
                          event_type, actor_type, actor_id, reason, created_at
                FROM gateway_operation_events
                WHERE operation_id = ? ORDER BY event_id""",
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()
        return [dict(row) for row in rows]

    def reconcile_gateway_operation_unknown(
        self, operation_id: str, actor_id: str, reason: str
    ) -> bool:
        if not isinstance(actor_id, str) or not actor_id.strip() or len(actor_id) > 100:
            raise ValueError("Audit actor_id must contain 1-100 non-whitespace characters.")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError("Reconciliation reason must contain 1-500 non-whitespace characters.")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = connection.execute(
                """UPDATE gateway_operations
                SET status = 'UNKNOWN', result = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'EXECUTING'""",
                ("Manually reconciled; outcome remains unknown.", timestamp, operation_id),
            )
            if cursor.rowcount == 1:
                connection.execute(
                    """UPDATE gateway_execution_jobs
                    SET status = 'UNKNOWN', worker_id = NULL,
                        lease_expires_at = NULL, updated_at = ?
                    WHERE operation_id = ? AND status IN ('LEASED', 'DISPATCH_STARTED')""",
                    (timestamp, operation_id),
                )
            if cursor.rowcount == 1:
                self._insert_gateway_event(
                    connection, operation_id, "EXECUTING", "UNKNOWN",
                    "MANUAL_RECONCILIATION", "owner", actor_id,
                    reason.strip(), timestamp,
                )
            connection.commit()
            return cursor.rowcount == 1
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def recover_stale_gateway_operations(
        self,
        stale_after_seconds: int,
        *,
        limit: int = 100,
        now: datetime | None = None,
        actor_id: str = "owner-recovery",
        reason: str = "Operation exceeded the stale execution threshold; outcome remains unknown.",
    ) -> list[str]:
        """Atomically move stale EXECUTING operations to UNKNOWN.

        This is detection/reconciliation only: it never invokes an executor or
        releases a reservation. A normal completion racing this method wins
        only if its transaction commits first.
        """
        if type(stale_after_seconds) is not int or not 60 <= stale_after_seconds <= 604800:
            raise ValueError("stale_after_seconds must be an integer between 60 and 604800.")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100.")
        if not isinstance(actor_id, str) or not actor_id.strip() or len(actor_id) > 100:
            raise ValueError("Audit actor_id must contain 1-100 non-whitespace characters.")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError("Recovery reason must contain 1-500 non-whitespace characters.")
        reference_time = now or datetime.now(timezone.utc)
        if reference_time.tzinfo is None or reference_time.utcoffset() is None:
            raise ValueError("now must be timezone-aware.")
        cutoff = (reference_time.astimezone(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT operation_id FROM gateway_operations
                WHERE status = 'EXECUTING' AND updated_at <= ?
                ORDER BY updated_at, operation_id LIMIT ?""",
                (cutoff, limit),
            ).fetchall()
            recovered: list[str] = []
            timestamp = datetime.now(timezone.utc).isoformat()
            for row in rows:
                operation_id = row["operation_id"]
                cursor = connection.execute(
                    """UPDATE gateway_operations
                    SET status = 'UNKNOWN', result = ?, updated_at = ?
                    WHERE operation_id = ? AND status = 'EXECUTING' AND updated_at <= ?""",
                    ("Stale execution recovered; outcome remains unknown.", timestamp, operation_id, cutoff),
                )
                if cursor.rowcount != 1:
                    continue
                connection.execute(
                    """UPDATE gateway_execution_jobs
                    SET status = 'UNKNOWN', worker_id = NULL,
                        lease_expires_at = NULL, updated_at = ?
                    WHERE operation_id = ? AND status = 'DISPATCH_STARTED'""",
                    (timestamp, operation_id),
                )
                self._insert_gateway_event(
                    connection, operation_id, "EXECUTING", "UNKNOWN",
                    "STALE_OPERATION_RECOVERY", "owner", actor_id, reason.strip(), timestamp,
                )
                recovered.append(operation_id)
            connection.commit()
            return recovered
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def mark_gateway_operation_unknown(self, operation_id: str) -> bool:
        """Backward-compatible trusted-internal helper."""
        return self.reconcile_gateway_operation_unknown(
            operation_id, "legacy-internal", "Legacy internal reconciliation."
        )

    def _evaluate_and_reserve(
        self,
        policy_id: str,
        amount: Decimal | str,
        recipient: str,
        request_id: str,
        now: datetime | None = None,
        agent_token: str | None = None,
    ) -> Decision | None:
        """Atomically authenticate (when supplied), evaluate, and reserve budget."""
        if isinstance(amount, (bool, float)):
            raise ValueError(
                "amount must be a Decimal or decimal string, not a float."
            )
        transaction_amount = Decimal(amount)
        utc_day = (
            (now or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .date()
            .isoformat()
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            policy_row = connection.execute(
                """SELECT max_transaction, daily_limit, allowed_recipients, chain_id,
                          agent_token_hash
                FROM policies WHERE policy_id = ?""",
                (policy_id,),
            ).fetchone()
            if policy_row is None:
                connection.commit()
                return None
            if agent_token is not None:
                stored_hash = policy_row["agent_token_hash"]
                supplied_hash = hashlib.sha256(agent_token.encode("utf-8")).hexdigest()
                if not stored_hash or not hmac.compare_digest(stored_hash, supplied_hash):
                    connection.commit()
                    return None
            policy = self._policy(policy_row)
            normalised_recipient = normalize_recipient(recipient, policy.chain_id)

            previous = connection.execute(
                """SELECT amount, recipient, allowed, reason_code, reason
                FROM daily_reservations WHERE policy_id = ? AND request_id = ?""",
                (policy_id, request_id),
            ).fetchone()
            if previous is not None:
                if (
                    Decimal(previous["amount"]) != transaction_amount
                    or previous["recipient"] != normalised_recipient
                ):
                    raise IdempotencyConflict(
                        "request_id has already been used with a different transaction."
                    )
                decision = self._decision(previous)
                connection.commit()
                return decision

            usage = connection.execute(
                """SELECT amount FROM daily_reservations
                WHERE policy_id = ? AND utc_day = ? AND allowed = 1
                  AND reservation_status IN ('RESERVED', 'SETTLED')""",
                (policy_id, utc_day),
            ).fetchall()
            # Aggregate reservations with the same exact precision used by
            # the policy engine; the default Decimal context can round totals.
            with localcontext() as context:
                context.prec = EXACT_ARITHMETIC_PRECISION
                daily_reserved = sum(
                    (Decimal(row["amount"]) for row in usage), Decimal("0")
                )
            request = TransactionRequest(
                transaction_amount, normalised_recipient, daily_reserved
            )
            decision = check_transaction(request, policy)
            connection.execute(
                """INSERT INTO daily_reservations
                (policy_id, request_id, utc_day, amount, recipient, allowed, reason_code, reason, reservation_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy_id,
                    request_id,
                    utc_day,
                    str(transaction_amount),
                    normalised_recipient,
                    int(decision.allowed),
                    decision.reason_code.value,
                    decision.reason,
                    "SETTLED" if decision.allowed else "NOT_RESERVED",
                ),
            )
            connection.commit()
            return decision
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
