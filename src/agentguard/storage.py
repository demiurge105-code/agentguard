"""SQLite persistence for policies and atomic daily-budget reservations."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
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
                        UNIQUE (policy_id, idempotency_key),
                        FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
                    )"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_gateway_operations_status
                    ON gateway_operations(status, updated_at)"""
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
        }

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
                """SELECT * FROM gateway_operations
                WHERE policy_id = ? AND idempotency_key = ?""",
                (policy_id, idempotency_key),
            ).fetchone()
            if previous is not None:
                if previous["canonical_intent"] != canonical_intent:
                    raise IdempotencyConflict(
                        "idempotency_key has already been used with a different action intent."
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

            # Keep gateway idempotency keys separate from legacy request_id values.
            reservation_id = f"gateway:{idempotency_key}"
            previous_reservation = connection.execute(
                """SELECT 1 FROM daily_reservations
                WHERE policy_id = ? AND request_id = ?""",
                (policy_id, reservation_id),
            ).fetchone()
            if previous_reservation is not None:
                raise IdempotencyConflict(
                    "A reservation already exists for this gateway idempotency key."
                )

            usage = connection.execute(
                """SELECT amount FROM daily_reservations
                WHERE policy_id = ? AND utc_day = ? AND allowed = 1""",
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
                (policy_id, request_id, utc_day, amount, recipient, allowed, reason_code, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy_id,
                    reservation_id,
                    utc_day,
                    str(amount),
                    normalized_recipient,
                    int(decision.allowed),
                    decision.reason_code.value,
                    decision.reason,
                ),
            )
            operation_id = str(uuid.uuid4())
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
            row = connection.execute(
                "SELECT * FROM gateway_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            connection.commit()
            return self._gateway_operation(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def claim_gateway_operation(self, operation_id: str) -> bool:
        """Atomically claim an approved operation for its single executor attempt."""
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    """UPDATE gateway_operations
                    SET status = 'EXECUTING', updated_at = ?
                    WHERE operation_id = ? AND status = 'APPROVED'""",
                    (datetime.now(timezone.utc).isoformat(), operation_id),
                )
                return cursor.rowcount == 1
        finally:
            connection.close()

    def complete_gateway_operation(
        self,
        operation_id: str,
        status: str,
        result: str | None = None,
    ) -> bool:
        """Persist an execution outcome; only EXECUTING operations can complete."""
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError("Invalid terminal gateway operation status.")
        if result is not None and (not isinstance(result, str) or len(result) > 1000):
            raise ValueError("Gateway operation result must be a string of at most 1000 characters.")
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    """UPDATE gateway_operations
                    SET status = ?, result = ?, updated_at = ?
                    WHERE operation_id = ? AND status = 'EXECUTING'""",
                    (
                        status,
                        result,
                        datetime.now(timezone.utc).isoformat(),
                        operation_id,
                    ),
                )
                return cursor.rowcount == 1
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
                """SELECT * FROM gateway_operations
                WHERE policy_id = ? AND idempotency_key = ?""",
                (policy_id, idempotency_key),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._gateway_operation(row)

    def mark_gateway_operation_unknown(self, operation_id: str) -> bool:
        """Explicitly mark an unresolved EXECUTING operation as UNKNOWN.

        This does not authorize another execution attempt.
        """
        return self.complete_gateway_operation(operation_id, "UNKNOWN")

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
                WHERE policy_id = ? AND utc_day = ? AND allowed = 1""",
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
                (policy_id, request_id, utc_day, amount, recipient, allowed, reason_code, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy_id,
                    request_id,
                    utc_day,
                    str(transaction_amount),
                    normalised_recipient,
                    int(decision.allowed),
                    decision.reason_code.value,
                    decision.reason,
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
