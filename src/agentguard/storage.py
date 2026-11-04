"""SQLite persistence for policies and atomic daily-budget reservations."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from agentguard.policy import Decision, DecisionReason, Policy, TransactionRequest, check_transaction


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a different request."""


class SQLitePolicyStore:
    """Persist policies and serialize daily-budget reservations in SQLite."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
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
                        agent_token_hash TEXT
                    )"""
                )
                # Existing databases have the original five-column policies table.
                # Add a nullable column so legacy policies remain readable but cannot
                # authenticate an agent until the owner rotates their token.
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(policies)").fetchall()
                }
                if "agent_token_hash" not in columns:
                    connection.execute(
                        "ALTER TABLE policies ADD COLUMN agent_token_hash TEXT"
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
                        allowed_recipients, created_at, agent_token_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        policy_id,
                        str(policy.max_transaction),
                        str(policy.daily_limit),
                        recipients,
                        created_at,
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
                """SELECT max_transaction, daily_limit, allowed_recipients
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
        """Atomically evaluate and reserve allowed budget; not an on-chain spend."""
        transaction_amount = Decimal(amount)
        normalised_recipient = recipient.strip().lower()
        utc_day = (
            (now or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .date()
            .isoformat()
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
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

            policy_row = connection.execute(
                """SELECT max_transaction, daily_limit, allowed_recipients
                FROM policies WHERE policy_id = ?""",
                (policy_id,),
            ).fetchone()
            if policy_row is None:
                connection.commit()
                return None
            policy = self._policy(policy_row)
            usage = connection.execute(
                """SELECT amount FROM daily_reservations
                WHERE policy_id = ? AND utc_day = ? AND allowed = 1""",
                (policy_id, utc_day),
            ).fetchall()
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
