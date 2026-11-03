"""SQLite persistence for owner-controlled AgentGuard policies."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentguard.policy import Policy


class SQLitePolicyStore:
    """Persist policies in SQLite without converting money to binary floats."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialise(self) -> None:
        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policies (
                        policy_id TEXT PRIMARY KEY,
                        max_transaction TEXT NOT NULL,
                        daily_limit TEXT NOT NULL,
                        allowed_recipients TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
        finally:
            connection.close()

    def create_policy(self, policy: Policy) -> str:
        policy_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        recipients_json = json.dumps(
            sorted(policy.allowed_recipients),
            separators=(",", ":"),
        )

        connection = self._connect()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO policies (
                        policy_id,
                        max_transaction,
                        daily_limit,
                        allowed_recipients,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        policy_id,
                        str(policy.max_transaction),
                        str(policy.daily_limit),
                        recipients_json,
                        created_at,
                    ),
                )
        finally:
            connection.close()

        return policy_id

    def get_policy(self, policy_id: str) -> Policy | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT max_transaction, daily_limit, allowed_recipients
                FROM policies
                WHERE policy_id = ?
                """,
                (policy_id,),
            ).fetchone()
        finally:
            connection.close()

        if row is None:
            return None

        recipients = json.loads(row["allowed_recipients"])
        return Policy(
            max_transaction=row["max_transaction"],
            daily_limit=row["daily_limit"],
            allowed_recipients=recipients,
        )
