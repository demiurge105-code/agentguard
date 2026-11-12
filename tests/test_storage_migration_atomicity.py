import hashlib
import sqlite3

import pytest

from agentguard.intent import ActionIntent
from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore


def test_execution_job_schema_migration_rolls_back_if_copy_fails(
    tmp_path, monkeypatch
):
    path = tmp_path / "migration-rollback.db"
    store = SQLitePolicyStore(path)
    token = "migration-rollback-token"
    policy_id = store.create_policy(
        Policy("100", "100", ["Alice"]),
        hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    operation = store.begin_gateway_operation(
        ActionIntent(policy_id, "10", "Alice"),
        token,
        "migration-rollback",
    )
    operation_id = operation["operation_id"]

    # Recreate the pre-CANCELLED schema while preserving its queued job.
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP INDEX idx_gateway_execution_jobs_claim")
        connection.execute(
            """CREATE TABLE gateway_execution_jobs_legacy (
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
            """INSERT INTO gateway_execution_jobs_legacy
            SELECT operation_id, status, fencing_token, worker_id,
                   lease_expires_at, created_at, updated_at
            FROM gateway_execution_jobs"""
        )
        connection.execute("DROP TABLE gateway_execution_jobs")
        connection.execute(
            "ALTER TABLE gateway_execution_jobs_legacy RENAME TO gateway_execution_jobs"
        )
        connection.execute(
            """CREATE INDEX idx_gateway_execution_jobs_claim
            ON gateway_execution_jobs(status, lease_expires_at, created_at)"""
        )
        connection.commit()
    finally:
        connection.close()

    original_connect = SQLitePolicyStore._connect

    class FailingConnection:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, *args):
            if sql.lstrip().upper().startswith(
                "INSERT INTO GATEWAY_EXECUTION_JOBS_NEW"
            ):
                raise RuntimeError("simulated migration copy failure")
            return self._connection.execute(sql, *args)

        def __enter__(self):
            self._connection.__enter__()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return self._connection.__exit__(exc_type, exc_value, traceback)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    def failing_connect(instance):
        return FailingConnection(original_connect(instance))

    monkeypatch.setattr(SQLitePolicyStore, "_connect", failing_connect)

    with pytest.raises(RuntimeError, match="simulated migration copy failure"):
        SQLitePolicyStore(path)

    # Restore the normal connector before inspecting the persisted database.
    monkeypatch.undo()
    connection = sqlite3.connect(path)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "gateway_execution_jobs_new" not in tables

        job = connection.execute(
            """SELECT operation_id, status FROM gateway_execution_jobs
            WHERE operation_id = ?""",
            (operation_id,),
        ).fetchone()
        assert job == (operation_id, "QUEUED")

        schema = connection.execute(
            """SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'gateway_execution_jobs'"""
        ).fetchone()[0]
        assert "'CANCELLED'" not in schema
    finally:
        connection.close()
