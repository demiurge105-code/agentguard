import asyncio
import importlib
import sqlite3
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

import agentguard.api as api_module
from agentguard.api import create_app
from agentguard.policy import Policy
from agentguard.storage import SQLitePolicyStore


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def admin_token():
    return "test-admin-token"


@pytest.fixture
def app(tmp_path, admin_token):
    store = SQLitePolicyStore(tmp_path / "p.db")
    application = create_app(store, admin_token)
    application.state.store = store
    return application


async def create_policy(client, token, payload=None):
    payload = payload or {
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"],
    }
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return await client.post("/policies", json=payload, headers=headers)


def tx(policy_id, key, amount="10", recipient="Alice"):
    return {
        "policy_id": policy_id,
        "request_id": key,
        "amount": amount,
        "recipient": recipient,
    }


async def check(client, policy_id, key, token, amount="10", recipient="Alice"):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return await client.post(
        "/check-transaction",
        json=tx(policy_id, key, amount, recipient),
        headers=headers,
    )


@pytest.mark.anyio
async def test_owner_can_create_policy_and_receives_agent_token(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, admin_token)

    body = response.json()
    assert response.status_code == 201
    assert body["daily_limit"] == "500"
    assert body["allowed_recipients"] == ["alice", "bob"]
    assert isinstance(body["agent_token"], str) and len(body["agent_token"]) >= 40


@pytest.mark.anyio
async def test_new_policies_receive_unique_agent_tokens(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = (await create_policy(client, admin_token)).json()
        second = (await create_policy(client, admin_token)).json()

    assert first["agent_token"] != second["agent_token"]


@pytest.mark.anyio
async def test_only_agent_token_hash_is_stored(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()

    connection = app.state.store._connect()
    try:
        row = connection.execute(
            "SELECT agent_token_hash FROM policies WHERE policy_id = ?",
            (created["policy_id"],),
        ).fetchone()
    finally:
        connection.close()

    assert row["agent_token_hash"] != created["agent_token"]
    assert len(row["agent_token_hash"]) == 64
    assert app.state.store.authenticate_agent(created["policy_id"], created["agent_token"])


@pytest.mark.anyio
async def test_policy_creation_rejects_missing_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, None)
    assert response.status_code == 401


@pytest.mark.anyio
async def test_policy_creation_rejects_wrong_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, "wrong")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_unset_admin_token_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_ADMIN_TOKEN", raising=False)
    app = create_app(SQLitePolicyStore(tmp_path / "p.db"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, "any")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_check_rejects_missing_agent_token(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await check(client, created["policy_id"], "one", None)
    assert response.status_code == 401


@pytest.mark.anyio
async def test_check_rejects_invalid_agent_token(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await check(client, created["policy_id"], "one", "not-the-token")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_agent_token_is_bound_to_its_policy(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = (await create_policy(client, admin_token)).json()
        second = (await create_policy(client, admin_token)).json()
        response = await check(
            client, second["policy_id"], "cross-policy", first["agent_token"]
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_unknown_policy_and_invalid_token_both_return_401(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await check(client, "does-not-exist", "one", "invalid")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_valid_agent_token_can_check_and_reserve_budget(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (
            await create_policy(
                client,
                admin_token,
                {
                    "max_transaction": "1000",
                    "daily_limit": "500",
                    "allowed_recipients": ["Alice", "Bob"],
                },
            )
        ).json()
        first = await check(
            client, created["policy_id"], "one", created["agent_token"], "300"
        )
        second = await check(
            client, created["policy_id"], "two", created["agent_token"], "250"
        )

    assert first.json()["allowed"] is True
    assert second.json()["reason_code"] == "daily_limit_exceeded"


@pytest.mark.anyio
async def test_owner_can_rotate_agent_token_and_old_token_is_invalidated(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        rotated = await client.post(
            f"/policies/{created['policy_id']}/rotate-agent-token",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        old_check = await check(
            client, created["policy_id"], "old", created["agent_token"]
        )
        new_check = await check(
            client, created["policy_id"], "new", rotated.json()["agent_token"]
        )

    assert rotated.status_code == 200
    assert rotated.json()["agent_token"] != created["agent_token"]
    assert old_check.status_code == 401
    assert new_check.status_code == 200


@pytest.mark.anyio
async def test_token_rotation_requires_owner_authentication(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await client.post(
            f"/policies/{created['policy_id']}/rotate-agent-token",
            headers={"Authorization": "Bearer wrong"},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_rotation_of_unknown_policy_returns_404(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/policies/missing/rotate-agent-token",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_caller_cannot_supply_daily_spent(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        payload = tx(created["policy_id"], "one")
        payload["daily_spent"] = "0"
        response = await client.post(
            "/check-transaction",
            json=payload,
            headers={"Authorization": f"Bearer {created['agent_token']}"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_policy_overrides_are_rejected(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        payload = tx(created["policy_id"], "one", "150")
        payload["daily_limit"] = "1000"
        response = await client.post(
            "/check-transaction",
            json=payload,
            headers={"Authorization": f"Bearer {created['agent_token']}"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_api_retry_is_idempotent(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (
            await create_policy(
                client,
                admin_token,
                {
                    "max_transaction": "1000",
                    "daily_limit": "500",
                    "allowed_recipients": ["Alice", "Bob"],
                },
            )
        ).json()
        first = await check(client, created["policy_id"], "retry", created["agent_token"], "300")
        retry = await check(client, created["policy_id"], "retry", created["agent_token"], "300")
        next_request = await check(client, created["policy_id"], "next", created["agent_token"], "250")

    assert first.json() == retry.json()
    assert next_request.json()["reason_code"] == "daily_limit_exceeded"


@pytest.mark.anyio
async def test_concurrent_api_retries_with_same_request_id_reserve_once(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (
            await create_policy(
                client,
                admin_token,
                {
                    "max_transaction": "1000",
                    "daily_limit": "500",
                    "allowed_recipients": ["Alice", "Bob"],
                },
            )
        ).json()

        responses = await asyncio.gather(
            *[
                check(
                    client,
                    created["policy_id"],
                    "concurrent-retry",
                    created["agent_token"],
                    "300",
                )
                for _ in range(8)
            ]
        )
        next_request = await check(
            client,
            created["policy_id"],
            "after-concurrent-retry",
            created["agent_token"],
            "250",
        )

    assert all(response.status_code == 200 for response in responses)
    assert all(response.json() == responses[0].json() for response in responses)
    assert responses[0].json()["allowed"] is True
    assert next_request.status_code == 200
    assert next_request.json()["reason_code"] == "daily_limit_exceeded"


@pytest.mark.anyio
async def test_reused_request_id_with_different_payload_returns_409(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        await check(client, created["policy_id"], "same", created["agent_token"])
        response = await check(
            client, created["policy_id"], "same", created["agent_token"], "11"
        )
    assert response.status_code == 409


@pytest.mark.anyio
async def test_negative_amount_rejected(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await check(
            client, created["policy_id"], "negative", created["agent_token"], "-1"
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_empty_recipient_rejected(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await check(
            client, created["policy_id"], "empty", created["agent_token"], recipient="   "
        )
    assert response.status_code == 422


def test_existing_database_migrates_and_legacy_policy_needs_rotation(tmp_path):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """CREATE TABLE policies (
                policy_id TEXT PRIMARY KEY,
                max_transaction TEXT NOT NULL,
                daily_limit TEXT NOT NULL,
                allowed_recipients TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO policies VALUES (?, ?, ?, ?, ?)",
            ("legacy-policy", "100", "500", '["alice"]', datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    finally:
        connection.close()

    store = SQLitePolicyStore(path)
    assert store.get_policy("legacy-policy") is not None
    assert not store.authenticate_agent("legacy-policy", "any-token")
    assert store.rotate_agent_token("legacy-policy", "a" * 64)
    assert store.authenticate_agent("legacy-policy", "a-token-that-does-not-match") is False


@pytest.mark.anyio
async def test_default_database_is_lazy(tmp_path, monkeypatch):
    path = tmp_path / "configured" / "db.sqlite"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    importlib.reload(api_module)
    assert not path.exists()
    app = api_module.create_app(admin_token="test-admin-token")
    assert not path.exists()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/")).status_code == 200
        assert not path.exists()
        created = await create_policy(client, "test-admin-token")
    assert created.status_code == 201
    assert path.is_file()


def test_injected_store_does_not_create_default_database(tmp_path, monkeypatch):
    path = tmp_path / "default.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    create_app(SQLitePolicyStore(tmp_path / "injected.db"), "test-admin-token")
    assert not path.exists()


@pytest.mark.anyio
async def test_create_evm_policy_and_check_canonical_address(app, admin_token):
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created_response = await create_policy(
            client,
            admin_token,
            {
                "max_transaction": "100",
                "daily_limit": "500",
                "allowed_recipients": [address],
                "chain_id": "eip155:8453",
            },
        )
        created = created_response.json()
        response = await check(
            client,
            created["policy_id"],
            "evm-case",
            created["agent_token"],
            recipient=address.lower(),
        )

    assert created_response.status_code == 201
    assert created["chain_id"] == "eip155:8453"
    assert created["allowed_recipients"] == [address.lower()]
    assert response.status_code == 200
    assert response.json()["allowed"] is True


@pytest.mark.anyio
async def test_create_evm_policy_rejects_malformed_allowlist_address(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(
            client,
            admin_token,
            {
                "max_transaction": "100",
                "daily_limit": "500",
                "allowed_recipients": ["Alice"],
                "chain_id": "eip155:1",
            },
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_create_policy_rejects_unsupported_chain_namespace(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(
            client,
            admin_token,
            {
                "max_transaction": "100",
                "daily_limit": "500",
                "allowed_recipients": ["Alice"],
                "chain_id": "solana:mainnet",
            },
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_check_evm_policy_rejects_malformed_recipient(app, admin_token):
    address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (
            await create_policy(
                client,
                admin_token,
                {
                    "max_transaction": "100",
                    "daily_limit": "500",
                    "allowed_recipients": [address],
                    "chain_id": "eip155:1",
                },
            )
        ).json()
        response = await check(
            client,
            created["policy_id"],
            "bad-evm-address",
            created["agent_token"],
            recipient="not-an-address",
        )

    assert response.status_code == 422
