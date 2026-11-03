import importlib

import pytest
from httpx import ASGITransport, AsyncClient

import agentguard.api as api_module
from agentguard.api import create_app
from agentguard.storage import SQLitePolicyStore


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def admin_token() -> str:
    return "test-admin-token"


@pytest.fixture
def app(tmp_path, admin_token):
    store = SQLitePolicyStore(tmp_path / "policies.db")
    return create_app(store=store, admin_token=admin_token)


async def create_policy(client, token, payload=None):
    if payload is None:
        payload = {
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return await client.post("/policies", json=payload, headers=headers)


@pytest.mark.anyio
async def test_owner_can_create_policy(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, admin_token)

    assert response.status_code == 201
    body = response.json()
    assert body["policy_id"]
    assert body["max_transaction"] == "100"
    assert body["daily_limit"] == "500"
    assert body["allowed_recipients"] == ["alice", "bob"]


@pytest.mark.anyio
async def test_policy_creation_rejects_missing_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, None)

    assert response.status_code == 401


@pytest.mark.anyio
async def test_policy_creation_rejects_wrong_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, "wrong-token")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_unset_admin_token_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_ADMIN_TOKEN", raising=False)
    app = create_app(store=SQLitePolicyStore(tmp_path / "policies.db"))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, "any-token")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_check_transaction_uses_stored_policy(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await create_policy(client, admin_token)
        policy_id = created.json()["policy_id"]
        response = await client.post(
            "/check-transaction",
            json={"policy_id": policy_id, "amount": "80", "recipient": "Alice", "daily_spent": "200"},
        )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


@pytest.mark.anyio
async def test_check_transaction_cannot_override_stored_policy(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await create_policy(client, admin_token)
        response = await client.post(
            "/check-transaction",
            json={
                "policy_id": created.json()["policy_id"],
                "amount": "150",
                "recipient": "Alice",
                "daily_spent": "0",
                "max_transaction": "1000",
                "daily_limit": "1000",
                "allowed_recipients": ["Alice"],
            },
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_check_transaction_returns_404_for_unknown_policy(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/check-transaction",
            json={"policy_id": "missing-policy", "amount": "10", "recipient": "Alice", "daily_spent": "0"},
        )

    assert response.status_code == 404


@pytest.mark.anyio
async def test_check_transaction_rejects_negative_amount(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await create_policy(client, "test-admin-token")
        response = await client.post(
            "/check-transaction",
            json={"policy_id": created.json()["policy_id"], "amount": "-1", "recipient": "Alice", "daily_spent": "0"},
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_check_transaction_rejects_empty_recipient(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await create_policy(client, "test-admin-token")
        response = await client.post(
            "/check-transaction",
            json={"policy_id": created.json()["policy_id"], "amount": "10", "recipient": "   ", "daily_spent": "0"},
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_default_database_is_created_only_when_storage_is_used(tmp_path, monkeypatch):
    db_path = tmp_path / "configured" / "agentguard.db"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(db_path))

    # Reloading the module simulates importing it in a fresh process.
    importlib.reload(api_module)
    assert not db_path.exists()

    app = api_module.create_app(admin_token="test-admin-token")
    assert not db_path.exists()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        home = await client.get("/")
        assert home.status_code == 200
        assert not db_path.exists()

        created = await create_policy(client, "test-admin-token")

    assert created.status_code == 201
    assert db_path.is_file()


def test_injected_store_does_not_create_default_database(tmp_path, monkeypatch):
    db_path = tmp_path / "default.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(db_path))

    injected_store = SQLitePolicyStore(tmp_path / "injected.db")
    create_app(store=injected_store, admin_token="test-admin-token")

    assert not db_path.exists()
