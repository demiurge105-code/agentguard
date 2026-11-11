import asyncio
import hashlib
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
    assert "chain_id" not in body  # Keep the legacy response shape unchanged.
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


@pytest.mark.anyio
async def test_check_transaction_uses_atomic_storage_authentication(app, admin_token, monkeypatch):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()

        def separate_authentication_must_not_be_used(*args, **kwargs):
            raise AssertionError("API must not authenticate outside the reservation transaction")

        monkeypatch.setattr(
            app.state.store, "authenticate_agent", separate_authentication_must_not_be_used
        )
        response = await check(
            client, created["policy_id"], "atomic-auth", created["agent_token"]
        )

    assert response.status_code == 200
    assert response.json()["allowed"] is True



def test_bearer_authentication_is_declared_in_openapi(app):
    schema = app.openapi()

    assert schema["components"]["securitySchemes"]["HTTPBearer"] == {
        "type": "http",
        "scheme": "bearer",
    }

    for path in (
        "/policies",
        "/policies/{policy_id}/rotate-agent-token",
        "/check-transaction",
    ):
        assert {"HTTPBearer": []} in schema["paths"][path]["post"]["security"]

@pytest.mark.anyio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_transaction", 0.1),
        ("max_transaction", 1),
        ("max_transaction", True),
        ("daily_limit", 0.1),
        ("daily_limit", 1),
        ("daily_limit", True),
    ],
)
async def test_policy_creation_rejects_json_numeric_money_values(
    app, admin_token, field, value
):
    payload = {
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"],
    }
    payload[field] = value

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await create_policy(client, admin_token, payload)

    assert response.status_code == 422


@pytest.mark.anyio
@pytest.mark.parametrize("value", [0.1, 1, True])
async def test_transaction_api_rejects_json_numeric_amount_without_reserving(
    app, admin_token, value
):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()

        rejected = await check(
            client,
            created["policy_id"],
            "strict-decimal-input",
            created["agent_token"],
            amount=value,
        )
        accepted = await check(
            client,
            created["policy_id"],
            "strict-decimal-input",
            created["agent_token"],
            amount="10",
        )

    assert rejected.status_code == 422
    assert accepted.status_code == 200
    assert accepted.json()["allowed"] is True



def gateway_headers(token, idempotency_key):
    headers = {"Idempotency-Key": idempotency_key}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def submit_gateway(
    client,
    policy_id,
    idempotency_key,
    token,
    amount="10",
    recipient="Alice",
    extra=None,
):
    payload = {
        "policy_id": policy_id,
        "amount": amount,
        "recipient": recipient,
    }
    if extra:
        payload.update(extra)
    return await client.post(
        "/gateway/operations",
        json=payload,
        headers=gateway_headers(token, idempotency_key),
    )


@pytest.mark.anyio
async def test_gateway_endpoint_executes_allowed_action_once(app, admin_token, monkeypatch):
    calls = []

    class CountingExecutor:
        def __call__(self, intent, operation_id):
            calls.append((intent, operation_id))
            return None

    monkeypatch.setattr(api_module, "PrintOnlyExecutor", CountingExecutor)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await submit_gateway(
            client, created["policy_id"], "gateway-allowed", created["agent_token"]
        )

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "SUCCEEDED"
    assert body["allowed"] is True
    assert body["operation_id"]
    assert len(calls) == 1
    assert calls[0][0].policy_id == created["policy_id"]


@pytest.mark.anyio
async def test_gateway_endpoint_denial_never_calls_executor(app, admin_token, monkeypatch):
    calls = []

    class CountingExecutor:
        def __call__(self, intent, operation_id):
            calls.append(operation_id)

    monkeypatch.setattr(api_module, "PrintOnlyExecutor", CountingExecutor)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (
            await create_policy(
                client,
                admin_token,
                {
                    "max_transaction": "5",
                    "daily_limit": "100",
                    "allowed_recipients": ["Alice"],
                },
            )
        ).json()
        response = await submit_gateway(
            client,
            created["policy_id"],
            "gateway-denied",
            created["agent_token"],
            amount="10",
        )

    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"
    assert response.json()["allowed"] is False
    assert calls == []


@pytest.mark.anyio
async def test_gateway_endpoint_retry_is_idempotent_and_conflict_returns_409(
    app, admin_token, monkeypatch
):
    calls = []

    class CountingExecutor:
        def __call__(self, intent, operation_id):
            calls.append(operation_id)

    monkeypatch.setattr(api_module, "PrintOnlyExecutor", CountingExecutor)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        first = await submit_gateway(
            client, created["policy_id"], "gateway-retry", created["agent_token"]
        )
        retry = await submit_gateway(
            client, created["policy_id"], "gateway-retry", created["agent_token"]
        )
        conflict = await submit_gateway(
            client,
            created["policy_id"],
            "gateway-retry",
            created["agent_token"],
            amount="11",
        )

    assert first.status_code == retry.status_code == 200
    assert first.json() == retry.json()
    assert conflict.status_code == 409
    assert len(calls) == 1


@pytest.mark.anyio
async def test_gateway_endpoint_rejects_missing_invalid_and_cross_policy_tokens(
    app, admin_token
):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = (await create_policy(client, admin_token)).json()
        second = (await create_policy(client, admin_token)).json()
        missing = await submit_gateway(
            client, first["policy_id"], "missing-token", None
        )
        invalid = await submit_gateway(
            client, first["policy_id"], "invalid-token", "wrong-token"
        )
        cross_policy = await submit_gateway(
            client, second["policy_id"], "cross-policy", first["agent_token"]
        )
        unknown = await submit_gateway(
            client, "unknown-policy", "unknown-policy", "wrong-token"
        )

    assert [missing.status_code, invalid.status_code, cross_policy.status_code, unknown.status_code] == [
        401, 401, 401, 401
    ]
    assert missing.json() == invalid.json() == cross_policy.json() == unknown.json()


@pytest.mark.anyio
@pytest.mark.parametrize("amount", [0.1, 1, True, "NaN", "Infinity", "-1", "not-a-number"])
async def test_gateway_endpoint_rejects_invalid_money_without_reserving(
    app, admin_token, amount
):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await submit_gateway(
            client,
            created["policy_id"],
            "invalid-gateway-amount",
            created["agent_token"],
            amount=amount,
        )

    assert response.status_code == 422
    connection = app.state.store._connect()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM gateway_operations"
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == 0


@pytest.mark.anyio
async def test_gateway_endpoint_authenticates_before_money_validation(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await submit_gateway(
            client,
            created["policy_id"],
            "invalid-token-numeric-amount",
            "wrong-token",
            amount=1,
        )

    assert response.status_code == 401


@pytest.mark.anyio
async def test_gateway_endpoint_requires_idempotency_key(app, admin_token):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await client.post(
            "/gateway/operations",
            json={
                "policy_id": created["policy_id"],
                "amount": "10",
                "recipient": "Alice",
            },
            headers={"Authorization": f"Bearer {created['agent_token']}"},
        )

    assert response.status_code == 422


@pytest.mark.anyio
@pytest.mark.parametrize(
    "extra",
    [
        {"chain_id": "eip155:1"},
        {"daily_spent": "0"},
        {"daily_limit": "1000"},
        {"max_transaction": "1000"},
        {"executor": "arbitrary"},
    ],
)
async def test_gateway_endpoint_rejects_caller_overrides(app, admin_token, extra):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        response = await submit_gateway(
            client,
            created["policy_id"],
            "forbidden-field-" + next(iter(extra)),
            created["agent_token"],
            extra=extra,
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_gateway_endpoint_uses_stored_evm_chain_context(app, admin_token):
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
        valid = await submit_gateway(
            client,
            created["policy_id"],
            "evm-valid",
            created["agent_token"],
            recipient=address.lower(),
        )
        invalid = await submit_gateway(
            client,
            created["policy_id"],
            "evm-invalid",
            created["agent_token"],
            recipient="not-an-address",
        )

    assert valid.status_code == 200
    assert valid.json()["status"] == "SUCCEEDED"
    assert invalid.status_code == 422


@pytest.mark.anyio
async def test_gateway_endpoint_revalidates_token_at_execution_claim(
    app, admin_token, monkeypatch
):
    calls = []
    new_token = "rotated-before-claim"

    class CountingExecutor:
        def __call__(self, intent, operation_id):
            calls.append(operation_id)

    monkeypatch.setattr(api_module, "PrintOnlyExecutor", CountingExecutor)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        store = app.state.store
        original_claim = store.claim_gateway_operation

        def rotate_then_claim(operation_id, token):
            store.rotate_agent_token(
                created["policy_id"],
                hashlib.sha256(new_token.encode("utf-8")).hexdigest(),
            )
            return original_claim(operation_id, token)

        monkeypatch.setattr(store, "claim_gateway_operation", rotate_then_claim)
        response = await submit_gateway(
            client,
            created["policy_id"],
            "rotate-during-gateway",
            created["agent_token"],
        )

    assert response.status_code == 401
    assert calls == []


@pytest.mark.anyio
async def test_gateway_endpoint_concurrent_retries_execute_once(app, admin_token, monkeypatch):
    from threading import Lock
    import time

    calls = []
    lock = Lock()

    class SlowExecutor:
        def __call__(self, intent, operation_id):
            with lock:
                calls.append(operation_id)
            time.sleep(0.05)

    monkeypatch.setattr(api_module, "PrintOnlyExecutor", SlowExecutor)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await create_policy(client, admin_token)).json()
        responses = await asyncio.gather(
            *[
                submit_gateway(
                    client,
                    created["policy_id"],
                    "gateway-concurrent",
                    created["agent_token"],
                )
                for _ in range(8)
            ]
        )

    assert all(response.status_code == 200 for response in responses)
    assert len(calls) == 1
    assert len({response.json()["operation_id"] for response in responses}) == 1
    assert app.state.store.get_gateway_operation(
        created["policy_id"], "gateway-concurrent"
    )["status"] == "SUCCEEDED"
