import importlib
import pytest
from httpx import ASGITransport, AsyncClient
import agentguard.api as api_module
from agentguard.api import create_app
from agentguard.storage import SQLitePolicyStore

@pytest.fixture
def anyio_backend(): return "asyncio"
@pytest.fixture
def admin_token(): return "test-admin-token"
@pytest.fixture
def app(tmp_path,admin_token): return create_app(SQLitePolicyStore(tmp_path/"p.db"),admin_token)
async def create_policy(client,token,payload=None):
    payload=payload or {"max_transaction":"100","daily_limit":"500","allowed_recipients":["Alice","Bob"]}
    return await client.post("/policies",json=payload,headers={"Authorization":f"Bearer {token}"} if token else {})
def tx(pid,key,amount="10",recipient="Alice"):
    return {"policy_id":pid,"request_id":key,"amount":amount,"recipient":recipient}

@pytest.mark.anyio
async def test_owner_can_create_policy(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c: r=await create_policy(c,admin_token)
    assert r.status_code==201 and r.json()["daily_limit"]=="500" and r.json()["allowed_recipients"]==["alice","bob"]
@pytest.mark.anyio
async def test_policy_creation_rejects_missing_token(app):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c: r=await create_policy(c,None)
    assert r.status_code==401
@pytest.mark.anyio
async def test_policy_creation_rejects_wrong_token(app):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c: r=await create_policy(c,"wrong")
    assert r.status_code==401
@pytest.mark.anyio
async def test_unset_admin_token_fails_closed(tmp_path,monkeypatch):
    monkeypatch.delenv("AGENTGUARD_ADMIN_TOKEN",raising=False); app=create_app(SQLitePolicyStore(tmp_path/"p.db"))
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c: r=await create_policy(c,"any")
    assert r.status_code==401
@pytest.mark.anyio
async def test_check_uses_server_side_daily_accounting(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token,{"max_transaction":"1000","daily_limit":"500","allowed_recipients":["Alice","Bob"]})).json()["policy_id"]
        first=await c.post("/check-transaction",json=tx(pid,"one","300"))
        second=await c.post("/check-transaction",json=tx(pid,"two","250"))
    assert first.json()["allowed"] is True and second.json()["reason_code"]=="daily_limit_exceeded"
@pytest.mark.anyio
async def test_caller_cannot_supply_daily_spent(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token)).json()["policy_id"]; payload=tx(pid,"one"); payload["daily_spent"]="0"
        r=await c.post("/check-transaction",json=payload)
    assert r.status_code==422
@pytest.mark.anyio
async def test_policy_overrides_are_rejected(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token)).json()["policy_id"]; payload=tx(pid,"one","150"); payload["daily_limit"]="1000"
        r=await c.post("/check-transaction",json=payload)
    assert r.status_code==422
@pytest.mark.anyio
async def test_unknown_policy_returns_404(app):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c: r=await c.post("/check-transaction",json=tx("missing","one"))
    assert r.status_code==404
@pytest.mark.anyio
async def test_api_retry_is_idempotent(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token,{"max_transaction":"1000","daily_limit":"500","allowed_recipients":["Alice","Bob"]})).json()["policy_id"]; payload=tx(pid,"retry","300")
        first=await c.post("/check-transaction",json=payload); retry=await c.post("/check-transaction",json=payload)
        next_req=await c.post("/check-transaction",json=tx(pid,"next","250"))
    assert first.json()==retry.json() and next_req.json()["reason_code"]=="daily_limit_exceeded"
@pytest.mark.anyio
async def test_reused_request_id_with_different_payload_returns_409(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token)).json()["policy_id"]; await c.post("/check-transaction",json=tx(pid,"same"))
        r=await c.post("/check-transaction",json=tx(pid,"same","11"))
    assert r.status_code==409
@pytest.mark.anyio
async def test_negative_amount_rejected(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token)).json()["policy_id"]; r=await c.post("/check-transaction",json=tx(pid,"negative","-1"))
    assert r.status_code==422
@pytest.mark.anyio
async def test_empty_recipient_rejected(app,admin_token):
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        pid=(await create_policy(c,admin_token)).json()["policy_id"]; r=await c.post("/check-transaction",json=tx(pid,"empty",recipient="   "))
    assert r.status_code==422
@pytest.mark.anyio
async def test_default_database_is_lazy(tmp_path,monkeypatch):
    path=tmp_path/"configured"/"db.sqlite"; monkeypatch.chdir(tmp_path); monkeypatch.setenv("AGENTGUARD_DB_PATH",str(path))
    importlib.reload(api_module); assert not path.exists(); app=api_module.create_app(admin_token="test-admin-token"); assert not path.exists()
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as c:
        assert (await c.get("/")).status_code==200 and not path.exists()
        created=await create_policy(c,"test-admin-token")
    assert created.status_code==201 and path.is_file()
def test_injected_store_does_not_create_default_database(tmp_path,monkeypatch):
    path=tmp_path/"default.db"; monkeypatch.setenv("AGENTGUARD_DB_PATH",str(path))
    create_app(SQLitePolicyStore(tmp_path/"injected.db"),"test-admin-token"); assert not path.exists()
