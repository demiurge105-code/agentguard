import pytest
from httpx import ASGITransport, AsyncClient

from agentguard.api import app


@pytest.fixture
def anyio_backend() -> str:
    """Run API tests with asyncio only; Trio is not a project dependency."""
    return "asyncio"


async def post_transaction(payload: dict[str, object]):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        return await client.post("/check-transaction", json=payload)


@pytest.mark.anyio
async def test_check_transaction_allowed() -> None:
    response = await post_transaction(
        {
            "amount": "80",
            "recipient": "Alice",
            "daily_spent": "200",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    )

    assert response.status_code == 200
    assert response.json() == {
        "allowed": True,
        "reason_code": "allowed",
        "reason": "Transaction is allowed by the policy.",
    }


@pytest.mark.anyio
async def test_check_transaction_denied() -> None:
    response = await post_transaction(
        {
            "amount": "150",
            "recipient": "Alice",
            "daily_spent": "200",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    )

    assert response.status_code == 200
    assert response.json()["reason_code"] == "amount_exceeds_maximum"


@pytest.mark.anyio
async def test_check_transaction_uses_the_existing_daily_limit_rule() -> None:
    response = await post_transaction(
        {
            "amount": "80",
            "recipient": "Alice",
            "daily_spent": "450",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    )

    assert response.status_code == 200
    assert response.json()["reason_code"] == "daily_limit_exceeded"


@pytest.mark.anyio
async def test_check_transaction_rejects_a_negative_amount() -> None:
    response = await post_transaction(
        {
            "amount": "-50",
            "recipient": "Alice",
            "daily_spent": "200",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_check_transaction_rejects_an_empty_recipient() -> None:
    response = await post_transaction(
        {
            "amount": "80",
            "recipient": "   ",
            "daily_spent": "200",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "Bob"],
        }
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_check_transaction_rejects_invalid_allowed_recipients() -> None:
    response = await post_transaction(
        {
            "amount": "80",
            "recipient": "Alice",
            "daily_spent": "200",
            "max_transaction": "100",
            "daily_limit": "500",
            "allowed_recipients": ["Alice", "   "],
        }
    )

    assert response.status_code == 422
