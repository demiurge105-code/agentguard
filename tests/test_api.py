from fastapi.testclient import TestClient
from agentguard.api import app

client = TestClient(app)


def test_check_transaction_allowed():
    payload = {
        "amount": "80",
        "recipient": "Alice",
        "daily_spent": "200",
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"]
    }

    response = client.post("/check-transaction", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert data["allowed"] is True
    assert data["reason_code"] == "allowed"
    assert data["reason"] == "Transaction is allowed by the policy."

def test_check_transaction_denied():
    payload = {
        "amount": "150",
        "recipient": "Alice",
        "daily_spent": "200",
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"]
    }

    response = client.post("/check-transaction", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert data["allowed"] is False
    assert data["reason_code"] == "amount_exceeds_maximum"
    assert data["reason"] == "Transaction exceeds the maximum transaction limit."

def test_check_transaction_negative_amount():
    payload = {
        "amount": "-50",
        "recipient": "Alice",
        "daily_spent": "200",
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"]
    }

    response = client.post("/check-transaction", json=payload)

    assert response.status_code == 422

def test_check_transaction_empty_recipient():
    payload = {
        "amount": "80",
        "recipient": "   ",
        "daily_spent": "200",
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "Bob"]
    }

    response = client.post("/check-transaction", json=payload)

    assert response.status_code == 422

def test_check_transaction_invalid_allowed_recipients():
    payload = {
        "amount": "80",
        "recipient": "Alice",
        "daily_spent": "200",
        "max_transaction": "100",
        "daily_limit": "500",
        "allowed_recipients": ["Alice", "   "]
    }

    response = client.post("/check-transaction", json=payload)

    assert response.status_code == 422