"""FastAPI interface for simulation-only AgentGuard policy checks."""

from __future__ import annotations

import hmac
import os
from decimal import Decimal
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.policy import Policy, TransactionRequest, check_transaction
from agentguard.storage import SQLitePolicyStore


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_transaction: Decimal = Field(ge=0)
    daily_limit: Decimal = Field(ge=0)
    allowed_recipients: list[str]

    @field_validator("max_transaction", "daily_limit")
    @classmethod
    def validate_finite_amounts(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("Policy amounts must be finite decimal values.")
        return value

    @field_validator("allowed_recipients")
    @classmethod
    def validate_allowed_recipients(cls, values: list[str]) -> list[str]:
        if any(not recipient.strip() for recipient in values):
            raise ValueError("Allowed recipients must not contain empty values.")
        return values


class TransactionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1)
    amount: Decimal = Field(gt=0)
    recipient: str = Field(min_length=1)
    daily_spent: Decimal = Field(ge=0)

    @field_validator("amount", "daily_spent")
    @classmethod
    def validate_finite_amounts(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("Transaction amounts must be finite decimal values.")
        return value

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Recipient must not be empty or whitespace.")
        return value


def create_app(
    store: SQLitePolicyStore | None = None,
    admin_token: str | None = None,
) -> FastAPI:
    """Create an app with injectable storage and owner token for testing."""
    policy_store = store

    def get_store() -> SQLitePolicyStore:
        """Create the default database only when an endpoint needs storage."""
        nonlocal policy_store
        if policy_store is None:
            db_path = os.getenv("AGENTGUARD_DB_PATH", "agentguard.db")
            policy_store = SQLitePolicyStore(Path(db_path))
        return policy_store

    if admin_token is None:
        admin_token = os.getenv("AGENTGUARD_ADMIN_TOKEN")

    application = FastAPI(title="AgentGuard API")

    @application.get("/")
    def home() -> dict[str, str]:
        return {"message": "AgentGuard API is running"}

    @application.post("/policies", status_code=status.HTTP_201_CREATED)
    def create_policy(
        data: PolicyInput,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        if not admin_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Policy creation is disabled because no admin token is configured.",
            )

        expected = f"Bearer {admin_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing admin token.",
            )

        policy = Policy(
            max_transaction=data.max_transaction,
            daily_limit=data.daily_limit,
            allowed_recipients=data.allowed_recipients,
        )
        policy_id = get_store().create_policy(policy)

        return {
            "policy_id": policy_id,
            "max_transaction": str(policy.max_transaction),
            "daily_limit": str(policy.daily_limit),
            "allowed_recipients": sorted(policy.allowed_recipients),
        }

    @application.post("/check-transaction")
    def check_transaction_api(data: TransactionInput) -> dict[str, object]:
        """Evaluate a simulated request against an owner-created policy."""
        policy = get_store().get_policy(data.policy_id)
        if policy is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Policy not found.",
            )

        request = TransactionRequest(
            amount=data.amount,
            recipient=data.recipient,
            daily_spent=data.daily_spent,
        )
        decision = check_transaction(request, policy)
        return decision.to_dict()

    return application


# This app evaluates simulated requests only. It never signs or submits a
# transaction, and it does not access wallets or private keys.
app = create_app()
