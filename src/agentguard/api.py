"""FastAPI interface for simulation-only AgentGuard policy checks."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from decimal import Decimal
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.chains import normalize_chain_id, normalize_recipient
from agentguard.policy import Policy
from agentguard.storage import IdempotencyConflict, SQLitePolicyStore


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_transaction: Decimal = Field(ge=0)
    daily_limit: Decimal = Field(ge=0)
    allowed_recipients: list[str]
    chain_id: str | None = None

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

    @field_validator("chain_id")
    @classmethod
    def validate_chain_id(cls, value: str | None) -> str | None:
        return normalize_chain_id(value)

    @model_validator(mode="after")
    def validate_recipients_for_chain(self) -> "PolicyInput":
        for recipient in self.allowed_recipients:
            normalize_recipient(recipient, self.chain_id)
        return self


class TransactionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1, max_length=200)
    amount: Decimal = Field(gt=0)
    recipient: str = Field(min_length=1)

    @field_validator("amount")
    @classmethod
    def validate_finite_amount(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("Transaction amount must be a finite decimal value.")
        return value

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Recipient must not be empty or whitespace.")
        return value

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("request_id must not be empty or whitespace.")
        return value


def _bearer_token(authorization: str | None) -> str | None:
    """Extract a Bearer credential without accepting malformed headers."""
    if authorization is None:
        return None
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or token.strip() != token:
        return None
    return token


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_app(
    store: SQLitePolicyStore | None = None,
    admin_token: str | None = None,
) -> FastAPI:
    policy_store = store

    def get_store() -> SQLitePolicyStore:
        nonlocal policy_store
        if policy_store is None:
            policy_store = SQLitePolicyStore(
                Path(os.getenv("AGENTGUARD_DB_PATH", "agentguard.db"))
            )
        return policy_store

    if admin_token is None:
        admin_token = os.getenv("AGENTGUARD_ADMIN_TOKEN")

    application = FastAPI(title="AgentGuard API")

    def require_admin(authorization: str | None) -> None:
        supplied_token = _bearer_token(authorization)
        if (
            not admin_token
            or supplied_token is None
            or not hmac.compare_digest(supplied_token, admin_token)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing admin token.",
            )

    @application.get("/")
    def home() -> dict[str, str]:
        return {"message": "AgentGuard API is running"}

    @application.post("/policies", status_code=status.HTTP_201_CREATED)
    def create_policy(
        data: PolicyInput,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        require_admin(authorization)
        policy = Policy(
            data.max_transaction,
            data.daily_limit,
            data.allowed_recipients,
            chain_id=data.chain_id,
        )
        agent_token = secrets.token_urlsafe(32)
        policy_id = get_store().create_policy(policy, _token_hash(agent_token))
        response: dict[str, object] = {
            "policy_id": policy_id,
            "max_transaction": str(policy.max_transaction),
            "daily_limit": str(policy.daily_limit),
            "allowed_recipients": sorted(policy.allowed_recipients),
            "agent_token": agent_token,
        }
        if policy.chain_id is not None:
            response["chain_id"] = policy.chain_id
        return response

    @application.post("/policies/{policy_id}/rotate-agent-token")
    def rotate_agent_token(
        policy_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        require_admin(authorization)
        agent_token = secrets.token_urlsafe(32)
        if not get_store().rotate_agent_token(policy_id, _token_hash(agent_token)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Policy not found.",
            )
        return {"policy_id": policy_id, "agent_token": agent_token}

    @application.post("/check-transaction")
    def check_transaction_api(
        data: TransactionInput,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        agent_token = _bearer_token(authorization)
        if agent_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing agent token.",
            )
        try:
            decision = get_store().evaluate_and_reserve_authenticated(
                data.policy_id,
                agent_token,
                data.amount,
                data.recipient,
                data.request_id,
            )
        except IdempotencyConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        if decision is None:
            # Do not reveal whether the policy ID exists or the token is invalid.
            raise HTTPException(status_code=401, detail="Invalid or missing agent token.")
        return decision.to_dict()

    return application


# Simulation only: this app never signs or submits transactions or accesses wallets.
app = create_app()
