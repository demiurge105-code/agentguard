"""FastAPI interface for simulation-only AgentGuard policy checks."""
from __future__ import annotations
import hmac, os
from decimal import Decimal
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from agentguard.policy import Policy
from agentguard.storage import IdempotencyConflict, SQLitePolicyStore

class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_transaction: Decimal = Field(ge=0)
    daily_limit: Decimal = Field(ge=0)
    allowed_recipients: list[str]
    @field_validator("max_transaction", "daily_limit")
    @classmethod
    def validate_finite_amounts(cls, value: Decimal) -> Decimal:
        if not value.is_finite(): raise ValueError("Policy amounts must be finite decimal values.")
        return value
    @field_validator("allowed_recipients")
    @classmethod
    def validate_allowed_recipients(cls, values: list[str]) -> list[str]:
        if any(not recipient.strip() for recipient in values): raise ValueError("Allowed recipients must not contain empty values.")
        return values

class TransactionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1, max_length=200)
    amount: Decimal = Field(gt=0)
    recipient: str = Field(min_length=1)
    @field_validator("amount")
    @classmethod
    def validate_finite_amount(cls, value: Decimal) -> Decimal:
        if not value.is_finite(): raise ValueError("Transaction amount must be a finite decimal value.")
        return value
    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        if not value.strip(): raise ValueError("Recipient must not be empty or whitespace.")
        return value
    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value.strip(): raise ValueError("request_id must not be empty or whitespace.")
        return value

def create_app(store: SQLitePolicyStore | None = None, admin_token: str | None = None) -> FastAPI:
    policy_store = store
    def get_store() -> SQLitePolicyStore:
        nonlocal policy_store
        if policy_store is None:
            policy_store = SQLitePolicyStore(Path(os.getenv("AGENTGUARD_DB_PATH", "agentguard.db")))
        return policy_store
    if admin_token is None: admin_token = os.getenv("AGENTGUARD_ADMIN_TOKEN")
    application = FastAPI(title="AgentGuard API")
    @application.get("/")
    def home() -> dict[str, str]:
        return {"message": "AgentGuard API is running"}
    @application.post("/policies", status_code=status.HTTP_201_CREATED)
    def create_policy(data: PolicyInput, authorization: str | None = Header(default=None)) -> dict[str, object]:
        if not admin_token:
            raise HTTPException(status_code=401, detail="Policy creation is disabled because no admin token is configured.")
        if authorization is None or not hmac.compare_digest(authorization, f"Bearer {admin_token}"):
            raise HTTPException(status_code=401, detail="Invalid or missing admin token.")
        policy = Policy(data.max_transaction, data.daily_limit, data.allowed_recipients)
        policy_id = get_store().create_policy(policy)
        return {"policy_id": policy_id, "max_transaction": str(policy.max_transaction),
                "daily_limit": str(policy.daily_limit), "allowed_recipients": sorted(policy.allowed_recipients)}
    @application.post("/check-transaction")
    def check_transaction_api(data: TransactionInput) -> dict[str, object]:
        try:
            decision = get_store().evaluate_and_reserve(data.policy_id, data.amount, data.recipient, data.request_id)
        except IdempotencyConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        if decision is None: raise HTTPException(status_code=404, detail="Policy not found.")
        return decision.to_dict()
    return application

# Simulation only: this app never signs or submits transactions or accesses wallets.
app = create_app()
