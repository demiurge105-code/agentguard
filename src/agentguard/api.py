"""FastAPI interface for simulation-only AgentGuard policy checks."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from decimal import Decimal
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.chains import normalize_chain_id, normalize_recipient
from agentguard.gateway import GatewayAuthenticationError, PrintOnlyExecutor, TrustedExecutionGateway
from agentguard.intent import ActionIntent
from agentguard.policy import Policy
from agentguard.storage import IdempotencyConflict, SQLitePolicyStore


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_transaction: Decimal = Field(ge=0)
    daily_limit: Decimal = Field(ge=0)
    allowed_recipients: list[str]
    chain_id: str | None = None

    @field_validator("max_transaction", "daily_limit", mode="before")
    @classmethod
    def require_decimal_string(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("Policy amounts must be provided as decimal strings.")
        return value

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

    @field_validator("amount", mode="before")
    @classmethod
    def require_decimal_string(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("Transaction amount must be provided as a decimal string.")
        return value

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


class GatewayOperationInput(BaseModel):
    """Keep raw field types until after agent authentication."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1)
    amount: object = Field(json_schema_extra={"type": "string"})
    recipient: object = Field(json_schema_extra={"type": "string"})


class GatewayReconciliationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Reconciliation reason must not be empty or whitespace.")
        return value.strip()


bearer_scheme = HTTPBearer(auto_error=False)


def _bearer_token(
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    """Extract a Bearer credential without accepting malformed values."""
    if credentials is None:
        return None

    token = credentials.credentials
    if not token or token.strip() != token:
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

    def require_admin(
        credentials: HTTPAuthorizationCredentials | None,
    ) -> None:
        supplied_token = _bearer_token(credentials)
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
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, object]:
        require_admin(credentials)
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
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, str]:
        require_admin(credentials)
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
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, object]:
        agent_token = _bearer_token(credentials)
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

    @application.post("/gateway/operations")
    def submit_gateway_operation(
        data: GatewayOperationInput,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, object]:
        agent_token = _bearer_token(credentials)
        if agent_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing agent token.",
            )

        try:
            # This authenticated lookup supplies the policy's immutable chain
            # context. The gateway reauthenticates during reservation and claim,
            # so token rotation between these steps still fails closed.
            policy = get_store().get_policy_authenticated(data.policy_id, agent_token)
            if policy is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing agent token.",
                )
            if idempotency_key is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="The Idempotency-Key header is required.",
                )
            if not isinstance(data.amount, str):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Transaction amount must be provided as a decimal string.",
                )
            if not isinstance(data.recipient, str):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Recipient must be provided as a string.",
                )

            intent = ActionIntent(
                data.policy_id,
                data.amount,
                data.recipient,
                chain_id=policy.chain_id,
            )
            result = TrustedExecutionGateway(
                get_store(),
                PrintOnlyExecutor(),
            ).submit(intent, agent_token, idempotency_key)
        except GatewayAuthenticationError as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing agent token.",
            ) from error
        except IdempotencyConflict as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
        except sqlite3.Error as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Gateway storage is temporarily unavailable.",
            ) from error

        return {
            "operation_id": result.operation_id,
            "policy_id": result.policy_id,
            "status": result.status.value,
            "allowed": result.allowed,
            "reason_code": result.reason_code,
            "reason": result.reason,
            "result": result.result,
            "created_at": result.created_at,
            "updated_at": result.updated_at,
        }

    @application.get("/gateway/operations/{operation_id}")
    def get_gateway_operation(
        operation_id: str,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, object]:
        require_admin(credentials)
        try:
            operation = get_store().get_gateway_operation_by_id(operation_id)
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="Gateway storage is temporarily unavailable.") from error
        if operation is None:
            raise HTTPException(status_code=404, detail="Gateway operation not found.")
        return {
            key: operation[key]
            for key in (
                "operation_id", "policy_id", "status", "allowed",
                "reason_code", "reason", "result", "created_at", "updated_at",
            )
        }

    @application.get("/gateway/operations/{operation_id}/events")
    def get_gateway_operation_events(
        operation_id: str,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, object]:
        require_admin(credentials)
        try:
            events = get_store().list_gateway_operation_events(operation_id)
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="Gateway storage is temporarily unavailable.") from error
        if events is None:
            raise HTTPException(status_code=404, detail="Gateway operation not found.")
        return {"operation_id": operation_id, "events": events}

    @application.post("/gateway/operations/{operation_id}/reconcile")
    def reconcile_gateway_operation(
        operation_id: str,
        data: GatewayReconciliationInput,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> dict[str, object]:
        require_admin(credentials)
        try:
            changed = get_store().reconcile_gateway_operation_unknown(
                operation_id, "owner", data.reason
            )
            operation = get_store().get_gateway_operation_by_id(operation_id)
        except sqlite3.Error as error:
            raise HTTPException(status_code=503, detail="Gateway storage is temporarily unavailable.") from error
        if operation is None:
            raise HTTPException(status_code=404, detail="Gateway operation not found.")
        if not changed:
            raise HTTPException(
                status_code=409,
                detail="Only an EXECUTING operation can be reconciled to UNKNOWN.",
            )
        return {
            "operation_id": operation_id,
            "status": operation["status"],
            "reconciled": True,
            "note": "UNKNOWN does not authorize another execution attempt.",
        }

    return application


# Simulation only: this app never signs or submits transactions or accesses wallets.
app = create_app()
