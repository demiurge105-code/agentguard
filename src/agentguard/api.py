from decimal import Decimal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator
from agentguard.policy import Policy, TransactionRequest, check_transaction

app = FastAPI(title="AgentGuard API")


@app.get("/")
def home():
    return {"message": "AgentGuard API is running"}


class TransactionInput(BaseModel):
    amount: Decimal = Field(gt=0)
    recipient: str = Field(min_length=1)
    daily_spent: Decimal = Field(ge=0)
    max_transaction: Decimal = Field(ge=0)
    daily_limit: Decimal = Field(ge=0)
    allowed_recipients: list[str]

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Recipient must not be empty or whitespace.")
        return value


    @field_validator("allowed_recipients")
    @classmethod
    def validate_allowed_recipients(cls, values: list[str]) -> list[str]:
        for recipient in values:
            if not recipient.strip():
                raise ValueError(
                    "Allowed recipients must not contain empty or whitespace-only values."
                )
        return values



@app.post("/check-transaction")
def check_transaction_api(data: TransactionInput):

    policy = Policy(
        max_transaction=data.max_transaction,
        daily_limit=data.daily_limit,
        allowed_recipients=data.allowed_recipients
    )

    request = TransactionRequest(
        amount=data.amount,
        recipient=data.recipient,
        daily_spent=data.daily_spent
    )

    decision = check_transaction(request, policy)

    return decision.to_dict()