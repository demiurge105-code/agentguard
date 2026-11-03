# AgentGuard — MVP Architecture

## Goal

AgentGuard is an experimental, simulation-only policy evaluation service for proposed crypto transactions from AI agents. It does not connect to wallets, sign transactions, or submit blockchain transactions.

## Core flow

1. The policy owner creates a policy through `POST /policies` using the owner token.
2. The API stores the policy in SQLite and returns a server-generated `policy_id`.
3. An agent submits `policy_id`, `request_id`, `amount`, and `recipient` to `POST /check-transaction`.
4. The SQLite store serializes evaluation and reservation in a write transaction.
5. The API returns an `ALLOW` or `DENY` decision with a stable reason code.

## Components

### Policy Engine

The deterministic policy engine checks, in order:

1. Maximum transaction amount.
2. Daily spending limit.
3. Recipient allowlist.

It uses Python `Decimal` for monetary arithmetic and remains independent of HTTP and database code. Its pure-Python `TransactionRequest` still accepts a `daily_spent` value; the HTTP API no longer accepts that field.

### SQLite Policy Store

Implemented in `agentguard.storage.SQLitePolicyStore`.

Public methods:

- `create_policy(policy) -> policy_id`
- `get_policy(policy_id) -> Policy | None`
- `evaluate_and_reserve(policy_id, amount, recipient, request_id) -> Decision | None`

Policy limits and transaction amounts are stored as decimal strings. Recipient allowlists are stored as JSON. The `daily_reservations` table records each request's UTC date, amount, recipient, and decision.

### Atomic daily-budget accounting

The store uses SQLite `BEGIN IMMEDIATE` to serialize each check-and-reserve operation. It reads the current day's allowed reservations, sums their decimal strings with Python `Decimal`, evaluates the new request, and inserts the decision before committing.

Reservations are grouped by policy and UTC calendar day. Usage resets at 00:00 UTC. Only allowed decisions consume daily budget. Denied decisions are also persisted so their idempotency keys replay consistently.

The primary key `(policy_id, request_id)` provides idempotency:

- Same key and same amount/recipient: replay the original decision without reserving again.
- Same key with a different amount or recipient: HTTP 409 conflict.
- The same key remains bound to its original decision even across a UTC day boundary.

An allowed decision is a **budget reservation for a simulated request**, not evidence that funds were actually spent or that a blockchain transaction was broadcast. Settlement and reservation release are not implemented.

### API

The FastAPI application is created by `create_app(store=None, admin_token=None)`. Tests can inject an isolated store and token. The module exports `app` for Uvicorn.

#### POST /policies

Requires `Authorization: Bearer <AGENTGUARD_ADMIN_TOKEN>`. If the token is unset or empty, policy creation fails closed with HTTP 401.

#### POST /check-transaction

Accepts only:

- `policy_id`
- `request_id`
- `amount`
- `recipient`

Caller-supplied `daily_spent` and policy overrides are rejected. Unknown policy IDs return HTTP 404. Reusing an idempotency key with a different payload returns HTTP 409.

## Security scope and limitations

AgentGuard is not a wallet security system. It does not hold keys, sign transactions, submit transactions, or stop an agent from bypassing the API. The owner token protects policy creation only; callers of `/check-transaction` are not authenticated or bound to an agent. Reservations are not reconciled with actual blockchain settlement. Do not use the API as the sole control protecting real funds.

## Technology

- Python
- FastAPI
- SQLite
- pytest

## What we are NOT building yet

- Reservation settlement or release
- Agent identity and request authentication
- Policy update or deletion endpoints
- Token, DAO, or own blockchain
- Mainnet transactions or custody
- Autonomous financial agents
- Complex cryptography
