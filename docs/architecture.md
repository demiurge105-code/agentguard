# AgentGuard — MVP Architecture

## Goal

AgentGuard is an open-source permission layer for AI agents interacting with crypto wallets.

The first MVP does not execute real transactions.

It evaluates whether a proposed transaction is allowed according to a user-defined policy.

## Core flow

AI Agent
    |
    v
AgentGuard API
    |
    v
Policy Engine
    |
    +---- Transaction limit
    |
    +---- Daily spending limit
    |
    +---- Allowed addresses
    |
    v
ALLOW / DENY
    |
    v
Decision Log

## Example

Policy:

- Maximum transaction: $50
- Daily spending limit: $200
- Allowed addresses:
  - 0xABC...
  - 0xDEF...

Request:

Send $35 to 0xABC...

Result:

ALLOW

Request:

Send $100 to 0xABC...

Result:

DENY

Reason:

Transaction exceeds the maximum transaction limit.

## MVP components

### Policy Engine

Responsible for evaluating transaction requests against a policy.

Input:

- transaction amount
- recipient address
- current daily spending
- policy

Output:

- allowed: true/false
- reason_code
- reason

### MVP contract

The first policy engine uses the following Python types:

```python
Policy(max_transaction, daily_limit, allowed_recipients)
TransactionRequest(amount, recipient, daily_spent)
check_transaction(request, policy) -> Decision
```

- Amounts and limits are `Decimal` values (or decimal strings), never floats.
- `daily_spent` is the amount already approved during the current day; it is supplied by the caller in the simulator.
- Recipient identifiers are non-empty strings and are compared case-insensitively. Address checksum validation is out of scope for this MVP.
- A `Decision` contains `allowed`, `reason_code`, and a human-readable `reason`.
- Rules are checked in this fixed order: maximum transaction amount, daily spending limit, recipient allowlist. The first failed rule supplies the deterministic denial reason.

### API

The FastAPI wrapper exposes the policy engine to external agents without
duplicating policy rules. It is a local simulation interface, not a wallet or
transaction service.

Endpoint:

POST /check-transaction

The request supplies `amount`, `recipient`, `daily_spent`, `max_transaction`,
`daily_limit`, and `allowed_recipients`. A successful response contains
`allowed`, `reason_code`, and `reason`. Invalid request input receives the
framework's validation response. Run it locally with:

```bash
uvicorn agentguard.api:app --reload
```

### Decision Log

Every evaluation should produce a record containing:

- timestamp
- requested amount
- recipient
- decision
- reason

The MVP can use SQLite.

### Demo Agent

A small Python program will simulate an AI agent making transaction requests.

It will demonstrate both allowed and denied actions.

## Security scope

The MVP is a policy evaluation system.

It is NOT yet a wallet security system.

An API cannot prevent a transaction if an agent or user bypasses the API and signs a transaction directly.

Future versions may enforce policies at the wallet or smart-contract layer.

## Technology

Initial stack:

- Python
- FastAPI
- SQLite
- pytest

Frontend and blockchain integration will be added after the policy engine works.

## MVP success criteria

The MVP is successful when:

1. A policy can be created.
2. A transaction can be evaluated.
3. Transactions exceeding the per-transaction limit are denied.
4. Transactions exceeding the daily limit are denied.
5. Transactions sent to non-whitelisted addresses are denied.
6. Valid transactions are allowed.
7. Automated tests cover the policy engine.
8. A demo agent can show the complete flow.

## Repository layout

```text
src/agentguard/     Policy engine package
tests/              Unit tests
examples/           Runnable simulation examples
docs/               Architecture and project documentation
```

## What we are NOT building yet

- Token
- DAO
- Own blockchain
- Mainnet transactions
- Custody
- Trading
- Autonomous financial agents
- Complex cryptography
