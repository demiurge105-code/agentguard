# AgentGuard — MVP Architecture

## Goal

AgentGuard is an experimental, simulation-only policy evaluation service for proposed crypto transactions from AI agents. It does not connect to wallets, sign transactions, or submit blockchain transactions.

## Core flow

1. The policy owner creates a policy through `POST /policies` using the owner token.
2. The API generates a cryptographically random agent token, stores only its SHA-256 hash with the policy, and returns the raw token once.
3. The agent submits the policy ID, request ID, amount, recipient, and its token in the `Authorization: Bearer` header to `POST /check-transaction`.
4. The API hashes the supplied token and compares it with the hash stored for that policy. Missing, invalid, and cross-policy tokens receive the same HTTP 401 response.
5. The SQLite store serializes evaluation and reservation in a write transaction.
6. The API returns an `ALLOW` or `DENY` decision with a stable reason code.

The deterministic demo uses a frozen `TransactionIntent` value object for each proposal. Its `Decimal` amount and recipient are serialized into the API check request, and the same object is passed to the simulated executor only after an explicit boolean `allowed: true`. This keeps the checked values and simulated values aligned within the cooperative demo process. It does not create a server-verifiable approval token, isolate the executor, or prevent an agent with another execution path from bypassing AgentGuard.

## Components

### Policy Engine

The deterministic policy engine checks, in order:

1. Maximum transaction amount.
2. Daily spending limit.
3. Recipient allowlist.

It uses Python `Decimal` for monetary arithmetic and remains independent of HTTP and database code. Its pure-Python `TransactionRequest` still accepts a `daily_spent` value; the HTTP API no longer accepts that field.

### Chain identifiers and address handling

The initial chain-aware implementation is EVM-first. A policy may optionally carry a CAIP-2 chain identifier in the `eip155` namespace, such as `eip155:1` or `eip155:8453`. The chain identifier is bound to the policy; transaction requests cannot override it.

When a policy has an EVM chain identifier, allowed and proposed recipients must have the 20-byte hexadecimal address shape (`0x` plus 40 hexadecimal characters). They are canonicalized to lowercase for allowlist and idempotency comparisons. EIP-55 checksum verification and live chain verification are not implemented. Unsupported namespaces, including Solana, are rejected rather than silently treated as EVM.

A policy without `chain_id` remains in legacy mode and keeps the original case-insensitive arbitrary-identifier behavior. This is a compatibility path, not the recommended mode for new chain-aware integrations.

### SQLite Policy Store

Implemented in `agentguard.storage.SQLitePolicyStore`.

Public methods:

- `create_policy(policy, agent_token_hash=None) -> policy_id`
- `authenticate_agent(policy_id, token) -> bool`
- `rotate_agent_token(policy_id, token_hash) -> bool`
- `get_policy(policy_id) -> Policy | None`
- `evaluate_and_reserve(policy_id, amount, recipient, request_id) -> Decision | None`

Policy limits and transaction amounts are stored as decimal strings. Recipient allowlists are stored as JSON. The nullable `policies.chain_id` column binds a policy to its chain; older databases are migrated with `chain_id = NULL` and therefore remain in legacy mode. The `policies.agent_token_hash` column stores only a SHA-256 hexadecimal digest; raw agent tokens are never written to SQLite. The `daily_reservations` table records each request's UTC date, amount, recipient, and decision.

### Agent token lifecycle

- Tokens are generated with Python's cryptographically secure `secrets.token_urlsafe(32)`.
- A new policy creation response returns its raw agent token once.
- The owner can rotate a token through `POST /policies/{policy_id}/rotate-agent-token`, authenticated by `AGENTGUARD_ADMIN_TOKEN`.
- Rotation replaces the hash immediately. The previous token stops authenticating as soon as the update commits.
- The raw token is not returned by any read endpoint and must be saved by the caller when created or rotated.
- Token hashes are compared with `hmac.compare_digest`.
- Existing policies from databases created before this column was introduced receive a nullable `agent_token_hash` column through a schema migration. Those policies remain stored, but agent requests are denied until the owner rotates a token for them.

This is a simple per-policy shared-secret mechanism. It is not a user identity system and does not prove that the caller controls the wallet or funds associated with a recipient.

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

Creates a policy and returns `policy_id`, policy values, the optional `chain_id`, and a one-time `agent_token`. Only the token hash is stored. When `chain_id` is an EVM CAIP-2 identifier, the API validates all allowlist addresses before creating the policy.

#### POST /policies/{policy_id}/rotate-agent-token

Requires the owner token. Replaces the policy's agent-token hash and returns the new raw token once. Unknown policy IDs return HTTP 404 to the authenticated owner.

#### POST /check-transaction

Requires `Authorization: Bearer <agent-token>` associated with the policy ID in the request. Accepts only:

- `policy_id`
- `request_id`
- `amount`
- `recipient`

For EVM-bound policies, the recipient must be a valid 20-byte hexadecimal EVM address. Caller-supplied `daily_spent` and policy overrides are rejected. Missing, invalid, and cross-policy credentials all return HTTP 401 without revealing whether a policy ID exists. Reusing an idempotency key with a different payload returns HTTP 409.

## Security scope and limitations

AgentGuard is not a wallet security system. It does not hold keys, sign transactions, submit transactions, or stop an agent from bypassing the API. Agent tokens authenticate access to the policy-evaluation endpoint; they are not proof of wallet ownership. Reservations are not reconciled with actual blockchain settlement. Do not use the API as the sole control protecting real funds.

## Technology

- Python
- FastAPI
- SQLite
- pytest

## What we are NOT building yet

- Reservation settlement or release
- Policy update or deletion endpoints
- Wallet connections, private keys, signing, broadcasting, or mainnet transactions
- User accounts, OAuth, JWT, or a full permissions system
- Rate limiting and public production deployment hardening
- Token, DAO, or own blockchain
