# AgentGuard — MVP Architecture

## Goal

AgentGuard is an experimental, simulation-only policy evaluation service for proposed crypto transactions from AI agents. It does not connect to wallets, sign transactions, or submit blockchain transactions.

## API evaluation flow

The backward-compatible HTTP policy-check flow remains:

1. The policy owner creates a policy through `POST /policies` using the owner token.
2. The API generates a cryptographically random agent token, stores only its SHA-256 hash with the policy, and returns the raw token once.
3. The agent submits the policy ID, request ID, amount, recipient, and its token in the `Authorization: Bearer` header to `POST /check-transaction`.
4. The API hashes the supplied token and compares it with the hash stored for that policy. Missing, invalid, and cross-policy tokens receive the same HTTP 401 response.
5. The SQLite store serializes evaluation and reservation in a write transaction.
6. The API returns an `ALLOW` or `DENY` decision with a stable reason code.

## Gateway API and demo flow

The canonical `examples/demo_agent.py` exercises the authenticated HTTP Gateway endpoint. The agent process does not open SQLite or receive an executor reference.

1. The demo creates a policy through the local API.
2. Each proposal is converted into the core immutable `ActionIntent`.
3. The demo submits the policy ID, exact decimal amount, recipient, agent token, and a unique `Idempotency-Key` to `POST /gateway/operations`.
4. The API loads the policy's stored chain context. It does not accept caller-supplied chain IDs, policy limits, daily-spent values, or executor parameters.
5. The API authenticates the token to obtain policy context, then the store reauthenticates atomically while binding the idempotency key, evaluating policy, reserving budget, creating the operation, and enqueueing its job.
6. The API returns the persisted operation state. An allowed operation remains `APPROVED` while its separate execution-job state is `QUEUED`; the HTTP request never invokes an executor.
7. A separate worker atomically leases a `QUEUED` job (or an expired pre-dispatch `LEASED` job), incrementing its fencing token. Two workers cannot own the same current lease.
8. Immediately before invoking the executor, the worker atomically verifies its worker ID, fencing token, and unexpired lease, then moves the job to `DISPATCH_STARTED` and the operation to `EXECUTING`. This is the no-replay boundary.
9. The worker persists `SUCCEEDED`, `FAILED`, or `UNKNOWN` only if its fencing token is still current and the operation remains `EXECUTING`. Executor exceptions and arbitrary return data are not stored.

Operation states remain `APPROVED`, `DENIED`, `EXECUTING`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`. Job states are `QUEUED`, `LEASED`, `DISPATCH_STARTED`, `COMPLETED`, and `UNKNOWN`. A trusted executor may return a typed `ExecutionOutcome`; `FAILED` is accepted only when its contract confirms no side effect occurred.

An expired `LEASED` job can be reclaimed because the worker has not crossed the dispatch boundary; its fencing token increments, so the previous worker cannot start. Once `DISPATCH_STARTED` is durable, the job is never automatically re-leased. A crash between persisting this state and actually calling the executor can therefore produce zero execution attempts. A crash after an external side effect but before result persistence leaves an ambiguous operation; stale recovery moves it to `UNKNOWN`, retains the reservation, and fences late worker completion.

Idempotency keys are globally unique within the SQLite database. Reuse with a different policy or canonical intent conflicts. Gateway reservations use a random operation-scoped reservation ID rather than the caller-provided key, avoiding collisions with legacy `/check-transaction` request IDs.

The gateway is an in-process application boundary on the API server, not a Python sandbox. Malicious code with the same process privileges can still import internal modules or use independent execution capabilities. The legacy `/check-transaction` endpoint remains a separate evaluation/reservation path and does not execute actions.

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
- `begin_gateway_operation(intent, agent_token, idempotency_key) -> operation | None`
- `claim_execution_job(worker_id, lease_seconds=30) -> job | None`
- `start_execution_job(operation_id, worker_id, fencing_token) -> bool`
- `complete_execution_job(operation_id, worker_id, fencing_token, status, result=None) -> bool`
- `get_gateway_execution_status(operation_id) -> str | None`
- `claim_gateway_operation(...) -> bool | None` and `complete_gateway_operation(...)` — retained for the legacy in-process helper, not used by the HTTP API.
- `get_gateway_operation(policy_id, idempotency_key) -> operation | None`
- `get_gateway_operation_by_id(operation_id) -> operation | None`
- `list_gateway_operation_events(operation_id) -> events | None`
- `reconcile_gateway_operation_unknown(operation_id, actor_id, reason) -> bool`

Policy limits and transaction amounts are stored as decimal strings. Recipient allowlists are stored as JSON. The nullable `policies.chain_id` column binds a policy to its chain; older databases are migrated with `chain_id = NULL` and therefore remain in legacy mode. The `policies.agent_token_hash` column stores only a SHA-256 hexadecimal digest; raw agent tokens are never written to SQLite. The `daily_reservations` table records each request's UTC date, amount, recipient, decision, and reservation lifecycle state (`RESERVED`, `SETTLED`, `RELEASED`, or `NOT_RESERVED`).

### Durable execution jobs and worker

The API's `POST /gateway/operations` path is enqueue-only. The operation row, daily-budget reservation, audit event, and `gateway_execution_jobs` outbox row are created in the same SQLite `BEGIN IMMEDIATE` transaction. An allowed API response is `status: APPROVED` and `execution_status: QUEUED`; denial creates no job.

Implemented in `agentguard.worker.ExecutionWorker` and `agentguard.storage.SQLitePolicyStore`.

The worker uses the following job lifecycle:

- `QUEUED`: durably waiting for a worker.
- `LEASED`: one worker owns a bounded pre-dispatch lease.
- `DISPATCH_STARTED`: the worker has crossed the no-automatic-replay boundary.
- `COMPLETED`: a terminal `SUCCEEDED` or trusted `FAILED` result was persisted.
- `UNKNOWN`: execution may have started, but its outcome cannot be safely established.

Claiming a job runs under `BEGIN IMMEDIATE`. A lease is reclaimable only while the job is still `LEASED` and its expiry has passed. Each claim increments a monotonically increasing fencing token. Before calling the executor, the worker must atomically prove that its worker ID and fencing token still match and that its lease has not expired. That transition changes the operation from `APPROVED` to `EXECUTING` and the job to `DISPATCH_STARTED`.

After dispatch starts, a job is never automatically reclaimed. If the process crashes before it calls the executor, the operation may never execute; this is an intentional safety trade-off. If a side effect occurs but its result is not persisted, recovery changes the operation and job to `UNKNOWN`, keeps the reservation, and prevents a late worker from persisting a result. A stale worker cannot complete after its job has been fenced by recovery.

Run the worker with `agentguard-worker`; use `agentguard-worker --once` to process at most one queued job. The API and worker must point to the same SQLite file via `AGENTGUARD_DB_PATH`.

The print-only executor only prints a simulation. A future executor can return `ExecutionOutcome`; it must return `FAILED` only when its own verification contract establishes that no side effect occurred. Arbitrary executor return values and exception messages are not stored; ambiguous outcomes are recorded as `UNKNOWN`.

The older in-process `TrustedExecutionGateway` helper remains available for direct internal use and its existing tests, but the HTTP API no longer invokes it. Do not wire an external executor into that in-process path.

Every operation creation and subsequent status transition is accompanied by an append-only `gateway_operation_events` row in the same SQLite transaction. Events include transition, actor type/identifier, bounded reason, and timestamp, but never credentials or arbitrary executor data. Existing operations are migrated with a `LEGACY_IMPORT` event that explicitly states earlier transitions are unavailable.

The owner-authenticated API can inspect an operation, its reservation state, and its events. An owner can reconcile only `EXECUTING -> UNKNOWN`, with a required reason. The owner can also explicitly recover a bounded batch of stale `EXECUTING` operations through `POST /gateway/operations/recover-stale`, using a caller-supplied age threshold and audit reason. The operation selection, `EXECUTING -> UNKNOWN` transitions, and per-operation audit events commit in one `BEGIN IMMEDIATE` transaction. Recovery never invokes an executor, never releases a reservation, and is not triggered automatically at application startup. Completion racing recovery is serialized; whichever transaction commits first determines the final state. There is deliberately no manual API transition to `SUCCEEDED` or `FAILED`. A trusted executor may return a typed `ExecutionOutcome`; `FAILED` is accepted only when that executor's contract confirms no side effect occurred. Exceptions, unsupported outputs, and ambiguous outcomes remain `UNKNOWN`, so their reservations are not released. Reconciliation never authorizes another execution attempt. The event log is append-only through the application API, but it is not tamper-proof against a database or host administrator.

The gateway is not a sandbox and does not protect against malicious same-process Python code. The demo is wired through the gateway, but the legacy HTTP `/check-transaction` endpoint is not. The authenticated gateway HTTP endpoint, wallet, signer, RPC, broadcasting, and real-fund execution remain distinct concerns.

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

An allowed legacy `/check-transaction` decision remains a committed daily-budget reservation for backward compatibility. Gateway operations create a `RESERVED` row. On `SUCCEEDED`, the operation and reservation atomically transition to `SETTLED`; on a typed trusted-executor `FAILED` outcome, they atomically transition to `RELEASED` only when the executor confirms no side effect occurred. `UNKNOWN` and manual reconciliation to `UNKNOWN` keep the reservation active. Reservation state changes are recorded in the operation audit log in the same SQLite transaction. The reservation day remains the UTC day on which it was created, even if execution completes after midnight. These states describe budget accounting, not blockchain settlement or proof that funds moved.

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

### POST /gateway/operations

The Gateway endpoint accepts an agent bearer token, a required `Idempotency-Key` header, and a body containing only `policy_id`, `amount` (decimal string), and `recipient`.

The API first performs an authenticated policy-context lookup to obtain the stored `chain_id`. This lookup is not the execution authorization: the gateway reauthenticates atomically when creating/reserving the operation and again when claiming `APPROVED -> EXECUTING`. A token revoked between those stages cannot reach the executor.

The caller cannot provide chain context, policy limits, daily-spent values, executor configuration, or other extra fields. The route constructs ActionIntent with the chain ID loaded from policy storage and delegates to TrustedExecutionGateway with the server-owned PrintOnlyExecutor.
ActionIntent currently requires canonical UUID policy IDs. Newly created policies satisfy this; older migrated policies with non-UUID identifiers can continue using `/check-transaction` but are not accepted by the gateway endpoint.

Responses include the operation ID, status, allow/deny decision, reason code, and timestamps. Invalid credentials return HTTP 401 without disclosing policy existence; conflicting idempotency reuse returns HTTP 409; invalid input returns HTTP 422; storage errors return HTTP 503. A denial is a normal operation response with status DENIED, not an HTTP error.

The route is simulation-only. SUCCEEDED means the print-only executor returned; it is not evidence of a blockchain transaction or real-world side effect. The legacy `/check-transaction` endpoint remains a separate evaluation/reservation path.

## Security scope and limitations

AgentGuard is not a wallet security system. It does not hold keys, sign transactions, submit transactions, or stop malicious code from bypassing the gateway or API. Agent tokens authenticate access to the policy-evaluation endpoint and in-process gateway; they are not proof of wallet ownership. The legacy /check-transaction endpoint remains separate from the gateway execution endpoint. Reservations are not reconciled with actual blockchain settlement. Do not use this system as the sole control protecting real funds.

## Technology

- Python
- FastAPI
- SQLite
- pytest

## What we are NOT building yet

- Policy update or deletion endpoints
- Wallet connections, private keys, signing, broadcasting, or mainnet transactions
- User accounts, OAuth, JWT, or a full permissions system
- Rate limiting and public production deployment hardening
- Token, DAO, or own blockchain
