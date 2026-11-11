# Trusted Execution Gateway: Security Boundary and Threat Model

## Status and scope

This document proposes a simulation-only architecture step. It is a design, not a description of current functionality.

Today, AgentGuard evaluates and reserves a proposed action. The demo agent then decides whether to call a print-only simulated executor. An agent with another execution path, wallet, signer, RPC endpoint, or direct tool can bypass that flow.

The proposed gateway owns the simulated executor and is the only component allowed to invoke it. This milestone adds no wallet, key custody, signing, RPC, broadcasting, chain adapter, LLM, frontend, or real-fund functionality.

## Assets and goals

Assets:
- Policy limits and recipient allowlists.
- Integrity of the exact action evaluated by the policy engine.
- Exclusive application-level access to the simulated executor.
- Request identity, idempotency records, and audit history.
- Confidentiality of owner and agent tokens.

Goals:
1. The executed simulated action is exactly the action evaluated.
2. Only an explicit policy allow can reach the executor.
3. Errors, malformed responses, timeouts, and unavailable storage never cause execution.
4. A retry cannot execute the same operation twice.
5. The system can explain what it checked and what the simulator did.

These are design goals, not guarantees of the current implementation.

## Implemented building block: ActionIntent

The core package now provides `agentguard.ActionIntent` as the validated input contract for the first gateway step. It is a frozen, slotted dataclass containing:

- `policy_id`: a canonical UUID identifying the policy context;
- `amount`: a positive finite Decimal within the policy engine's existing precision and exponent bounds;
- `recipient`: normalized through the existing chain-aware recipient helpers;
- `chain_id`: the normalized EVM CAIP-2 identifier, or `null` for legacy mode.

The model rejects boolean and float amounts, non-finite or non-positive amounts, malformed policy UUIDs, invalid recipients, and unsupported chain identifiers. It does not modify the current API or demo flow; the future gateway must construct this value before evaluation or reservation.

`canonical_json` emits compact, key-sorted JSON with a schema version. Amounts are encoded as decimal strings in fixed-point form, with insignificant fractional trailing zeros removed. Therefore `1`, `1.0`, and `1.00` share the same monetary identity, while distinct numeric values remain distinct. `canonical_bytes` exposes the exact UTF-8 bytes for a later digest.

The idempotency key is intentionally excluded. A future durable operation record must bind the caller-scoped key to both the policy identity and this canonical representation. Canonicalization alone does not authorize an action, prevent replay, or provide tamper-proof storage.


## Trust boundaries

| Component | Trust level | Responsibility |
| --- | --- | --- |
| Agent / planner | Untrusted | Proposes an action and idempotency key. |
| Agent-provided fields | Untrusted | Amount, recipient, chain context, and metadata require validation. |
| Gateway | Trusted within this design | Validates and freezes intent, requests policy evaluation, controls executor access. |
| Policy engine and store | Trusted within this design | Return deterministic decisions and atomically reserve budget. |
| Simulated executor | Trusted, minimal component | Performs a print-only simulation for a gateway-approved intent. |
| Audit store | Trusted for integrity and availability | Persists decisions and execution outcomes. |

The agent must not receive an executor object, executor credentials, or a callable route that bypasses the gateway.

**A Python module boundary is not a security sandbox.** Untrusted agent code running with the same process privileges may import internal modules, inspect memory, or use other available capabilities. Protection against hostile code requires process/container isolation and OS permissions, with execution capability available only to the gateway. That isolation is outside this milestone.

## Proposed flow

1. **Receive:** accept one action intent and a caller-scoped idempotency key. Do not accept executor parameters separately later.
2. **Validate:** reject unknown fields, malformed identifiers, non-finite or non-positive monetary values, invalid recipients, and unsupported chain identifiers. Use Decimal; never convert money through float.
3. **Freeze:** create one immutable validated intent containing every field that can affect execution. Normalize only according to documented chain-specific rules.
4. **Bind identity:** bind the idempotency key to the policy and canonical intent. An exact retry refers to the original operation; reuse with a different intent returns conflict.
5. **Evaluate and reserve:** evaluate the frozen intent and atomically reserve budget for an allowed operation. Any error or unavailable store stops the flow.
6. **Authorize internally:** only a well-formed literal boolean allowed=true for this same intent can advance.
7. **Execute:** pass the exact frozen intent to the gateway-owned simulated executor. Never rebuild amount or recipient from the original agent payload.
8. **Record:** persist the decision and execution outcome. Return the stored operation state.

```text
Untrusted agent
      | one intent + idempotency key
      v
Trusted gateway: validate + freeze
      |
      v
Policy evaluation + atomic budget reservation
      |
      +---- deny / error ----> no executor call
      |
      +---- explicit ALLOW
                 |
                 v
       Gateway-owned simulated executor
                 |
                 v
           Audit outcome
```

## Security invariants

- **Exact-intent binding:** all execution-relevant fields are validated once and bound to the decision. The executor receives the same immutable value, not reconstructed values.
- **Gateway-only execution:** the agent has no direct reference, credential, or network route to the executor. In this milestone this is an application-architecture rule, not hostile-process isolation.
- **Fail closed:** exceptions, timeouts, missing fields, unexpected types, unknown decision values, storage errors, and audit failures must not cause execution.
- **Policy ownership:** limits and allowlists come from stored policy state; the agent cannot override them.
- **Monetary correctness:** use Decimal, reject non-finite values, and reject booleans/floats where decimal strings or Decimal values are required.
- **Replay safety:** one idempotency key is bound to one canonical intent and operation record. Conflicting reuse is rejected.
- **Secret hygiene:** raw bearer tokens never enter logs or audit records.

## Failure and replay behavior

| Condition | Required behavior |
| --- | --- |
| Invalid intent | Reject before evaluation; no execution. |
| Policy denial | Record denial; no executor call. |
| Policy service / database unavailable | Fail closed; no execution. |
| Missing or malformed decision, or allowed is not literal true | No execution. |
| Timeout before decision is known | No execution. Retry only against the same operation identity. |
| Executor failure | Record failure; do not blindly retry unless executor idempotency is guaranteed. |
| Crash after reservation but before execution | Recover existing operation; do not reserve or execute a second time. |
| Crash after executor action but before success record | Outcome is ambiguous; reconcile before any retry. |

The current API idempotency behavior prevents duplicate budget reservation for a repeated policy check and rejects a different payload under the same key. It does **not** guarantee exactly-once execution. The gateway needs durable execution state associated with the same operation identity.

A possible state model is PENDING -> APPROVED -> EXECUTING -> SUCCEEDED / FAILED / UNKNOWN. State transitions must be durable and concurrency-controlled. UNKNOWN is required when the process may have performed a side effect but crashed before recording the result.

A database row alone cannot guarantee exactly-once external side effects. That requires an idempotent executor or a transaction that couples state and side effect. The simulation executor can deduplicate by operation ID; any future external executor needs its own idempotency and reconciliation contract.

## Reservations and audit

The current store reserves daily budget when an allowed decision is returned. Reservation release and settlement are not implemented. Therefore, executor failure must not silently refund budget in this milestone. Keep the reservation and record failure/unknown outcome until a separately designed lifecycle exists.

Each operation audit record should include:
- operation ID and idempotency key;
- policy ID and policy version or immutable policy snapshot reference;
- canonical intent or a privacy-reviewed representation;
- digest of canonical intent;
- decision, reason code, and timestamp;
- reserved amount and UTC accounting date;
- execution state, timestamps, and sanitized executor result;
- correlation ID.

Never record raw bearer tokens, private keys, seed phrases, or unrelated agent context. A digest detects mismatches but is not proof of authorization or tamper-proof storage.

Audit persistence is part of the trusted path. If required operation state cannot be durably recorded, do not execute.

## Threats and mitigations

| Threat | Example | Mitigation / residual risk |
| --- | --- | --- |
| Agent bypass | Agent calls another tool or RPC path. | Gateway-only executor capability; hostile code requires process isolation, out of scope here. |
| Intent mutation | Recipient or amount changes after approval. | Freeze one validated intent and pass that exact object to executor. |
| Policy override | Agent supplies a larger limit or alternate allowlist. | Load policy from trusted storage; reject unknown fields. |
| Replay | Agent resends an approved request. | Durable idempotency and execution state; executor deduplicates by operation ID. |
| Key collision | Same key reused with a different action. | Bind key to canonical intent; return conflict. |
| Concurrent overspend | Parallel requests race on remaining budget. | Atomic reservation and concurrency tests at gateway boundary. |
| Fail-open parsing | Response says allowed as a string or omits the field. | Require literal boolean true; otherwise deny execution. |
| Crash ambiguity | Crash after side effect, before success record. | Durable transitions, idempotent executor, reconcile UNKNOWN; never blindly retry. |
| Token leakage | Authorization header appears in logs. | Redact credentials; exclude tokens from audit data. |
| Audit loss/tampering | Operation history unavailable or modified. | Restrict writes, validate transitions, fail closed on required write failure. Tamper-evident storage is future work. |

## Explicit limitations

Even after implementation, this simulation gateway will not protect real funds, prove wallet ownership, stop hostile code with independent execution capability, provide secure signing, guarantee exactly-once arbitrary external side effects, or provide tamper-proof logs.

Before real transaction integration, a separate reviewed design would be required for process/network isolation, signer custody and authorization, chain-specific transaction construction, nonce and fee handling, final transaction verification, settlement and reservation recovery, monitoring, key rotation, rate limiting, and independent security review. These are future research areas, not current capabilities.

## Smallest implementation sequence

1. Define a typed immutable gateway intent and strict canonicalization tests.
2. Add a gateway service that owns the simulated executor; do not expose the executor to the demo agent.
3. Add a durable operation record with unique policy-scoped idempotency key and canonical-intent binding.
4. Implement atomic state transitions and explicit UNKNOWN handling.
5. Make the executor deduplicate by operation ID and accept only the gateway's validated intent type.
6. Add negative tests for bypass, mutation, malformed decisions, retries, conflicting keys, concurrency, storage failures, and crash points.
7. Update the demo and docs to describe only guarantees actually enforced.

Do not add wallet, signing, RPC, broadcasting, LLM, frontend, or production deployment functionality as part of this design task.
