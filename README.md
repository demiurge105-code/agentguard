# AgentGuard

**An open-source policy engine for evaluating crypto transaction requests from AI agents.**

AgentGuard is an early-stage project that evaluates simulated transaction requests against explicit, testable policies. It provides a Python policy engine, SQLite-backed owner-controlled policy storage, and a local FastAPI interface.

> **Status: experimental, simulation-only.** AgentGuard does not connect to wallets, sign transactions, submit blockchain transactions, or prevent operations that bypass its evaluation flow.

## The problem

AI agents can interact with external tools, but transaction-related actions need clear and testable limits. Developers need a way to evaluate proposed operations against rules such as maximum transaction amounts, daily spending limits, and approved recipients.

## Current capabilities

The current implementation includes:

- A deterministic policy engine.
- A maximum transaction amount check.
- A daily spending limit check.
- A recipient allowlist with legacy case-insensitive identifiers and chain-aware EVM address validation when a policy specifies an EVM chain.
- Structured `ALLOW` / `DENY` decisions.
- Stable reason codes and human-readable explanations.
- Decimal input validation, including rejection of `NaN`, `sNaN`, and positive or negative infinity.
- SQLite storage for owner-created policies; monetary values are stored as decimal strings.
- Owner-token-protected policy creation and agent-token rotation.
- Per-policy agent tokens; only SHA-256 token hashes are stored.
- A FastAPI endpoint that authenticates an agent before evaluating a request.
- Atomic server-side daily reservations and idempotent request handling.
- An in-process TrustedExecutionGateway with durable operation records and a single atomic execution claim.
- Idempotent gateway retries that do not invoke the executor twice, including after an unresolved execution attempt.
- Automated tests and pull-request CI.

The engine checks rules in this order: maximum transaction amount, daily spending limit, then recipient allowlist. The first failed rule determines the denial reason.

## Requirements

- Python 3.10+
- Git

The package currently declares FastAPI and Uvicorn as runtime dependencies. Pytest and HTTPX are included in the optional development dependencies.

## Quick start

Clone the repository and install the package with its development dependencies:

```bash
git clone https://github.com/demiurge105-code/agentguard.git
cd agentguard

python -m venv .venv

# Windows PowerShell
.venv\\Scripts\\Activate.ps1

# macOS / Linux
# source .venv/bin/activate

python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
python -m pytest
```

Run the basic example:

```bash
python examples/basic_check.py
```

The example should print an allowed `Decision`.

## Python usage

```python
from agentguard import Policy, TransactionRequest, check_transaction

policy = Policy(
    max_transaction="50",
    daily_limit="200",
    allowed_recipients=["0xABC"],
)

request = TransactionRequest(
    amount="35",
    recipient="0xABC",
    daily_spent="100",
)

decision = check_transaction(request, policy)
print(decision.to_dict())
```

Amounts and limits should be provided as `Decimal` values or decimal strings, not floats.

## Local API

Start the local FastAPI application:

```bash
uvicorn agentguard.api:app --reload
```

Open the interactive API documentation at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

### Configuration

Set an owner token before creating or rotating policies. Keep it secret and do not commit it:

```bash
# macOS / Linux
export AGENTGUARD_ADMIN_TOKEN="replace-with-a-long-random-secret"

# Windows PowerShell
$env:AGENTGUARD_ADMIN_TOKEN = "replace-with-a-long-random-secret"
```

The SQLite database path can be changed with `AGENTGUARD_DB_PATH`. If unset, the application uses `agentguard.db` in the current working directory.

If `AGENTGUARD_ADMIN_TOKEN` is unset or empty, policy creation and token rotation fail closed with HTTP 401.

### Run the demo agent

Use `examples/demo_agent.py` as the canonical Gateway v1 demo. It creates a policy through the local FastAPI endpoint, builds two immutable `ActionIntent` objects, then submits them over HTTP to `/gateway/operations`.

The demo does **not** call `/check-transaction` and then decide for itself whether to execute. The API server authenticates the agent token, evaluates and reserves budget, persists the operation, atomically claims execution, and invokes its own `PrintOnlyExecutor` only for an approved action. The agent process never opens the SQLite database or receives an executor reference.

- The first proposal is within the per-transaction limit and should finish as `SUCCEEDED`.
- The second proposal exceeds the per-transaction limit and should finish as `DENIED`; the executor is not called.
- Operation IDs and statuses are printed. The agent token is kept in memory and never printed.

The demo is deterministic; no LLM API key or wallet is required.

Start the API from the repository root in one terminal. Set an owner token before starting it:

```bash
# macOS / Linux
export AGENTGUARD_ADMIN_TOKEN="replace-with-a-long-random-secret"
uvicorn agentguard.api:app --reload
```

Windows PowerShell:

```powershell
$env:AGENTGUARD_ADMIN_TOKEN = "replace-with-a-long-random-secret"
uvicorn agentguard.api:app --reload
```

In a second terminal, from the repository root, set the same owner token and run the demo:

```bash
# macOS / Linux
export AGENTGUARD_ADMIN_TOKEN="replace-with-a-long-random-secret"
python examples/demo_agent.py
```

Windows PowerShell:

```powershell
$env:AGENTGUARD_ADMIN_TOKEN = "replace-with-a-long-random-secret"
python examples/demo_agent.py
```

The API server uses `AGENTGUARD_DB_PATH` for SQLite; if unset, it uses `agentguard.db` in its current working directory. The demo does not access this file directly. It accepts only a loopback API URL; if needed, set `AGENTGUARD_API_URL` to a URL such as `http://localhost:8000`.

All proposals and executor actions are simulations. The print-only executor does not connect to a wallet, sign or broadcast transactions, or move funds. The gateway is an in-process application boundary, not a sandbox against malicious Python code running with the same process privileges. The existing `/check-transaction` API remains available for backward compatibility and is separate from the gateway execution endpoint.

### Create a policy

`POST /policies` requires the owner token:

```http
POST /policies
Authorization: Bearer <your-admin-token>
Content-Type: application/json

{
  "max_transaction": "50",
  "daily_limit": "200",
  "allowed_recipients": ["0xABC", "0xDEF"]
}
```

The response includes a generated `policy_id` and an `agent_token`. **Save the agent token immediately:** the raw token is returned only when the policy is created or its token is rotated. AgentGuard stores only its SHA-256 hash in SQLite and does not provide a way to retrieve the raw token later.

### Chain-aware policies (EVM-first)

New EVM policies can bind their allowlist to a CAIP-2 chain identifier. For example, use `chain_id: "eip155:1"` for Ethereum mainnet or `chain_id: "eip155:8453"` for Base. The chain is stored on the policy, so callers cannot override it on individual transaction checks.

When `chain_id` is present, every allowed recipient and proposed recipient must be a 20-byte hexadecimal EVM address (`0x` followed by 40 hexadecimal characters). Addresses are normalized to lowercase before allowlist and idempotency comparisons. The current implementation validates address shape; it does not verify EIP-55 checksums, query a chain, or prove that the selected chain exists or is reachable.

When `chain_id` is omitted, the policy remains in legacy mode and retains the previous case-insensitive arbitrary-identifier behavior. This preserves existing policies and integrations while new chain-aware integrations opt into EVM validation.

Example policy payload:

```json
{
  "max_transaction": "50",
  "daily_limit": "200",
  "chain_id": "eip155:8453",
  "allowed_recipients": ["0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"]
}
```

### Check a transaction

`POST /check-transaction` requires the agent token associated with the requested policy:

```http
POST /check-transaction
Authorization: Bearer <agent-token>
Content-Type: application/json

{
  "policy_id": "<policy-id-returned-when-created>",
  "amount": "35",
  "recipient": "0xABC",
  "request_id": "agent-run-0001"
}
```

The response contains `allowed`, `reason_code`, and `reason`. Missing, invalid, and cross-policy tokens return HTTP 401 without revealing whether the policy ID exists. The endpoint loads policy limits and recipients from SQLite; callers cannot override them in the request.

### Submit an action through the Gateway

`POST /gateway/operations` sends a proposed action through the in-process Trusted Execution Gateway. Unlike `/check-transaction`, this endpoint owns the print-only executor and returns a persisted operation state.

```http
POST /gateway/operations
Authorization: Bearer <agent-token>
Idempotency-Key: <unique-key>
Content-Type: application/json

{
  "policy_id": "<policy-id-returned-when-created>",
  "amount": "25",
  "recipient": "0xABC"
}
```

The caller must provide a globally unique `Idempotency-Key`. Repeating the same key with the same policy and canonical action returns the stored operation without invoking the executor again. Reusing it with another policy or action returns HTTP 409.

The response includes `operation_id`, `status`, `allowed`, `reason_code`, `reason`, and timestamps. A policy denial is returned as HTTP 200 with status `DENIED`; invalid or missing credentials return HTTP 401 without revealing whether the policy exists. Invalid payloads return HTTP 422.

The endpoint loads the chain identifier from the stored policy. The request cannot override `chain_id`, limits, daily spending, or executor parameters. Monetary amounts must be decimal strings. The endpoint uses `PrintOnlyExecutor`: `SUCCEEDED` means the simulation completed, not that a blockchain transaction was sent.

The existing `/check-transaction` endpoint remains available for policy evaluation and budget reservation without execution.

### Rotate an agent token

`POST /policies/{policy_id}/rotate-agent-token` requires the owner token:

```http
POST /policies/<policy-id>/rotate-agent-token
Authorization: Bearer <your-admin-token>
```

The response contains the new `agent_token` once. Rotation replaces the stored hash immediately, so the previous token stops working. Save the new token securely.

### Existing databases

On startup, AgentGuard adds the nullable `agent_token_hash` column to an older SQLite `policies` table when needed. Existing policies are preserved, but they have no agent token and therefore cannot be used through `/check-transaction` until the owner rotates a token for each policy.

### Important security limitation

This is still a simulation interface, not a secure transaction-enforcement boundary.

Daily usage is derived from SQLite reservations. Evaluation and reservation run in one serialized write transaction, so concurrent requests cannot collectively reserve more than the daily limit. Only allowed requests reserve budget; denied requests do not. Usage resets at 00:00 UTC. A reservation is budget allocated to an allowed simulated request, not proof that funds were spent or a transaction was broadcast; settlement and release are not implemented.

Per-policy agent tokens authenticate access to the evaluation API and gateway service. They do not prove that a caller is the legitimate wallet owner. The gateway is currently an in-process service; malicious code with the same process privileges can still bypass it, and the existing /check-transaction endpoint is not routed through the gateway. Do not use this system as the sole control protecting real funds.

## Architecture

The current implementation consists of:

- **Policy and request models** — validate policy limits, transaction amounts, and recipient identifiers.
- **Chain adapters** — validate EVM CAIP-2 chain identifiers and normalize EVM addresses; other chain namespaces are not implemented yet.
- **Policy engine** — evaluates a request and returns a deterministic decision.
- **SQLite policy store** — persists policies, agent-token hashes, daily reservations, and gateway operation states separately from the policy engine.
- **Trusted Execution Gateway** — authenticates and reserves atomically, binds idempotency keys to canonical intents, and owns the print-only executor exposed through `/gateway/operations`.
- **FastAPI interface** — exposes owner-authenticated policy management, the backward-compatible `/check-transaction` endpoint, and the authenticated `/gateway/operations` execution endpoint.
- **Tests and examples** — demonstrate and verify the simulation behaviour.

See [docs/architecture.md](docs/architecture.md) for more detail.

## Roadmap

Planned areas of work include:

1. A dedicated gateway HTTP integration so remote agents can submit operations without accessing the SQLite store directly.
2. Reservation settlement/release and a tamper-evident audit design.
3. External developer feedback and independent security review.
4. Process isolation and further research before any wallet or testnet execution integration.

The roadmap may change as the project is tested with developers and potential users.

## Contributing

Contributions are welcome from developers interested in Python, backend development, AI agents, Web3, testing, and security.

- Browse [good first issues](https://github.com/demiurge105-code/agentguard/labels/good%20first%20issue).
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before starting.
- Check whether an issue already has an active pull request or a contributor working on it.
- Run `python -m pytest` before submitting a change.

Pull requests automatically run the test suite on the Python versions configured in CI.

This is an unfunded collaborative project. Participation is voluntary; there is no salary or guaranteed future compensation.

## Security

AgentGuard is experimental software and is not currently a wallet security system.

It does not hold keys, sign transactions, submit transactions, or stop an agent from bypassing the API. Do not use an `ALLOW` decision as proof that a transaction is safe.

Never commit private keys, seed phrases, API keys, owner tokens, or agent tokens.

## License

This project is licensed under the [MIT License](LICENSE).
