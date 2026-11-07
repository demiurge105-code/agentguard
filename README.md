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

Use `examples/demo_agent.py` as the canonical API demo. It creates a policy through the local API and proposes two hypothetical transactions. For each proposal, it asks AgentGuard for a decision before reaching the simulated executor:

Each proposal is represented by a frozen `TransactionIntent` containing its description, exact `Decimal` amount, and recipient. The API check payload is built from that object, and the simulated executor receives the same object rather than separately reconstructed values. This demonstrates in-process intent consistency; it is not a cryptographic authorization proof and does not prevent a malicious agent from bypassing the demo flow.

- If the response contains the literal boolean `"allowed": true`, the demo prints that the simulated action would execute.
- If AgentGuard returns `DENY`, omits the `allowed` field, or returns a non-boolean value, the simulated executor is skipped.
- If the API request fails or returns an invalid response, the demo stops without simulating execution.

The agent is deterministic and uses Python's standard library; no LLM API key or wallet is required.

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

The demo creates a new policy on each run. It proposes one transaction within the per-transaction limit (expected: `ALLOW`) and one above that limit (expected: `DENY`). The returned agent token is kept in memory and is not printed. The script accepts only a local loopback API URL; if needed, set `AGENTGUARD_API_URL` to a URL such as `http://localhost:8000`.

All proposals and executor actions are simulations. The demo does not use an LLM, connect to a wallet, sign or broadcast transactions, or prevent an agent from bypassing the API. The executor is deliberately a print-only placeholder, not a production transaction adapter.

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

Per-policy agent tokens authenticate access to the evaluation API. They do not prove that a caller is the legitimate wallet owner, and they do not stop an agent from bypassing AgentGuard entirely. Do not use this API as the sole control protecting real funds.

## Architecture

The current implementation consists of:

- **Policy and request models** — validate policy limits, transaction amounts, and recipient identifiers.
- **Chain adapters** — validate EVM CAIP-2 chain identifiers and normalize EVM addresses; other chain namespaces are not implemented yet.
- **Policy engine** — evaluates a request and returns a deterministic decision.
- **SQLite policy store** — persists policies, agent-token hashes, and daily reservations separately from the policy engine.
- **FastAPI interface** — exposes owner-authenticated policy management and agent-authenticated transaction evaluation.
- **Tests and examples** — demonstrate and verify the simulation behaviour.

See [docs/architecture.md](docs/architecture.md) for more detail.

## Roadmap

Planned areas of work include:

1. Reservation settlement/release and a decision log.
2. An LLM-backed agent adapter built on top of the deterministic API demo.
3. External developer feedback and security review.
4. Further security design and isolated wallet or testnet integration research.

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
