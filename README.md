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
- A recipient allowlist with case-insensitive recipient comparison.
- Structured `ALLOW` / `DENY` decisions.
- Stable reason codes and human-readable explanations.
- Decimal input validation, including rejection of `NaN`, `sNaN`, and positive or negative infinity.
- SQLite storage for owner-created policies; monetary values are stored as decimal strings.
- Owner-token-protected policy creation.
- A FastAPI endpoint that evaluates requests against a stored policy.
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

Set an owner token before creating policies. Keep it secret and do not commit it:

```bash
# macOS / Linux
export AGENTGUARD_ADMIN_TOKEN="replace-with-a-long-random-secret"

# Windows PowerShell
$env:AGENTGUARD_ADMIN_TOKEN = "replace-with-a-long-random-secret"
```

The SQLite database path can be changed with `AGENTGUARD_DB_PATH`. If unset, the application uses `agentguard.db` in the current working directory.

If `AGENTGUARD_ADMIN_TOKEN` is unset or empty, policy creation is disabled (fail closed).

### Create a policy

`POST /policies` requires the owner token in the Authorization header:

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

The server generates and returns a `policy_id`. Policy values are stored in SQLite; monetary values are stored as decimal strings.

### Check a transaction

`POST /check-transaction` accepts only the policy ID and proposed transaction data:

```json
{
  "policy_id": "<policy-id-returned-when-created>",
  "amount": "35",
  "recipient": "0xABC",
  "request_id": "agent-run-0001"
}
```

The response contains `allowed`, `reason_code`, and `reason`. The endpoint loads policy limits and recipients from SQLite; callers cannot override them in the request. Unknown policy IDs return HTTP 404.

### Important security limitation

This is still a simulation interface, not a secure transaction-enforcement boundary.

Daily usage is derived from SQLite reservations. Evaluation and reservation run in one serialized write transaction, so concurrent requests cannot collectively reserve more than the daily limit. Only allowed requests reserve budget; denied requests do not. Usage resets at 00:00 UTC. A reservation is budget allocated to an allowed simulated request, not proof that funds were spent or a transaction was broadcast; settlement and release are not implemented.

The owner token protects policy creation; it does not authenticate callers of `/check-transaction` or bind a policy to a particular agent. Do not use this API as the sole control protecting real funds.

## Architecture

The current implementation consists of:

- **Policy and request models** — validate policy limits, transaction amounts, and recipient identifiers.
- **Policy engine** — evaluates a request and returns a deterministic decision.
- **SQLite policy store** — persists owner-created policies separately from the policy engine.
- **FastAPI interface** — exposes owner-authenticated policy creation and transaction evaluation.
- **Tests and examples** — demonstrate and verify the simulation behaviour.

See [docs/architecture.md](docs/architecture.md) for more detail.

## Roadmap

Planned areas of work include:

1. Trusted daily-spending accounting maintained by AgentGuard, including safe concurrency.
2. A decision log for recording evaluation outcomes.
3. A demo integration with an AI agent.
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

It does not hold keys, sign transactions, submit transactions, or stop an agent from bypassing the API. The owner token is a basic shared-secret mechanism for policy creation, not a complete authentication or authorization system. Do not use an `ALLOW` decision as proof that a transaction is safe.

Never commit private keys, seed phrases, API keys, or other secrets.

## License

This project is licensed under the [MIT License](LICENSE).
