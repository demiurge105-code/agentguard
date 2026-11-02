# AgentGuard

**An open-source policy engine for evaluating crypto transaction requests from AI agents.**

AgentGuard is an early-stage project that evaluates simulated transaction requests against explicit, testable policies. It currently provides a Python policy engine and a local FastAPI interface.

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
- A FastAPI endpoint for evaluating simulated transaction requests.
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

The `POST /check-transaction` endpoint accepts:

- `amount`
- `recipient`
- `daily_spent`
- `max_transaction`
- `daily_limit`
- `allowed_recipients`

A successful evaluation returns `allowed`, `reason_code`, and `reason`. See [docs/architecture.md](docs/architecture.md) for the current contract and evaluation rules.

### Important API limitation

The current API is a simulation interface, not an enforcement boundary. The caller supplies the policy values and `daily_spent` with each request. AgentGuard does not yet store owner-controlled policies or independently track cumulative spending. A caller could therefore supply different policy values or an inaccurate spending total.

Do not use this API as the sole control protecting real funds.

## Architecture

The current implementation consists of:

- **Policy and request models** — validate policy limits, transaction amounts, and recipient identifiers.
- **Policy engine** — evaluates a request and returns a deterministic decision.
- **FastAPI interface** — exposes the evaluation flow over HTTP.
- **Tests and examples** — demonstrate and verify the simulation behaviour.

See [docs/architecture.md](docs/architecture.md) for more detail.

## Roadmap

Planned areas of work include:

1. Owner-controlled policy storage, rather than accepting policy values from every caller.
2. Reliable daily-spending accounting maintained by AgentGuard.
3. A decision log for recording evaluation outcomes.
4. A demo integration with an AI agent.
5. Further security design and isolated wallet or testnet integration research.

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

It does not hold keys, sign transactions, submit transactions, or stop an agent from bypassing the API. Do not use it to control real funds or treat an `ALLOW` decision as proof that a transaction is safe.

Never commit private keys, seed phrases, API keys, or other secrets.

## License

This project is licensed under the [MIT License](LICENSE).
