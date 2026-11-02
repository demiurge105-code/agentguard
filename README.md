# AgentGuard

**An open-source permission layer for AI agents interacting with crypto wallets.**

## The problem

AI agents can interact with external tools, but crypto wallet operations need explicit, testable permissions.

## Our approach

AgentGuard is an early-stage project exploring a policy engine that evaluates simulated transactions before execution.

Initial policies:
- Maximum transaction amount
- Daily spending limit
- Recipient address allowlist
- ALLOW or DENY decisions with explanations

## Quick start

AgentGuard currently has no runtime dependencies. It requires Python 3.10+.

```bash
git clone https://github.com/demiurge105-code/agentguard.git
cd agentguard
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
# source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python examples/basic_check.py
```

Expected result: the test suite passes and the example prints an allowed
`Decision`. If `pytest` is not found, run it as `python -m pytest` from the
activated virtual environment.

The policy engine is deliberately a simulator: it makes a decision about a
proposed transaction but never submits a transaction or accesses a wallet.

```python
from agentguard import Policy, TransactionRequest, check_transaction

policy = Policy("50", "200", ["0xABC"])
request = TransactionRequest(amount="35", recipient="0xABC", daily_spent="100")

decision = check_transaction(request, policy)
# Decision(allowed=True, reason_code=<DecisionReason.ALLOWED: 'allowed'>, ...)
```

See [the architecture](docs/architecture.md) for the MVP contract and rule order.

## Project status and next milestones

The simulation-only policy engine, example, tests, and pull-request CI are in
place. The next deliberately small milestones are:

1. Review and merge the current JSON-serialization contribution.
2. Add a minimal FastAPI wrapper that delegates to the policy engine.
3. Add a demo agent only after the API contract is stable.

EVM testnet work is explicitly out of scope until the simulator and its API
have proven reliable.

## Run the local API

The API is also simulation-only: it evaluates a supplied request and never
accesses a wallet, signs, or submits a transaction.

```bash
uvicorn agentguard.api:app --reload
```

Open `http://127.0.0.1:8000/docs` to try the generated local API documentation.
The endpoint accepts `POST /check-transaction` with the policy and request
fields shown in [the architecture](docs/architecture.md), then returns
`allowed`, `reason_code`, and `reason`.

## Tech stack

- Python
- FastAPI
- pytest
- SQLite (planned)
- TypeScript / React (planned)

## Current status

🚧 Early development. Simulation only. AgentGuard does not currently secure real wallets or prevent transactions submitted outside its policy engine.

## Contributing

We welcome beginner and early-career developers interested in Python, backend development, AI agents, Web3, testing, and security. Start with an issue labelled [`good first issue`](https://github.com/demiurge105-code/agentguard/labels/good%20first%20issue).

Before choosing work, check whether an issue already has an active pull
request or a contributor who has claimed it. For the next small starter task,
see the maintainer-ready [issue draft](docs/starter-task-non-finite-decimals.md).
It is intentionally scoped to one focused pull request and includes its
acceptance criteria and tests.

New here? Read [CONTRIBUTING.md](CONTRIBUTING.md), complete the Quick start
above, then run `python -m pytest` before changing anything.

Every pull request automatically runs the test suite on supported Python versions.

This is an unfunded collaborative project. Participation is voluntary; there is no salary or guaranteed future compensation.

## Security

Do not use this experimental project to control real funds. Never commit private keys, seed phrases, or API secrets.

## License

This project is licensed under the [MIT License](LICENSE).
