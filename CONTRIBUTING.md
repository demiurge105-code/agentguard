# Contributing to AgentGuard

Thanks for your interest in building AgentGuard with us!

## What we're building

AgentGuard is an early-stage open-source project exploring permission policies for AI agents that interact with crypto wallets.

Our first milestone is a simulator that evaluates proposed transactions against explicit rules. It does not control real funds.

## Who we're looking for

We welcome beginner and early-career contributors interested in:

- Python and backend development
- FastAPI and REST APIs
- Automated testing with pytest
- React and TypeScript
- Web3 and smart contracts
- Documentation and product research

You do not need to know everything. Clear communication and a willingness to learn matter more than a long CV.

## First milestone

Build a policy engine that can:

1. Reject transactions above a configured per-transaction limit.
2. Reject transactions that exceed a daily spending limit.
3. Reject recipients not present in an allowlist.
4. Return an explicit ALLOW or DENY decision with a reason.
5. Pass automated tests for allowed and rejected cases.

## How to get involved

1. Read the project README.
2. Choose a small, clearly scoped issue, preferably one labelled `good first issue`.
3. Comment on the issue before starting work so we can coordinate.
4. Create a branch and keep the pull request focused on that issue.
5. Run `python -m pytest` locally and add or update tests whenever behaviour changes.
6. Submit a pull request explaining the change and the tests you ran.

If an issue already has an open pull request or another contributor has
claimed it, choose a different issue instead. Browse the current [good first
issues](https://github.com/demiurge105-code/agentguard/labels/good%20first%20issue)
for available starter tasks; issue availability can change, so check its status
and discussion before beginning.

## Local setup

AgentGuard requires Python 3.10+. From the repository root:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS / Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

## MVP conventions

- Use `Decimal` or decimal strings for monetary values; never use `float`.
- Keep the MVP simulation-only: no private keys, wallet signing, RPC calls, or blockchain transactions.
- Preserve the documented deterministic rule order unless the corresponding documentation and tests are updated in the same PR.

## Working agreement

AgentGuard currently has no funding and offers no salary or guaranteed future compensation. Participation is voluntary and collaborative. Agree on responsibilities, expected time commitment, attribution, and ownership before taking on substantial work. Do not assume that future equity, tokens, grants, or payment are guaranteed.

## Security rules

- Never commit private keys, seed phrases, passwords, or API secrets.
- Do not test against wallets holding real funds.
- Keep the first milestone limited to simulation and automated tests.
- Report suspected security issues privately to the project maintainer rather than publishing exploit details.

Thanks for helping build something useful.
