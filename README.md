# Local GPT MCP

A consent-first Windows desktop companion for ChatGPT-compatible MCP integrations. This repository is currently a **toolchain scaffold**. It cannot yet remotely control a computer or browser.

## Develop and verify

Prerequisites: Python 3.12+, Git, and Bash (Git Bash works on Windows).

~~~bash
./scripts/bootstrap --ci
./ci/run fast
./ci/run pr
./ci/run audit
~~~

CI reports are written to `artifacts/ci/<stage>.json`. All stages fail closed on invalid configuration, missing commands, or failed checks. PR Actions are required to pass before merge.

## Security boundary

No device or browser action will run without an explicit, locally approved, narrowly scoped, revocable session. Denial, expiration, and emergency stop are enforced on-device. The application must not bypass Windows permission prompts, secure desktops, browser security controls, or account authentication.

## Project tracking

- [Master plan](docs/MASTER_PLAN.md)
- [CI contract](docs/CHATFREEPT_CI.md)
- [Control Issue](https://github.com/Nippytime/local-gpt-mcp/issues/1)
- `dev` for integration and `main` for production

The source for reviewed, runtime-neutral CI design is [mlookhere/CI-Pipline](https://github.com/mlookhere/CI-Pipline). This project uses ChatGPT with its GitHub connector, not a secondary autonomous coding agent.
