# Local GPT MCP

A consent-first Windows companion that will let users **control their own PC from ChatGPT on the web, wherever they are**.

**Status:** The existing local Windows/browser MCP execution engine is implemented in `dev`, but **web-to-PC remote access is not implemented**. The current local stdio transport needs an authenticated HTTPS gateway, an outbound-only device agent, and remote owner approval before the user can work on a PC while away. The release is blocked until real remote end-to-end and physical Windows tests pass.

See [web-first product architecture](docs/WEB_REMOTE.md) and [Issue #20](https://github.com/Nippytime/local-gpt-mcp/issues/20).

## Target user experience

1. Install and pair the Windows agent to your own verified account.
2. Leave the PC powered on, online, and in a controllable user session.
3. Open ChatGPT **web** from another location and authorize the companion plugin.
4. Select your own paired PC and request a bounded read or action.
5. Approve consequential actions on a **trusted remote browser/phone**, independently of the model. Denial or emergency stop works remotely.
6. Receive results in ChatGPT. An offline, locked, UAC, or secure-desktop PC must safely refuse interactive actions.

ChatGPT web currently supports full custom-MCP actions for eligible Business/Enterprise/Edu workspaces; plan and workspace permissions still apply. No existing account is automatically entitled to remote-write tools. A private Secure MCP Tunnel can pilot the connection, but public distribution needs a stable HTTPS MCP server with OAuth.

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
