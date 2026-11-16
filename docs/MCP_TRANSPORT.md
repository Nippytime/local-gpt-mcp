# MCP transport and locally approved pairing

The transport uses the official Python MCP SDK v2.3 with the local **stdio** transport. The SDK handles MCP protocol negotiation (2026-07-28 and older), JSON-RPC validation, tool/resource discovery and schema generation. No HTTP listener, remote connection or Windows application control is enabled.

## Local host

After `./scripts/bootstrap --ci`, launch the server as a **local MCP subprocess**:

```bash
python -m local_gpt_mcp --stdio
```

The local MCP host must speak protocol messages through stdio, not treat stdout as ordinary shell output. A browser-only ChatGPT tab cannot spawn a desktop subprocess. Supporting remote ChatGPT access will require an approved authenticated connector/tunnel and a local UI in later items.

## Pairing and grants

1. `session_open(user_id, device_id, client_nonce)` requires a fresh 16–32 byte hexadecimal nonce. The server shows a human the claimed user/device and a random challenge on the **actual interactive console** (never MCP stdin/stdout). The human types the indicated `APPROVE` challenge, or denies.
2. Pairing returns a random bearer session token and session ID. Sessions expire after five minutes. Pairing attempts, session count and request rates are bounded.
3. Every authenticated tool call requires its session bearer and a fresh random nonce. Replayed nonces and unknown or expired tokens are rejected.
4. `session_request_grant` prompts the local human again for the target, capabilities and expiry, then returns a grant bound to the exact session and limited by the remaining session lifetime.
5. `session_revoke_grant`, `session_close`, and `session_emergency_stop` revoke authority. Future device adapters must check `SessionBroker.authorize_grant` immediately before every action.

A public `local-gpt://about` resource reveals only static non-sensitive capabilities. No OS-control tools or credentials exist in this delivery item.

## Security and usability limits

Without an interactive TTY or Windows console, local approval fails **closed**. There is no environment variable, stdin, silent approval or auto-accept override. Console prompts are the first verifiable user-controlled mechanism; an accessible tray UI is scheduled for Issue #8.

MCP 2026-07-28 made the **protocol** sessionless; this companion's short-lived authorization sessions are independent of the removed protocol session IDs. Remote HTTP transport is deliberately unavailable until host and origin validation, authentication, DNS rebinding resistance and explicit opt-in are verified.
