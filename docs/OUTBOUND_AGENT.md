# Windows outbound agent — Issue #22

This document originally described the **read-only Issue #22 device-connection slice**, not a complete ChatGPT web-to-PC deployment. The currently integrated agent still defaults to deny-all reads, but an **explicitly enabled** `--run-approved-input` mode now supports only one locally selected `window.click` with separate owner OAuth/WebAuthn approval and native signed-receipt/policy verification. No general remote typing, shell, UAC/lock-screen control, password retrieval, inbound TCP listener, port forwarding, unattended permission or automatic local approval exists. Public hosting, actual login, passkey and cross-location ChatGPT Web tests remain unverified: see [WEB_REMOTE.md](WEB_REMOTE.md).

## Owner enrollment

The gateway's external OAuth identity provider first authenticates the owner with `devices:manage` scope **and the exact operator-pinned, separate owner-browser OAuth client identity**. A model OAuth client cannot use this endpoint even if it receives an elevated scope. The owner makes an authenticated **non-MCP** request to \`POST /api/owner/enrollments\` with a device \`label\`; the gateway creates a random single-use, 180-second enrollment code and associated unique device ID. Codes are bound to that **verified OAuth account**, and never exposed through an MCP tool.

On the owner's Windows PC, in an **interactive standard-user session**:

\`\`\`powershell
local-gpt-agent --gateway https://YOUR-OWNED-GATEWAY.example --pair
\`\`\`

Enter the device ID and secret from the trusted owner portal. The agent generates its own Ed25519 keypair locally and sends only its public key plus the one-time code. The gateway consumes the code once, pins the public key to that owner/device, and defaults the new device to **offline**. The private key is stored with Windows user-scoped DPAPI encryption in \`%LOCALAPPDATA%\LocalGPTMCP\device-identity.json\`, never uploaded as plaintext. An existing identity cannot be silently overwritten. A failed save after enrollment requires explicit owner revocation/re-enrollment.

## Start / stop outbound-only session

\`\`\`powershell
local-gpt-agent --gateway https://YOUR-OWNED-GATEWAY.example --run
\`\`\`

The agent initiates **HTTPS-only POST** calls to the trusted gateway. Device ID, short-lived timestamp, random request nonce, exact endpoint path and body hash are covered by Ed25519 signatures. The gateway verifies the matching enrolled public key, freshness and one-time nonce before dispatch. Default `--run` handles at most one bounded read request with a deny-first executor; a separately opted-in and physically authorized `--run-approved-input` session may instead handle one owner-passkey-approved signed `window.click`. Uncertain results are never silently retried. Response size, queue depth and timeouts are bounded.

The agent polls periodically with capped reconnect backoff. Press Ctrl+C or stop the process locally to disconnect. No Windows service, scheduled task, automatic startup or firewall rule is installed here. The Windows PC must remain powered on, connected, unlocked and within an interactive user desktop to perform Windows input. The cloud cannot bypass Windows lock, UAC or secure desktop restrictions.

### Local authorization remains mandatory

The gateway does not grant native OS permissions. The default agent read executor is **deny-all**. A local integration must supply a trusted executor that checks the exact browser origin or HWND through the existing \`SessionBroker\`/desktop/browser controllers and previously approved local grants **immediately before each read**. The fake executor in CI is for test fixtures only.

The independent owner-presence approval provider, conditional remote action relay and on-device single-use receipt verification of [Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23) are now **source integrated but default-OFF**. The operator may opt in with a separately provisioned owner passkey, gateway issuer and local safety panel; no MCP client can approve its own request. A trusted `window.click` is the **only** supported remote write and requires an unlocked, foreground selected window. Neither hosted CI nor a local test proves real owner-away use; this still does **not** deliver a verified ChatGPT web-to-PC experience.

### Explicitly locally authorized remote click (later #23 integration)

A one-time local setup is still required **at the PC before leaving**. The owner signs into a separately configured owner OAuth browser, registers a passkey with a trusted operator permit, and pairs the device with a single-use code. The PC operator independently pins the gateway Ed25519 **public** issuer key as `owner-issuer.pub` in the protected local identity directory and starts:

```powershell
local-gpt-agent --gateway https://gateway.example.com --run-approved-input --owner-id OWNER_SUB --window-handle HWND
```

This opens a real Windows safety panel with typed local pairing/grant challenges. Remote `request_device_click` requests go to a separate owner browser for WebAuthn user verification; the PC checks an issuer-signed, exact device/session/target/action, single-use receipt and foreground/window/STOP policy again before executing. `--run` alone stays deny-all, and no automatic boot service or unattended unlocking is installed. See [current pilot requirements](WEB_REMOTE.md) and [physical Windows acceptance](WINDOWS_ACCEPTANCE.md). This capability has not been verified from another location in the real ChatGPT web product.

### Operator/API contract

The gateway's \`create_gateway(..., relay=AgentRelay())\` enables the following API endpoints alongside authenticated Streamable HTTP MCP:

| Authenticator | HTTP endpoint | Result |
| --- | --- | --- |
| Verified owner OAuth `devices:manage` and dedicated owner-client pin | `POST /api/owner/enrollments` | Single-use device claim; not callable by MCP model tools |
| Verified owner OAuth `devices:manage` and dedicated owner-client pin | `POST /api/owner/revoke`, `POST /api/owner/halt` | Revoke enrolled key or persist owner STOP with the protected ledger |
| One-time owner code (new device) | \`POST /api/agent/enroll\` | Bind public key to the authenticated owner's pending claim |
| Ed25519 device signature | `POST /api/agent/poll` | Heartbeat and one pending read or explicit trusted remote click; default executor denies |
| Ed25519 device signature | \`POST /api/agent/result\` | Return a bounded observation, never an arbitrary command |

Every public API is fixed to an operator-owned HTTPS host; invalid bearer tokens, unknown devices, cross-account reads, expired/replayed signatures and code reuse fail closed. The model cannot invoke enrollment, owner revoke or remote approval tools. Owner OAuth tokens are not valid device signatures and device keys are not valid owner OAuth tokens.

## Security/operational limitations

- **No cloud deployment or public hostname configured yet.** The identity-provider flow, production storage, rate limiting, health monitoring, TLS proxy/Host handling and actual ChatGPT web plugin link require independently verified hosting and accounts. In-process CI integration is not a live internet connection.
- Pending requests, one-time enrollment codes and owner challenges remain **single-process** and may expire on restart; there is no supported multi-worker distributed coordinator. When explicitly provisioned, the private POSIX STOP ledger retains stopped/revoked devices, enrolled public keys and nonce replay decisions across restarts. It is **not** a distributed multi-host release deployment. Never treat a restarted in-memory queue as an authorized replay or assume horizontal scaling is safe.
- Real Windows DPAPI access, sleep/reconnect, trusted UI approvals, lock/UAC refusal, and device emergency stop require human/physical Windows acceptance. Hosted Windows package tests cannot substitute.
- The independent owner-passkey approval and durable STOP primitives for [Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23) are implemented as default-OFF source, but **physical owner/device acceptance is not verified**. Real ChatGPT web-to-remote-Windows proof and any required platform/plugin review remain [Issue #24](https://github.com/Nippytime/local-gpt-mcp/issues/24). All three HIGH DNS egress, physical Windows and remote E2E blockers remain OPEN.

Do **not** mark release Complete or merge to \`main\` merely because this agent's fake-cloud tests and nine integration checks pass.
