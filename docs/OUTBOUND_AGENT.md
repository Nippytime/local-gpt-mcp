# Windows outbound agent — Issue #22

This is the **device-connection implementation**, not the completed ChatGPT web remote-control product. The gateway can securely identify an enrolled PC, receive outbound heartbeat/polls, and forward a bounded *read-only* request when a trusted local read executor has separately authorized it. **No remote input, terminal, UAC, lock-screen unlock, password retrieval, inbound TCP listener, port forwarding or automatic local approval exists.**

## Owner enrollment

The gateway's external OAuth identity provider first authenticates the owner with \`devices:manage\` scope. The owner makes an authenticated **non-MCP** request to \`POST /api/owner/enrollments\` with a device \`label\`; the gateway creates a random single-use, 180-second enrollment code and associated unique device ID. Codes are bound to that **verified OAuth account**, and never exposed through an MCP tool.

On the owner's Windows PC, in an **interactive standard-user session**:

\`\`\`powershell
local-gpt-agent --gateway https://YOUR-OWNED-GATEWAY.example --pair
\`\`\`

Enter the device ID and secret from the trusted owner portal. The agent generates its own Ed25519 keypair locally and sends only its public key plus the one-time code. The gateway consumes the code once, pins the public key to that owner/device, and defaults the new device to **offline**. The private key is stored with Windows user-scoped DPAPI encryption in \`%LOCALAPPDATA%\LocalGPTMCP\device-identity.json\`, never uploaded as plaintext. An existing identity cannot be silently overwritten. A failed save after enrollment requires explicit owner revocation/re-enrollment.

## Start / stop outbound-only session

\`\`\`powershell
local-gpt-agent --gateway https://YOUR-OWNED-GATEWAY.example --run
\`\`\`

The agent initiates **HTTPS-only POST** calls to the trusted gateway. Device ID, short-lived timestamp, random request nonce, exact endpoint path and body hash are covered by Ed25519 signatures. The gateway verifies the matching enrolled public key, freshness and one-time nonce before dispatch. It returns only a single bounded read job, which is never automatically replayed, and accepts its signed result once. Response size, queue depth and timeouts are bounded.

The agent polls periodically with capped reconnect backoff. Press Ctrl+C or stop the process locally to disconnect. No Windows service, scheduled task, automatic startup or firewall rule is installed here. The Windows PC must remain powered on, connected, unlocked and within an interactive user desktop to perform Windows input. The cloud cannot bypass Windows lock, UAC or secure desktop restrictions.

### Local authorization remains mandatory

The gateway does not grant native OS permissions. The default agent read executor is **deny-all**. A local integration must supply a trusted executor that checks the exact browser origin or HWND through the existing \`SessionBroker\`/desktop/browser controllers and previously approved local grants **immediately before each read**. The fake executor in CI is for test fixtures only.

A user who is actually away from home will need the independent owner-presence remote approval provider of [Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23). Until it is implemented and integrated into on-device policy, this transport deliberately **cannot run remote write actions** and does not deliver the final web-to-PC experience.

### Operator/API contract

The gateway's \`create_gateway(..., relay=AgentRelay())\` enables the following API endpoints alongside authenticated Streamable HTTP MCP:

| Authenticator | HTTP endpoint | Result |
| --- | --- | --- |
| Owner bearer OAuth, \`devices:manage\` | \`POST /api/owner/enrollments\` | Single-use device claim; not callable by MCP model tools |
| Owner bearer OAuth, \`devices:manage\` | \`POST /api/owner/revoke\` | Revoke enrolled public key; reject queued/future work |
| One-time owner code (new device) | \`POST /api/agent/enroll\` | Bind public key to the authenticated owner's pending claim |
| Ed25519 device signature | \`POST /api/agent/poll\` | Heartbeat and one pending *read-only* operation |
| Ed25519 device signature | \`POST /api/agent/result\` | Return a bounded observation, never an arbitrary command |

Every public API is fixed to an operator-owned HTTPS host; invalid bearer tokens, unknown devices, cross-account reads, expired/replayed signatures and code reuse fail closed. The model cannot invoke enrollment, owner revoke or remote approval tools. Owner OAuth tokens are not valid device signatures and device keys are not valid owner OAuth tokens.

## Security/operational limitations

- **No cloud deployment or public hostname configured yet.** The identity-provider flow, production storage, rate limiting, health monitoring, TLS proxy/Host handling and actual ChatGPT web plugin link require independently verified hosting and accounts. In-process CI integration is not a live internet connection.
- Gateway enrollments, nonce replay cache, device registration and queues are currently **single-process in memory**, so restarts invalidate them and production multi-instance routing is not safe. Persistent data store, transactional single-use codes, distributed replay enforcement, secure key rotation and a full owner pairing UI remain prerequisites to public deployment.
- Real Windows DPAPI access, sleep/reconnect, trusted UI approvals, lock/UAC refusal, and device emergency stop require human/physical Windows acceptance. Hosted Windows package tests cannot substitute.
- Genuine remote user consent, passkey action binding and globally authenticated stop are **Issue #23**, and real ChatGPT web-to-remote-Windows proof and plugin review are **Issue #24**. Existing DNS egress, physical Windows and remote E2E blockers in \`security/release_blockers.json\` remain OPEN.

Do **not** mark release Complete or merge to \`main\` merely because this agent's fake-cloud tests and nine integration checks pass.
