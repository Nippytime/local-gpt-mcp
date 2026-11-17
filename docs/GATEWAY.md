# Web gateway — authenticated resource server (Issue #21)

The web-first user experience is ChatGPT Web → a public HTTPS MCP endpoint → an outbound-only, user-owned Windows agent. **This PR supplies only the first gateway contract. It does not deploy a public URL, register Windows agents, complete OAuth login, or enable remote input.**

## OAuth boundary

The cloud gateway uses the MCP Python SDK's Streamable HTTP resource-server authentication. Every HTTP MCP request must present a bearer access token issued by an **external trusted identity provider**. The gateway checks the RSA signature against the operator-pinned JWKS endpoint; the exact issuer, full \`https://.../mcp\` audience, \`iat\`, \`nbf\`, \`exp\`, verified \`sub\` account identity, client ID and \`devices:read\` scope. Missing/forged/expired/wrong-audience tokens are rejected; authentication is not taken from MCP tool arguments.

The SDK publishes RFC 9728 protected-resource metadata at \`/.well-known/oauth-protected-resource/mcp\`, and uses \`WWW-Authenticate\` on unauthorized requests. The identity provider, **not this gateway**, must publish RFC 8414 discovery, implement OAuth 2.1 authorization-code with PKCE **S256**, support suitable client registration (CIMD or DCR), honor the OAuth \`resource\` parameter and display actual user login/consent. Do not point ChatGPT at this server until those IdP requirements are met.

### Configuration

Set these three **operator-owned** environment values at the hosted service (never accept them as MCP tool inputs):

| Setting | Example shape |
| --- | --- |
| \`LOCAL_MCP_RESOURCE_URL\` | \`https://gateway.your-owned-domain.com/mcp\` |
| \`LOCAL_MCP_ISSUER_URL\` | \`https://login.your-id-provider.com\` |
| \`LOCAL_MCP_JWKS_URL\` | \`https://login.your-id-provider.com/.well-known/jwks.json\` |

The actual URLs, deployment domain and account provider have **not** been provisioned in the repository. The gateway rejects missing values and plain HTTP URLs, and pins JWKS to the issuer's hostname. No secrets, private signing keys, developer tokens, domain claims or cloud credentials are embedded in source control.

To test behind an HTTPS-terminating ingress on a **trusted** host after configuring an IdP:

\`\`\`bash
python -m uvicorn local_gpt_mcp.gateway.server:create_from_env --factory --host 127.0.0.1 --port 8000
\`\`\`

The ingress must preserve the trusted public \`Host\` and forward only HTTPS traffic. The MCP app enforces its own Host and Origin allowlists and does not create an insecure or anonymous HTTP fallback. TLS policy, trusted proxy headers, rate limiting, WAF, health checks, logging redaction, uptime and deployment credential rotation require actual hosting verification.

### Tools and tenant isolation

| MCP tool | Permission | Behavior |
| --- | --- | --- |
| \`list_my_devices\` | Verified \`devices:read\` | Lists only devices registered to the bearer token's owner identity |
| \`device_status\` | Verified \`devices:read\` | Returns own device's online/offline state; unknown and another account's device are indistinguishable |
| \`read_from_device\` | Verified \`devices:read\` and a **separately verified online agent** | Forwards only bounded, typed window/browser observations |

A device is offline by default. Enrollment and marking the device online are **internal trusted interfaces only**, not MCP tools or public HTTP endpoints. Without the independently authenticated outbound agent of [Issue #22](https://github.com/Nippytime/local-gpt-mcp/issues/22), even a validly authenticated device read fails closed. A cloud model does not receive the local pairing token, native grant token, passwords, cookies or arbitrary filesystem access.

There are **no remote write tools** in this gateway. A future remotely requested click/type/navigation needs the independent owner-presence approval of [Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23) and execution-time policy verification on the Windows device. Do not add a model-callable "enroll", "mark online" or "approve" tool.

## Verification and limits

The deterministic suites in \`tests/gateway\` cover forged/wrong-issuer/wrong-audience/out-of-time tokens, required scopes, public HTTPS configuration, cross-account device enumeration, offline denial, fake-agent read routing and HTTP OAuth challenge/metadata. The regular nine PR checks, dependency audit, coverage threshold and production release guard remain mandatory.

These tests are **not a live OAuth authorization-code flow**: identity-provider client registration, S256 login, cloud hosting, cross-user deployment, device registration, true outbound connectivity, second-device approvals and ChatGPT web use still require implementation and externally verifiable evidence. See [#21–#24](https://github.com/Nippytime/local-gpt-mcp/issues/20), [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10) and [WEB_REMOTE.md](WEB_REMOTE.md). No release blocker is closed by this PR alone.
