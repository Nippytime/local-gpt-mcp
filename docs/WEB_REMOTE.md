# Web-first remote Windows control

**Product outcome:** A user should be able to sign into ChatGPT **on the web from anywhere**, select **only their own authorized Windows PC**, request bounded local desktop/browser work, approve consequential actions **without being physically near the PC**, and receive results in the web conversation.

## What exists today and what is missing

- **Implemented on `dev`:** stdio-only MCP tool server, Windows foreground window observation/input, isolated Chromium automation, policy grants and tokens, locally displayed challenge approval, workflow checkpoints/emergency stop, hosted CI and per-user installation.
- **In progress (draft PR #19):** pinned-HTTPS outbound browser transport and release artifact provenance; two original high-risk release blockers remain open.
- **Not implemented yet:** a ChatGPT-web-accessible remote MCP endpoint, cloud account authentication, device registration, outbound agent channel, owner consent from a second location, remotely selectable PC, and an end-to-end web-to-PC test. Do **not** describe the current companion as remotely accessible.

## Connection architecture

```text
User opens ChatGPT web from anywhere
  └── installs / selects the user's OAuth-linked Local GPT MCP plugin
        └── public HTTPS Streamable HTTP /mcp gateway
              ├── OAuth 2.1 (PKCE, verified user identity, token audience/scopes)
              ├── one authenticated tenant → only the tenant's enrolled devices
              └── bounded, short-lived request/response relay
                    └── TLS outbound-only agent on the user's Windows PC
                          ├── device-bound enrollment identity
                          ├── on-device policy, foreground/lock/UAC checks
                          ├── Windows/isolated-browser adapters
                          └── revocation and visible STOP
Owner on separate trusted phone/browser
  └── independent authenticated permission / passkey confirmation
        └── per-device, per-action, per-target, single-use approval proof
              └── verified by local agent before action execution
```

The PC initiates the outbound secure connection; no user forwards ports, turns off firewalls, enables a public VNC/RDP server, or grants a cloud server local administrator privileges.

## One owner / many devices / many users

Each owner has a separately authenticated account and may enroll individually named PCs. The plugin can only list the caller's devices. Every request binds **user ID, device ID, action, exact target, timestamp, nonce and approved scope**; forwarding to another user's machine must be impossible. A PC is never controlled merely because the model guessed its device ID or the network address is known.

## Approval from anywhere

The present Windows UI asks for a typed challenge *at the PC*, which is useless if nobody is standing there. A real remote design must use a separate trusted owner-facing approval screen on a phone/browser and verify user presence, preferably via a passkey/WebAuthn flow. The agent independently verifies the resulting short-lived, single-use approval against the requested action and live grant. The ChatGPT model/MCP tool request cannot produce or override the approval proof. Denial, timeout, offline owner, wrong user, changed target and emergency stop **must deny**.

Remote approval does **not** justify bypassing Windows lock, UAC, session isolation or secure desktop. The PC must be on, connected and have a controllable logged-in interactive user session for desktop input. When unavailable, report the restriction and preserve uncertainty rather than silently replaying work.

## ChatGPT web compatibility and distribution

**Private pilot:** OpenAI [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) can connect a private **stdio** MCP server to supported ChatGPT Business/Enterprise/Edu workspaces using `tunnel-client` and an outbound HTTPS control path. This can validate tool discovery and the user experience, but does **not** provide multi-user device routing, owner-away approval, or public plugin submission.

**General web product:** Build a publicly reachable `https://<owned-domain>/mcp` Streamable HTTP server. OpenAI [requires this for a publicly submitted MCP plugin](https://developers.openai.com/plugins/build/mcp-server). Implement [OAuth 2.1 authorization code with PKCE](https://developers.openai.com/plugins/build/auth), verified bearer scopes and audience, OpenAI client identification requirements, and account-specific device selection. A remote connector is **not** the same thing as a port forwarded to the user's PC.

**Account limitations:** OpenAI's [custom MCP availability](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) states that full custom MCP write operations are currently for Business and Enterprise/Edu workspaces. Pro read/fetch availability does not imply general remote writes, and feature access is subject to workspace permissions and platform review. Do not promise identical access to every ChatGPT plan or imply app publishing is automatically approved.

## Build sequence and acceptance

1. **#20:** establish the web-first requirement, trust diagram, owner-away consent and release blocking. Required PR CI green.
2. **#21:** implement public OAuth 2.1 HTTPS MCP gateway and strict multi-tenant device authorization with fake agents.
3. **#22:** implement outbound device agent with one-time pairing, secure credential management and safe offline/reconnect semantics.
4. **#23:** implement trusted remote owner approvals and global stop, independently checked by device authority.
5. **#24:** demonstrate a real ChatGPT web tool read + remote-approved write from another location and reject wrong-user/offline/locked/UAC requests; complete public plugin review as supported.
6. **Release:** verify full CI, live DNS/network and physical Windows security, then close high-risk blockers with evidence and issue a separately audited production release.

A product is **not ready** until someone can use the actual ChatGPT web interface, away from home, to operate *their own* paired Windows PC under these security checks. The release manifest holds an additional `WEB_REMOTE_E2E` high-risk blocker so CI enforces this rather than treating a local-only build as complete.
