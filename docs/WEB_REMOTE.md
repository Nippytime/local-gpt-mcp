# Web-first remote Windows control

**Product outcome:** A user should be able to sign into ChatGPT **on the web from anywhere**, select **only their own authorized Windows PC**, request bounded local desktop/browser work, approve consequential actions **without being physically near the PC**, and receive results in the web conversation.

## Implementation versus actual availability — November 17, 2026

**Source integrated into `dev` (tested, not publicly deployed):** OAuth-protected Streamable HTTP MCP gateway and tenant-scoped device tools; opt-in owner enrollment and a durable private STOP ledger; outbound-only Windows agent with signed device requests, DPAPI identity, and default-deny local reads; separate owner-browser OAuth PKCE and WebAuthn registration/approval; single-use signed action receipts verified again by the PC; visible Windows STOP and one selected-window `window.click` when explicitly enabled. The bounded pinned-HTTPS browser transport, real Chromium egress regressions, and reproducible release evidence are also integrated. Read-only is the default; approvals and remote input are **OFF unless deliberately configured and physically authorized**. All source changes require nine named CI checks.

**Not delivered or demonstrated:** a user-owned public HTTPS deployment, real external IdP and ChatGPT workspace registration, independently exercised physical phone/passkey, and an end-to-end ChatGPT Web call from another location to a real Windows PC. The backend retains explicit **single-process/single-worker pilot** restrictions. Automatic PC startup, unattended lock-screen input, elevated/UAC control, generalized remote typing or arbitrary shell actions are **not** part of the present contract. Actual feature entitlement and plugin review depend on the ChatGPT account/workspace and current platform support. Neither CI nor a source-level gateway qualifies as a working service for users.

**Release hold:** [Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10), [Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23), and [Issue #24](https://github.com/Nippytime/local-gpt-mcp/issues/24) remain open; the matching draft PRs #19/#28 remain unmerged. `DNS_REBINDING_TOCTOU`, `PHYSICAL_WINDOWS_ACCEPTANCE`, and `WEB_REMOTE_E2E` are all HIGH, OPEN, evidence empty. Production `main` must not advance until actual acceptance.

## Private end-to-end pilot setup (not production instructions)

1. **Establish separate trust identities.** Own a public HTTPS hostname for `https://gateway.example.com/mcp` and a real OAuth issuer/JWKS; register the ChatGPT integration and a **different owner-browser public PKCE client**, each with its own exact redirect URI, audience, and least-privilege scopes. Confirm the intended ChatGPT account/workspace currently supports the required MCP write tools **before** testing remote clicks. Never use an MCP/model token as an owner-approval credential.
2. **Provision only on a trusted POSIX gateway host.** Create a private service-owned mode-0700 directory and explicitly provision the durable STOP ledger, operator permit ledger, P-256 public-credential database, and Ed25519 issuer key as described in [OWNER_BOOTSTRAP.md](OWNER_BOOTSTRAP.md), [PASSKEY_REGISTRATION.md](PASSKEY_REGISTRATION.md), [DURABLE_STOP.md](DURABLE_STOP.md), and [the issuer provisioning CLI](../src/local_gpt_mcp/gateway/issuer_keys.py). Do not commit or log secrets. Set `LOCAL_MCP_RESOURCE_URL`, `LOCAL_MCP_ISSUER_URL`, `LOCAL_MCP_JWKS_URL`, `LOCAL_MCP_STOP_DB`, `LOCAL_MCP_OWNER_CLIENT_ID`, `LOCAL_MCP_OWNER_AUTHORIZE_URL`, `LOCAL_MCP_OWNER_TOKEN_URL`, `LOCAL_MCP_PASSKEY_DB`, `LOCAL_MCP_OWNER_PERMIT_DB`, and `LOCAL_MCP_APPROVAL_SIGNER_FILE` to the actual operator-controlled values.
3. **Explicitly opt into one-worker pilot flows.** Only after provisioning and independent security review, set `LOCAL_MCP_OWNER_ENROLLMENT=1`, `LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK=1`, `LOCAL_MCP_REMOTE_APPROVALS=1`, and `LOCAL_MCP_REMOTE_SINGLE_PROCESS_ACK=1`. A missing private database, signing key, durable STOP ledger, pinned issuer identity or acknowledgment must fail startup. Use a real hardened HTTPS ingress that preserves the public Host header, and keep the gateway internal process bound to loopback. Do not forward a Windows PC port or run a public unauthenticated remote desktop.
4. **Independently enroll an owner passkey.** A trusted operator verifies the owner out of band and generates a **single-use short-lived permit locally** (never from the model). The owner visits `/owner/enroll` on their own device, signs in via the independent owner PKCE flow and finishes WebAuthn registration. Verify that the public credential is stored under the correct owner and cannot be re-registered after revocation. Use `/owner/approve` on a separate trusted device for later action approvals.
5. **Pair the actual Windows PC locally.** In a non-administrator interactive Windows session, obtain the device ID and single-use enrollment code through the independently authenticated owner-management flow. Run `local-gpt-agent --gateway https://gateway.example.com --pair`. Independently compare the gateway issuer **public key**, then install the verified public pin as `owner-issuer.pub` in that Windows user's protected agent identity directory. Never copy the issuer private key or let the model provide the pin.
6. **Start the safe outbound session while physically present.** Choose the exact current Windows foreground handle and verified OAuth owner ID; run `local-gpt-agent --gateway https://gateway.example.com --run-approved-input --owner-id OWNER_SUB --window-handle HWND`. The PC displays its local safety panel and demands local pairing/grant approval. The selected window must stay eligible and Windows unlocked; STOP, UAC/secure desktop and disconnection must deny, not auto-replay. The simpler `--run` mode stays deny-first and does not grant remote clicks.
7. **Verify from another physical location.** Connect the supported ChatGPT Web MCP integration to `https://gateway.example.com/mcp`, authenticate as the device's owner, list only that owner's PC, perform a limited authorized read, request one `window.click`, complete the **separate owner passkey approval on their trusted device**, and verify the target-window result. Also test wrong owner, offline PC, rejected/expired approval, changed target, reused receipt, STOP, locked desktop, UAC and uncertain result. A CI fake or private tunnel is not an acceptable substitute for [Issue #24](https://github.com/Nippytime/local-gpt-mcp/issues/24).
8. **Record independently reviewable evidence.** Run the [physical Windows smoke collector](WINDOWS_ACCEPTANCE.md) on the real PC and record redacted operator/environment outcomes, actual OAuth/ChatGPT connector readiness and network egress findings in the existing Issues. Only an external human/security audit can clear the three HIGH blockers; no script or GitHub check auto-closes them.

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

The initial Windows setup still asks for a typed challenge *at the PC*, so physical first-time pairing is mandatory. The separately opt-in owner browser approval page (`/owner/approve`) and WebAuthn assertion verifier are now present in `dev`, but require a trusted externally deployed IdP, correctly provisioned owner passkey and real second-device verification. Once locally paired and running, the agent independently verifies the resulting short-lived, single-use approval against the exact requested action and live grant. The ChatGPT model/MCP tool request cannot produce or override the approval proof. Denial, timeout, offline owner, wrong user, changed target and emergency stop **must deny**.

Remote approval does **not** justify bypassing Windows lock, UAC, session isolation or secure desktop. The PC must be on, connected and have a controllable logged-in interactive user session for desktop input. When unavailable, report the restriction and preserve uncertainty rather than silently replaying work.

## ChatGPT web compatibility and distribution

**Private pilot:** OpenAI [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) can connect a private **stdio** MCP server to supported ChatGPT Business/Enterprise/Edu workspaces using `tunnel-client` and an outbound HTTPS control path. This can validate tool discovery and the user experience, but does **not** provide multi-user device routing, owner-away approval, or public plugin submission.

**General web product:** Build a publicly reachable `https://<owned-domain>/mcp` Streamable HTTP server. OpenAI [requires this for a publicly submitted MCP plugin](https://developers.openai.com/plugins/build/mcp-server). Implement [OAuth 2.1 authorization code with PKCE](https://developers.openai.com/plugins/build/auth), verified bearer scopes and audience, OpenAI client identification requirements, and account-specific device selection. A remote connector is **not** the same thing as a port forwarded to the user's PC.

**Account limitations:** OpenAI's [custom MCP availability](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt) states that full custom MCP write operations are currently for Business and Enterprise/Edu workspaces. Pro read/fetch availability does not imply general remote writes, and feature access is subject to workspace permissions and platform review. Do not promise identical access to every ChatGPT plan or imply app publishing is automatically approved.

## Build sequence and acceptance

1. **#20:** establish the web-first requirement, trust diagram, owner-away consent and release blocking. Required PR CI green.
2. **#21:** implement public OAuth 2.1 HTTPS MCP gateway and strict multi-tenant device authorization with fake agents.
3. **#22 — integrated:** outbound device agent with one-time pairing, secure credential management and safe offline/reconnect semantics; default-deny local executor.
4. **#23 — source integrated, physical acceptance OPEN:** independent owner WebAuthn approval and signed, scoped remote `window.click` checked again by native policy; operator runbook remains in draft PR #28.
5. **#24 — externally unverified:** demonstrate a supported real ChatGPT web tool read + owner-passkey-approved click from another location and reject wrong-user/offline/locked/UAC requests; complete connector/plugin review only where actually supported.
6. **Release:** verify full CI, live DNS/network and physical Windows security, then close high-risk blockers with evidence and issue a separately audited production release.

A product is **not ready** until someone can use the actual ChatGPT web interface, away from home, to operate *their own* paired Windows PC under these security checks. The release manifest holds an additional `WEB_REMOTE_E2E` high-risk blocker so CI enforces this rather than treating a local-only build as complete.



## Dedicated OAuth client for owner device management (Issue #47)

The `POST /api/owner/enrollments`, `/api/owner/revoke`, and `/api/owner/halt` endpoints are **independent owner-management interfaces**, not ChatGPT MCP tools. They now require a verified OAuth bearer containing the exact `devices:manage` scope **and** a configured, exact-match owner browser OAuth client identity. Deployments should register an independently consented browser client at the trusted IdP and configure its nonsecret identifier as `LOCAL_MCP_OWNER_CLIENT_ID`. With no owner client configured, all three owner-management endpoints deny even a valid broad-scope bearer; signed outbound device poll/result remain available to already-enrolled and locally authorized devices. This prevents an MCP/model OAuth client accidentally granted `devices:manage` from generating device enrollment codes or initiating owner HALT.

The client pin is not a passkey assertion or proof of physical ownership. Do not reuse the ChatGPT/model client ID as the owner browser ID, and do not make this setting caller-controlled. Real owner OAuth, native Windows STOP/lock/UAC and distant ChatGPT web-to-PC acceptance remain mandatory and unverified.
