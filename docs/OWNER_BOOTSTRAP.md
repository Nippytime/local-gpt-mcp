# Trusted first-owner bootstrap permits (Issue #41)

**Not a public first-enrollment endpoint.** The server-side WebAuthn registration verifier (#37) and private credential store (#39) need a separate human/operator decision before the first owner can register a passkey. This slice introduces a **single-use, 180-second operator code** generated solely from a trusted local POSIX terminal. The code is shown once; only its SHA-256 digest, bound owner and expiry are stored in a private SQLite file. No HTTP or MCP tool can issue, reveal or renew the code. An OAuth bearer alone never suffices.

## Operator procedure (private gateway host)

Use an OS service account and a private **0700** directory owned by that account. Explicitly provision once:

```sh
python -m local_gpt_mcp.policy.bootstrap provision /private/owner-mcp/permits.sqlite
```

To authorize an owner's first WebAuthn browser ceremony, independently verify the owner via an out-of-band trusted operator channel, then run:

```sh
python -m local_gpt_mcp.policy.bootstrap issue /private/owner-mcp/permits.sqlite alice
```

The terminal prints a unique 43-character secret. Deliver it only to the independently identified owner, never in GitHub, logs, model messages, untrusted webpages or public support. To cancel it:

```sh
python -m local_gpt_mcp.policy.bootstrap revoke /private/owner-mcp/permits.sqlite alice
```

The owner must separately present the code to an **authenticated owner-only browser registration integration** that derives `owner` from verified OAuth, NOT a caller-supplied JSON field. The integration calls `first_owner_registration(owner=..., code=..., origin=..., permits=..., credentials=...)` and uses the returned `OperatorAuthorizedRegistration.begin/finish` WebAuthn flow. The exact signed `navigator.credentials.create()` result is verified, and the permit is atomically consumed **before** writing the owner's first public credential. If writing fails, the permit stays consumed and requires a fresh trusted operator action. Other workers cannot consume the same permit; wrong owner/code, expiry, revoked permit, missing DB, insecure file, or already-enrolled owner deny. Revoked credentials are not resurrected.

This primitive does **not** implement an authenticated owner browser registration page, owner OAuth integration, service-host hardening, physical passkey acceptance or a cloud-origin model input grant. Do not expose `issue_local` or CLI through remote routes, or enable remote Windows input from this component. Single-host private POSIX ledger only. Continue #23, #24 and #10 with real Windows, second-device and distant ChatGPT-web validation; all high-risk release blockers remain OPEN.

## Owner-only authenticated HTTP enrollment API (Issue #43)

The gateway now offers optional JSON-only `POST /api/owner/passkey/begin` and `POST /api/owner/passkey/finish` **only when a trusted deployment explicitly installs** `OwnerEnrollmentAPI` via `create_gateway(..., owner_enrollment=...)`. The production `create_from_env` remains disabled by default: no public first-passkey endpoint is enabled until the deployment supplies both independently provisioned private stores, the fixed resource/audience, and a **dedicated owner-browser OAuth client ID**. ChatGPT/MCP client identities and `devices:read` tokens cannot enroll a passkey.

The owner browser must use a separately verified OAuth session with the exact audience and `owner:enroll` scope. Its JavaScript sends the locally issued out-of-band `operator_code` to `begin`, converts the returned `options` to `navigator.credentials.create()`, and submits the resulting attestation with the opaque ceremony ID and challenge to `finish`. The server verifies browser Host, same-origin request metadata, dedicated OAuth client, owner identity and bearer-token binding; it atomically consumes the ceremony and the operator permit and stores only the verified public credential. All sensitive API responses use no-store/no-referrer headers. There is **no permit issuance endpoint**, no model-accessible MCP registration tool, no remote input permission change, and no automatic re-enrollment after revocation.

This component does not yet provide the independently audited owner login/registration UI, real third-party OAuth deployment, reverse-proxy Origin enforcement verification, cross-process ceremony coordination or physical passkey acceptance. It does **not** establish end-to-end ChatGPT web-to-PC access. Leave #23/#24/#10 and all HIGH release blockers open until the real second-device browser flow, native Windows execution-time STOP and distant ChatGPT web acceptance succeed.

## Owner browser enrollment page (Issue #45)

The fixed, owner-only WebAuthn begin/finish API from Issue #43 now has a **separately opt-in browser page** at `/owner/enroll`. To enable, the trusted deployment must explicitly construct `OwnerEnrollmentAPI` with its **independently provisioned** operator permit ledger and owner passkey store, the exact gateway OAuth verifier, and a dedicated owner-browser OAuth client; it must pass both `owner_enrollment=...` and `enrollment_page=OwnerEnrollmentPageConfig(...)` to `create_gateway`. The default `create_from_env` deliberately does not enable either feature.

The page uses OAuth authorization-code + PKCE S256 for an independently configured client, one-time state validation and cleanup, and an in-memory access token only. The operator separately issues the owner-scoped 180-second permit in a trusted local terminal. On the owner’s **own browser**, after successful OAuth sign-in, the owner enters the permit into a password field, which is cleared before and after submitting. The browser calls `/api/owner/passkey/begin`, invokes native `PublicKeyCredential.parseCreationOptionsFromJSON` and `navigator.credentials.create`, and sends `credential.toJSON()` to `/api/owner/passkey/finish`. No model client can issue permits or access the `owner:enroll` scope without independent OAuth authorization. No token/permit is placed in URLs, persistent storage or logs. A modern browser with these WebAuthn APIs is required; unsupported clients fail rather than downgrading to insecure registration.

The configured IdP must correctly register `https://<gateway-host>/owner/enroll` as an exact redirect URI and support its own public OAuth PKCE client and CORS-protected token exchange. Actual public IdP, deployed TLS proxy, browser authenticator, second-device owner approval, native Windows STOP and distant ChatGPT web-to-PC acceptance **have not yet been tested**. Keep Issue #23, #24, #10 and all HIGH release blockers OPEN, and keep remote actions disabled until independent physical acceptance.

## Explicit hosted owner first-passkey enrollment (Issue #49)

**Disabled unless enabled by the operator.** Existing hosted `create_from_env` exposes no passkey registration endpoint or `/owner/enroll` page by default. A trusted, **single-worker POSIX** gateway pilot can explicitly install the already-verified first-passkey API and owner PKCE browser page only after provisioning both SQLite stores once in the same private (mode 0700, service-owned) directory:

```sh
python -m local_gpt_mcp.policy.bootstrap provision /private/owner-mcp/permits.sqlite
# Provision the separate passkey store once using SQLiteCredentialStore.provision()
# as described in docs/PASSKEY_REGISTRATION.md.
```

Configure, in addition to the existing public resource, issuer and JWKS HTTPS settings:

```sh
LOCAL_MCP_OWNER_ENROLLMENT=1
LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK=1
LOCAL_MCP_OWNER_CLIENT_ID=separate-owner-browser-client
LOCAL_MCP_OWNER_AUTHORIZE_URL=https://idp.example.com/authorize
LOCAL_MCP_OWNER_TOKEN_URL=https://idp.example.com/token
LOCAL_MCP_OWNER_PERMIT_DB=/private/owner-mcp/permits.sqlite
LOCAL_MCP_PASSKEY_DB=/private/owner-mcp/passkeys.sqlite
```

The identity provider must separately register that browser client as an OAuth public PKCE client with **only** independently granted `owner:enroll`, the exact resource audience and a redirect URI of `https://<gateway-host>/owner/enroll`. Use URLs on the configured HTTPS issuer; mismatched, missing or malformed paths deny startup. At runtime a trusted operator verifies the account separately, runs the **local terminal-only** `python -m local_gpt_mcp.policy.bootstrap issue ... <owner-sub>` command, then independently gives the single-use 180-second code to that owner. No HTTP or MCP tool can issue or renew it. All database files must exist and retain private ownership/mode; startup never creates, resets or repairs them.

The in-memory WebAuthn ceremony is limited to 60 seconds and one gateway process; a restart loses uncompleted ceremonies. `LOCAL_MCP_OWNER_SINGLE_PROCESS_ACK=1` explicitly acknowledges this pilot limitation. This option does not automatically enroll a PC, authorize an action, or enable Windows input. It **does not prove** live IdP compatibility, remote owner physical user verification, resilient multi-worker coordination, native STOP/locked/UAC behavior, or actual ChatGPT-web-to-PC E2E. Leave #23/#24/#10 and all three HIGH production blockers OPEN.
