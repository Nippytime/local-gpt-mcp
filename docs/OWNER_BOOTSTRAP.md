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
