# First-passkey WebAuthn registration verification core (Issue #37)

This component is a **security primitive**, not a live enrollment service. It accepts a real `navigator.credentials.create()` result only **after an independently trusted operator authorization** and consumes a 60-second owner-bound challenge exactly once. The caller must provide a `TrustedPasskeyStore` that safely persists the verified credential ID and P-256 public key, enforces unique IDs across owners, and supports revocation. It intentionally has **no MCP tool, no HTTP route, no implicit OAuth-only bootstrap**, and no default permit.

`OperatorAuthorizedRegistration` is bound to an exact public HTTPS origin/RP ID and pins WebAuthn ES256/P-256, attestation `none`, user presence and user verification. The server derives a stable non-secret user handle from the owner identity, sends browser creation options, verifies the RP hash, challenge, origin, attested public key and UV/UP using the maintained `webauthn` library, then stores **public** material only. Challenges expire on service restart and never persist as blanket permissions.

**Next integration steps:** implement a separate operator-trusted initial authorization mechanism (verified before `begin` and again before `finish`), connect the existing draft PR #28 owner OAuth browser route to this class and `SQLitePasskeys`, and perform real hardware/browser credential creation plus a signed assertion on another trusted device. A verified WebAuthn `fmt:none` public key is not evidence of authenticator manufacturer provenance; this is acceptable only when independent operator bootstrap has securely established which owner is allowed to register.

Do not merge Issue #23 or release until single-use action authorization, durable emergency STOP at native PC execution time, real Windows lock/UAC/STOP testing and cross-location ChatGPT web E2E are verified. Required CI passing alone is not live owner consent evidence.

## Durable credential storage (Issue #39)

The WebAuthn registration verifier now has an independent private `SQLiteCredentialStore` backend to persist verified P-256 public keys and assertion counters. It **does not** expose any HTTP/MCP enrollment route, and does **not** grant an operator authorization. The injecting application must independently verify trusted operator authorization at both registration begin and finish. The existing Issue #23 approval draft retains its pilot store until consolidated.

Provision the backend **exactly once**, as the POSIX service user, in a private owner-owned **0700** directory (not a symlink):

```sh
python -c 'from pathlib import Path; from local_gpt_mcp.policy.credential_store import SQLiteCredentialStore; SQLiteCredentialStore.provision(Path("/private/owner-mcp/credentials.sqlite"))'
```

Normal process startup uses `SQLiteCredentialStore(Path("/private/owner-mcp/credentials.sqlite"))` and **must never create** a missing or erased database. It denies unsafe/linked/hardlinked files, incorrect ownership or access modes, missing schema and corrupt key data. The database is 0600 and contains owner ID, credential ID, P-256 public key, monotonically advancing sign count and revoked-ID tombstones **only**. An already revoked credential ID cannot be silently re-registered or assigned to a different owner. No private credential material, OAuth bearer, user password, raw assertion or action data is written.

This is a **single-host** storage primitive, not a hosted identity provider, distributed registration service or physical STOP. Credential first-use browser ceremony, independent operator bootstrap, subsequent OAuth/passkey approval linkage, native Windows lock/UAC/STOP, and actual distant ChatGPT web end-to-end remain unverified.
