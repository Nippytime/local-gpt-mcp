# Remote owner receipts — Issue #23 (first security boundary)

This initial change is **only the device-side signed approval verifier**, not a finished phone portal, WebAuthn/passkey ceremony, or remotely enabled input. Do not call it owner-present until an independently authenticated owner service has approved the *exact* pending action.

- A verifier must receive a **locally pinned Ed25519 public key**, a trusted user-owned SQLite replay database and an emergency-stop callback. None may come from a ChatGPT tool argument, untrusted web page, or remote request. Missing configuration must deny.
- Receipts bind verified account, paired device, session, exact native target, capability, canonical hash of the specific action parameters, 128-bit single-use nonce, issued-at time and expiry. Every changed field or signature mismatch rejects the action. Max lifetime is 60 seconds.
- SQLite transactionally consumes nonce before dispatch. Reopening the same replay database after an agent restart still rejects the same receipt. A local STOP denies both before and after consumption; **the native executor still must check PolicyAuthority, foreground/lock/UAC/target and STOP immediately before each effect**.
- No typed text, secret, cookie, browser token, or screenshot is stored in the replay table (nonce and expiry only). Receipt data may contain a target; do not log or expose it to untrusted callers.
- `issue_testable_receipt` is a signing primitive for deterministic security tests and a future independently trusted issuer. Its presence **does not assert owner presence** and must never be registered as an MCP tool or public unauthenticated endpoint.

## Mandatory integration before remote input

1. A **separate authenticated phone/browser UI** must challenge for a concrete pending device action and verify owner presence (prefer WebAuthn/passkey UV); not accept approval from MCP, a model-controlled tab or its bearer token. The trusted issuer signs only after that ceremony.
2. Bind the receipt to a short-lived, tenant-scoped relay job; the Windows process must verify it against the *live* local policy and native target. No remote click/type/navigation can be attempted when the owner is offline, approval is absent, or the computer is locked.
3. Implement server-side revocation/STOP and reliable cancellation of queued and in-flight work; renew only through a fresh owner approval. Lost acknowledgments must not replay uncertain input.
4. Test malicious issuer/key substitution, spoofed user/device/session, changed action/target, replay across restarts, expiry, concurrent STOP, browser/phone user presence, Windows lock/UAC, lost connectivity and real cross-location ChatGPT web invocation.

No public HTTP write or approval endpoint is added by this first commit. Existing high-risk release blockers remain **OPEN**. The complete live two-device flow is required before Issue #23 can close, and actual ChatGPT web operation remains Issue #24.


## Verified user-presence building block (active PR #28)

`policy/owner_presence.py` now provides a **trusted service-side ES256 WebAuthn assertion verifier**, not a web login/registration endpoint. Owner and passkey are enrolled via `register_trusted` only by a trusted operator integration. The issuer receives an owner identity from an independently verified caller, binds a single short-lived challenge to a pending `ScopedAction` and registered credential, then checks the actual browser's `webauthn.get` signed assertion against:

- exact HTTPS approval origin and relying-party SHA-256 hash; exact server-held challenge, `webauthn.get` client-data type and no cross-origin assertion;
- required user-presence (UP) **and** user-verification (UV) authenticator flags, P-256 ECDSA signature, monotonic nonzero sign counter, one-attempt challenge consumption and expiration;
- owner/credential binding and emergency-stop checks before producing a 30-second exact-action receipt. The device still checks the separately pinned receipt issuer and nonce database.

Deterministic tests generate real P-256 signatures and reject forged keys, foreign origins, missing UV, stale challenges, counter rollback and consumed challenges. **No browser registration ceremony, production durable credential/counter storage, independently authenticated phone UI, trusted pending-relay-job linkage, native input wiring, real two-device session, or deployable hosting is claimed by this unit.** Never expose `begin`, `finish`, `register_trusted` or the receipt signer as MCP tools. Model-controlled web content cannot be treated as the trusted approval UI.


## Trusted pending job and OAuth-owner API prototype — PR #28

The `OwnerApprovalQueue` allows only **trusted, in-process relay code** to enqueue a job bound to owner, device, session, job ID, target, capability, and the canonical hash of the **actual** action operation/parameters. The owner cannot generate an arbitrary job from an HTTP request, choose its target/parameters at approval time, or retrieve the receipt from the owner-facing API. A 60-second bound, single WebAuthn challenge, exact job matching, one-time trusted receipt pickup, explicit deny, bounded pending capacity and owner-queue halt are enforced in the prototype.

`create_gateway(..., approvals=...)` optionally enables separate owner OAuth endpoints. It is **disabled by default** on the production `create_from_env` entry point until an independently authenticated owner portal and durable store are configured. These endpoints are not MCP tools:

| Endpoint | Scope | Behavior |
| --- | --- | --- |
| `GET /api/owner/approvals` | `approvals:manage` | Owner-only pending exact action details, no receipts |
| `POST /api/owner/approvals/begin` | `approvals:manage` | Challenge for an existing owner job and pre-enrolled passkey |
| `POST /api/owner/approvals/finish` | `approvals:manage` **plus real passkey UP+UV assertion** | Authorize the precise pending job, returns acknowledgement only |
| `POST /api/owner/approvals/deny` | `approvals:manage` | Cancel the specific pending job |
| `POST /api/owner/approvals/halt` | `approvals:manage` | Cancel future approvals for this process/owner (not yet the native STOP) |

Host/Origin checks, bounded request bodies, `Cache-Control: no-store`, and denial when the passkey or job is absent are required. Only the trusted device delivery seam `take_trusted` can retrieve a proof after verified owner presence; it is **not** an HTTP/MCP endpoint and is not yet integrated into signed agent polls. No public HTTP write/approval app is deployed, and no user should treat this as a production approval portal. Remaining work: production passkey enrollment and storage, OAuth PKCE browser integration, per-job real device/action creation, native STOP and execution-time verification on Windows, actual remote phone test and three release blockers.


### Signed action transport (work in progress)

The opt-in `RemoteActionRelay` now binds a server-trusted pending action to a randomly generated job ID, an existing authenticated device heartbeat, owner/device/session, a strict `window.click` argument allowlist and a separate owner WebAuthn approval queue. **No action is sent on a signed device poll until passkey approval succeeds.** Once approved, a receipt is removed from the owner queue and delivered **once** to the authenticated device at `POST /api/agent/actions/poll`; a matching bounded device-key-signed `POST /api/agent/actions/result` is the only accepted reply. Missing approval, foreign identity, expired job, offline device, revocation or owner halt deny. The job expires after 60 seconds; an uncertain remote input must never be retried automatically.

This is a **transport-only** integration. The default `create_from_env` does NOT install the action endpoints, does NOT register an MCP write tool, and existing outbound agents do NOT execute actions. An agent-side receipt/nonce verifier with locally paired authority and native Windows safety checks remains mandatory before enabling any remote execution.
