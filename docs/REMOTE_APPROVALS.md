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
