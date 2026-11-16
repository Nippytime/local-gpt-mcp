# Local authorization security boundary

The local companion has no device-control capability in its scaffold state. The policy authority added in Issue #3 defines the rules that future MCP tool adapters must enforce.

- **Two explicit on-device approvals:** pairing a specific person and device, then authorizing a session-specific capability and target. No UI provider means deny all. The approval provider must be wired exclusively to a trusted, visible local UI; never expose it as a remote MCP method.
- **Scoped grants:** opaque cryptographically random 256-bit bearer tokens are only valid for the approved person, device, session, exact target, capabilities and TTL of 1–600 seconds. Browser scopes are HTTPS origins without paths, credentials, fragments or queries; window scopes refer to specific positive handles.
- **Fail closed:** missing pairing, denial, expired/unknown/altered grants, mismatched caller, mismatched target or capability and emergency stop reject actions. Every action must call policy authorization immediately before execution; cached decisions are not valid.
- **Stop and revoke:** individual tokens and pairings are revocable. Emergency stop is permanent for the current authority instance; restoring operation requires a freshly created authority and new on-device approvals. Long-running adapters must also watch the stop event and cancel promptly (later integration slices).
- **Privacy:** bounded in-memory audit events record only operation, decision and reason, not tokens, typed text, screenshots, full URLs or user credentials. Durable encrypted storage and GUI controls are separate planned slices.
- **Threat model:** untrusted web content and remote MCP calls must not provide or impersonate a local approval callback. No elevation, security-dialog bypass, hidden control, or automation after denial. A window/browser adapter must verify real active target identity before every action (future slices).

Run tests with `./ci/run pr`. This policy slice alone does not expose an MCP endpoint or any desktop input function.
