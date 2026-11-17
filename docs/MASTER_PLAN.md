# Master delivery plan — Local GPT MCP

**Repository:** [Nippytime/local-gpt-mcp](https://github.com/Nippytime/local-gpt-mcp)  
**Integration:** `dev` · **Production:** `main` · **Control Issue:** [#1](https://github.com/Nippytime/local-gpt-mcp/issues/1)  
**Operating model:** ChatGPT + GitHub MCP. A single delivery Issue maps to one `work/<issue>-<slug>` branch from `dev` and one PR into `dev`. No direct integration or production changes after the documented initial bootstrap.

## Owner-directed web-first requirement — 2026-11-16

**The first publicly usable product must work from `chatgpt.com` on a remote computer, without the user sitting next to their Windows PC.** The existing nine local-execution and release slices are necessary but not sufficient. The new mandatory delivery Issues [#20](https://github.com/Nippytime/local-gpt-mcp/issues/20)–[#24](https://github.com/Nippytime/local-gpt-mcp/issues/24) define authenticated web access, the outbound agent, remote independent consent, and true end-to-end validation. Production `main` and the release guard must not be advanced until these requirements and existing high-risk blockers pass.

See [Web remote architecture](WEB_REMOTE.md). Supported account/workspace MCP write entitlements and OpenAI public-plugin review policies are external requirements; do not claim all ChatGPT plans have full custom MCP tool access.

## Outcome and technical boundaries

Build a consent-driven Windows companion that exposes **scoped desktop and browser actions** through an authenticated MCP interface suitable for ChatGPT integrations where supported. A browser page alone cannot directly control the host operating system. Native control is delivered through a locally installed, **user-authorized** companion that can maintain an **opt-in outbound authenticated connection** for remote use, through a public OAuth-protected HTTPS MCP gateway. Private tunnel testing is optional and cannot replace the publicly accessible endpoint required for distributed web plugins. Do not assume a custom ChatGPT web plugin can automatically gain OS access or that a specific OpenAI integration mode is enabled for every account. A user may decline any requested action; decline immediately ends that action.

Guiding principles: DRY, KISS, YAGNI, SOLID; least privilege; no credential or session extraction; explicit pairing; permission by capability/target/session/duration; runtime policy checks **on the device**; explicit approval for consequential actions; visible active indicator; instant stop; audit logs with redaction. No covert operation, consent bypass, remote shell by default, privilege escalation, bypass of Windows secure desktop or user account controls, or uncontrolled website commands.

## Architecture

1. **Client-facing MCP layer:** versioned tool contracts, schema validation, per-call session identity, structured failures. **Public remote HTTPS hosting is required for the web-first product**, but local Windows policy enforcement remains authoritative.
2. **Pairing and consent:** locally verified device ownership, account-bound registration, remote owner-presence approvals from a trusted second device when away, narrow session grants, expiration, cancellation and revocation. The model must never approve itself.
3. **Execution core:** allowlisted application and browser adapters; one shared enforcement point and action journal; observation separate from input.
4. **Windows host:** desktop UI Automation + bounded input, explicit browser targets, visible session indicator and emergency stop, plus an opt-in outbound-only cloud connection. Deny Windows lock/UAC/secure desktops.
5. **Delivery and evidence:** deterministic Linux CI with fake adapters; dedicated Windows interactive smoke and manual device approvals; supply-chain gates; signed release only when signing credentials are legitimately provided.

### Risk and verification labels

Intended `type:feature`, `type:security`, `type:release`; `state:ready`, `state:active`, `state:blocked`, `state:review`, `state:release-ready`; `risk:ci`, `risk:security`, `risk:dependencies`, `risk:deployment`. Connector has no label listing/creation tool; track these in Issue bodies and [control #1](https://github.com/Nippytime/local-gpt-mcp/issues/1) until label management exists, without blocking work.

**Fast**: formatting, lint, static analysis, fast deterministic tests and workflow policy.  
**PR**: metadata/Issue/risk contract, full unit/integration suite, coverage and reproducible build.  
**Audit**: pinned dependency vulnerability and secret checks, plus workflow policy.  
**Release**: all PR gates + Windows build regression, package integrity/provenance and release checks.  
**Windows-smoke**: target UI Automation and input tests in an interactive Windows session; not pretended by Linux mocks.  
**Security**: adversarial grant, identity, prompt-injection and unsafe-input tests.  
No gate counts as passed until the required GitHub Actions jobs ran and concluded success. No zero/pending/skipped-as-required check can be treated as green.

## Numbered independently deliverable items

### 1. [Project scaffold, CI and reproducible toolchain — #2](https://github.com/Nippytime/local-gpt-mcp/issues/2)

- **Acceptance:** Python 3.12 typed package, deterministic configuration and fixtures; review/port only runtime-neutral parts of `mlookhere/CI-Pipline`; `./scripts/bootstrap --ci`, `./ci/run fast`, and `./ci/run pr` function on a clean checkout; required PR Actions jobs **actually run and succeed**, with job-log inspection on failure.
- **Areas:** `ci/`, `scripts/`, `workflow/`, `.github/workflows/`, `.chatfreept/`, `pyproject.toml`, `tests/`, `docs/`.
- **Gates:** Fast, PR, Audit, Workflow policy. **Risk:** `risk:ci`, `risk:dependencies`.

### 2. [Consent policy and local authority boundary — #3](https://github.com/Nippytime/local-gpt-mcp/issues/3)

- **Acceptance:** deny-by-default grants bound to device, user, capability, target, session, and TTL; expired, replayed, cross-session and unauthorized calls rejected; immediate revocation/kill switch; redacted, structured audit entries; negative unit tests cover every constraint.
- **Areas:** `src/local_gpt_mcp/policy/`, `tests/policy/`, `docs/SECURITY.md`.
- **Gates:** Fast, PR, Security. **Risk:** `risk:security`.

### 3. [MCP transport, identity and trusted pairing — #4](https://github.com/Nippytime/local-gpt-mcp/issues/4)

- **Acceptance:** typed, versioned MCP tools and structured errors; local-only connection or explicitly authenticated secure tunnel; on-device one-time pairing approval, replay/nonce protection, TTL and rate limiting; integration tests prove unpaired callers cannot invoke controls.
- **Areas:** `src/local_gpt_mcp/mcp/`, `src/local_gpt_mcp/pairing/`, `tests/integration/`.
- **Gates:** Fast, PR, Audit, Security. **Risk:** `risk:security`, `risk:dependencies`.

### 4. [Windows desktop observation and bounded input — #5](https://github.com/Nippytime/local-gpt-mcp/issues/5)

- **Acceptance:** enumerate allowlisted windows; consented screenshot and UIA inspection of selected targets; bounded click, type, scroll and keyboard actions with target checks; locked session/UAC/secure desktop never bypassed; deterministic mocked tests and real opt-in Windows smoke.
- **Areas:** `src/local_gpt_mcp/desktop/`, `tests/desktop/`, `tests/windows/`.
- **Gates:** Fast, PR, Windows-smoke, Security. **Risk:** `risk:security`.

### 5. [Browser automation with constrained profiles — #6](https://github.com/Nippytime/local-gpt-mcp/issues/6)

- **Acceptance:** selected tabs via Playwright/Chrome-compatible adapter for navigation, reading, clicks, fills, scroll and screenshot; origin allowlists and sensitive-field masking; confirmation for upload/download and consequential actions; no cookie/token exfiltration or browser permission bypass; integration tests.
- **Areas:** `src/local_gpt_mcp/browser/`, `tests/browser/`.
- **Gates:** Fast, PR, Browser integration, Security. **Risk:** `risk:security`, `risk:dependencies`.

### 6. [Orchestrated workflows, checkpoints and recovery — #7](https://github.com/Nippytime/local-gpt-mcp/issues/7)

- **Acceptance:** typed, cancelable action plans; pre/postconditions and idempotency; bounded retry/backoff and crash/network recovery without reusing invalid grants; explicit per-action approval for destructive, financial, account, privilege and credential-sensitive operations; failure-mode tests.
- **Areas:** `src/local_gpt_mcp/orchestrator/`, `tests/orchestrator/`.
- **Gates:** Fast, PR, Security. **Risk:** `risk:security`.

### 7. [Windows UX, installation and secure operations — #8](https://github.com/Nippytime/local-gpt-mcp/issues/8)

- **Acceptance:** user-facing pairing/revocation UI, visible active-session and immediate stop; accessible permission review; per-user least-privilege installer, explicit startup opt-in, complete uninstall, redacted diagnostics; fresh-install Windows test evidence.
- **Areas:** `src/local_gpt_mcp/ui/`, `packaging/`, `scripts/`, `docs/OPERATIONS.md`.
- **Gates:** Fast, PR, Windows-smoke, Packaging. **Risk:** `risk:deployment`, `risk:security`.

### 8. [Security hardening and adversarial validation — #9](https://github.com/Nippytime/local-gpt-mcp/issues/9)

- **Acceptance:** documented threat model; web content treated as untrusted instructions; local executor always enforces policy; request validation fuzz tests, grant replay, path traversal, SSRF, approval-race and logging leak tests; documented dependency/SBOM review and blocked release for serious findings.
- **Areas:** `docs/THREAT_MODEL.md`, `tests/security/`, `ci/`, `.github/workflows/`.
- **Gates:** Fast, PR, Audit, Security, Regression. **Risk:** `risk:security`, `risk:ci`.

### 9. [Release candidate and real-user Windows validation — #10](https://github.com/Nippytime/local-gpt-mcp/issues/10)

- **Acceptance:** clean checked GitHub fast/PR/release history; real Windows user approves pairing and bounded actions then verifies stop; install/uninstall; versioned checksummed build and provenance; integration prerequisites, rollback and disable instructions; no release before required Windows evidence and human acceptance.
- **Areas:** `packaging/`, `docs/RELEASE.md`, `tests/e2e/`, `.github/workflows/`.
- **Gates:** Fast, PR, Release, Windows-smoke, Security. **Risk:** `risk:deployment`, `risk:security`.

## Mandatory web-first slices — added after original local foundation

### 10. [Web-first scope and release contract — #20](https://github.com/Nippytime/local-gpt-mcp/issues/20)

- **Acceptance:** product architecture, user-away approval contract, supported ChatGPT plan/publishing limits and a **third open high-risk release blocker `WEB_REMOTE_E2E`**. The current local-only software must not be described as web-ready.
- **Areas:** `docs/WEB_REMOTE.md`, `README.md`, `docs/MASTER_PLAN.md`, `security/release_blockers.json`, `tests/security/`.
- **Gates:** Fast, PR, Audit, Security. **Risk:** `risk:security`, `risk:deployment`, `risk:ci`.

### 11. [Public HTTPS MCP gateway and account isolation — #21](https://github.com/Nippytime/local-gpt-mcp/issues/21)

- **Acceptance:** stable HTTPS Streamable HTTP MCP endpoint with OAuth 2.1 PKCE/protected-resource metadata, user/device authorization, correct tenant isolation, denial of cross-user and offline calls, bounded responses and negative security tests.
- **Areas:** `src/local_gpt_mcp/gateway/`, `tests/gateway/`, `docs/`, `ci/`. **Risk:** `risk:security`, `risk:dependencies`, `risk:deployment`.

### 12. [Owner-paired outbound Windows agent — #22](https://github.com/Nippytime/local-gpt-mcp/issues/22)

- **Acceptance:** one-time trusted machine enrollment, device-bound credentials, TLS-only outbound channel, reconnect/heartbeat/offline support, per-request on-device enforcement and no port forwarding or remote shell.
- **Areas:** `src/local_gpt_mcp/agent/`, `src/local_gpt_mcp/pairing/`, `tests/`, `packaging/windows/`. **Risk:** `risk:security`, `risk:deployment`.

### 13. [Remote owner approval and emergency stop — #23](https://github.com/Nippytime/local-gpt-mcp/issues/23)

- **Acceptance:** independently authenticated browser/phone consent while away (user-presence/passkey preferred), single-use scoped action receipts, revocation and STOP, and denial when the owner cannot be verified. The MCP caller cannot approve its own requests.
- **Areas:** `src/local_gpt_mcp/policy/`, `src/local_gpt_mcp/ui/`, `src/local_gpt_mcp/agent/`, `tests/security/`. **Risk:** `risk:security`, `risk:deployment`.

### 14. [Actual ChatGPT web-to-remote-PC acceptance and distribution — #24](https://github.com/Nippytime/local-gpt-mcp/issues/24)

- **Acceptance:** test a **real** supported ChatGPT web conversation using an OAuth-linked plugin from another location to operate an authenticated device, including separate remote write approval, denied offline/locked/UAC/foreign-user requests, emergency stop and public submission readiness. Do not close `WEB_REMOTE_E2E` before verified proof.
- **Areas:** `tests/e2e/`, `docs/RELEASE.md`, `docs/WEB_REMOTE.md`, `packaging/`, `ci/`. **Risk:** `risk:security`, `risk:deployment`, `risk:ci`.

**Updated release rule:** The original [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10) is still open and has a draft local integration PR. Even if the local PR passes all nine checks, it cannot authorize a web-first production release until remote Issues #20–#24 and every high-risk release gate have verified acceptance. Each new slice uses one Issue, `work/<issue>-slug` branch and one PR into `dev`; no CI weakening or direct production pushes.

## CI template migration strategy

Reference source: [mlookhere/CI-Pipline](https://github.com/mlookhere/CI-Pipline) `dev`. Inspect each workflow before porting. Only runtime-neutral portions of `ci/`, `scripts/`, `workflow/`, `.github/workflows/`, `.pre-commit-config.yaml`, `.gitattributes`, and merged `.gitignore` may be incorporated, with attribution. Never copy `.claude/`, `.claude-workflow.json`, `.github/claude/`, Claude agents/hooks/prompts/skills/CLIs/auth or Claude-specific tests. Replace template branches `master` → `main`; preserve `dev`. Keep stable named required jobs as recorded in `.chatfreept/project.json`. Template files referring to absent commands must be adapted or omitted, **never left as passing no-ops**.

All changes after bootstrap must be delivered as `work/<issue>-<slug>` PRs into `dev`, each PR body containing `Refs #<issue>`, Result, Implementation, Verification, Risk and Remaining work. Re-check every required Actions check, inspect first causal job log on failure, fix no more than three times for the same error without escalating. `main` only moves through a verified release PR from `dev`.

## Supported integration reality

Official documentation describes authenticated [plugin MCP servers](https://developers.openai.com/plugins/build/auth) and the [local/remote MCP transport options](https://developers.openai.com/api/docs/guides/tools-connectors-mcp). [ChatGPT Work](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex) also includes permissioned computer-use capabilities on supported clients. This project must not claim automatic web-chat local PC control until its own connector pairing and a real supported ChatGPT product integration have been demonstrated.
