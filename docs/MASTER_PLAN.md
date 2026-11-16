# Master delivery plan — Local GPT MCP

**Repository:** [Nippytime/local-gpt-mcp](https://github.com/Nippytime/local-gpt-mcp)  
**Integration:** `dev` · **Production:** `main` · **Control Issue:** [#1](https://github.com/Nippytime/local-gpt-mcp/issues/1)  
**Operating model:** ChatGPT + GitHub MCP. A single delivery Issue maps to one `work/<issue>-<slug>` branch from `dev` and one PR into `dev`. No direct integration or production changes after the documented initial bootstrap.

## Outcome and technical boundaries

Build a consent-driven Windows companion that exposes **scoped desktop and browser actions** through an authenticated MCP interface suitable for ChatGPT integrations where supported. A browser page alone cannot directly control the host operating system. Native control is delivered through a locally installed, **user-launched** companion, with approved secure connectivity (e.g. an authenticated MCP endpoint/tunnel when supported). Do not assume a custom ChatGPT web plugin can automatically gain OS access or that a specific OpenAI integration mode is enabled for every account. A user may decline any requested action; decline immediately ends that action.

Guiding principles: DRY, KISS, YAGNI, SOLID; least privilege; no credential or session extraction; explicit pairing; permission by capability/target/session/duration; runtime policy checks **on the device**; explicit approval for consequential actions; visible active indicator; instant stop; audit logs with redaction. No covert operation, consent bypass, remote shell by default, privilege escalation, bypass of Windows secure desktop or user account controls, or uncontrolled website commands.

## Architecture

1. **Client-facing MCP layer:** versioned tool contracts, schema validation, per-call session identity, structured failures. Remote hosting is optional and never a prerequisite to local policy enforcement.
2. **Pairing and consent:** on-device challenge and user-approved scoped session grants, expiration, cancellation and revocation.
3. **Execution core:** allowlisted application and browser adapters; one shared enforcement point and action journal; observation separate from input.
4. **Windows host:** desktop UI Automation + bounded input, explicit browser targets, visible tray/session surface.
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

## CI template migration strategy

Reference source: [mlookhere/CI-Pipline](https://github.com/mlookhere/CI-Pipline) `dev`. Inspect each workflow before porting. Only runtime-neutral portions of `ci/`, `scripts/`, `workflow/`, `.github/workflows/`, `.pre-commit-config.yaml`, `.gitattributes`, and merged `.gitignore` may be incorporated, with attribution. Never copy `.claude/`, `.claude-workflow.json`, `.github/claude/`, Claude agents/hooks/prompts/skills/CLIs/auth or Claude-specific tests. Replace template branches `master` → `main`; preserve `dev`. Keep stable named required jobs as recorded in `.chatfreept/project.json`. Template files referring to absent commands must be adapted or omitted, **never left as passing no-ops**.

All changes after bootstrap must be delivered as `work/<issue>-<slug>` PRs into `dev`, each PR body containing `Refs #<issue>`, Result, Implementation, Verification, Risk and Remaining work. Re-check every required Actions check, inspect first causal job log on failure, fix no more than three times for the same error without escalating. `main` only moves through a verified release PR from `dev`.

## Supported integration reality

Official documentation describes authenticated [plugin MCP servers](https://developers.openai.com/plugins/build/auth) and the [local/remote MCP transport options](https://developers.openai.com/api/docs/guides/tools-connectors-mcp). [ChatGPT Work](https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex) also includes permissioned computer-use capabilities on supported clients. This project must not claim automatic web-chat local PC control until its own connector pairing and a real supported ChatGPT product integration have been demonstrated.
