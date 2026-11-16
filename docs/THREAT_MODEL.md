# Threat model and adversarial security acceptance

**Scope:** Local GPT MCP Windows desktop companion, stdio MCP server, isolated Chromium browser, typed workflow engine, local approval UI, and user-owned per-user installation. This document records checked boundaries and known unresolved release risks; it does not certify a production release.

## Assets and adversaries

- Assets: local window/screenshot content, UIA labels, browser page text, user input, selected origin and HWND, pairing/session/grant bearers, local approval challenges, installation directory and workflow checkpoint state.
- Adversaries: unpaired MCP clients, authorized but malicious/model-controlled callers, hostile webpages or prompt-injected text, malicious HTML controls/redirects, local files placed in untrusted folders, manipulated DNS, and dependencies/build workflows.
- The trusted human can approve or deny actions on the physical local panel. The model, website and MCP arguments are **not** trusted authorities. Windows UAC/secure desktops and existing user browser credentials remain excluded.

## Non-bypassable boundaries

1. The server has **no HTTP listener**. Desktop/browser tools are registered only when an explicit local startup target exists; Windows refuses adapter startup if the topmost safety panel cannot open.
2. Device pairing is locally approved, grant tokens are bound to session/target/capability/expiry, and each request consumes a fresh nonce with replay and rate bounds.
3. Every **direct mutating MCP tool** now pre-authorizes the session/grant **before a local prompt**, requires a new typed local confirmation, and then **reauthorizes at the executor** using a server-issued nonce. An invalid session cannot trigger a local approval prompt; revocation/stop between approval and effect denies the effect.
4. Workflow mutations additionally use a separate local approval and are never automatically retried. Crash/timeout after a potential side effect is an uncertain checkpoint requiring manual review.
5. Windows actions require a locally selected, non-elevated, current-user foreground HWND bound to PID and process creation time, unlocked default input desktop and immediate pre-dispatch verification.
6. Browser actions require one ephemeral Playwright context and a locally selected exact public HTTPS origin; private-IP URLs, unsafe redirects, download acceptance, file inputs, secrets/password controls and cross-origin request attempts are rejected.
7. Page and UI text are **untrusted data**, not system instructions. Browser-read MCP responses now carry `trust: untrusted_page_content`; reading prompt-injected HTML never authorizes shell, unapproved navigation or device input.
8. Checkpoint paths are locally supplied; stored JSON includes only plan SHA-256 digest, index and state. Symlink checks and private/atomic writes reduce accidental corruption; no bearer tokens or typed content are persisted.
9. CI uses pinned GitHub Actions, strict Ruff/mypy/pytest/coverage, dependency audit, secret scan, mocked Windows contract, real Chromium contract, per-user Windows packaging contract, and a separate mandatory adversarial regression/SBOM job.

## Adversarial scenarios and expected outcomes

| Scenario | Outcome and test evidence |
| --- | --- |
| Fake session or replayed nonce before an action | Reject without local approval; `tests/security/test_mutation_boundary.py` |
| Direct MCP click/navigation with grant but no fresh local approval | Deny; direct mutations fail closed by default |
| Revocation or emergency stop while a local challenge is pending | The second executor authorization fails and no action is performed |
| Malicious webpage text instructing shell/control bypass | Returned as explicitly untrusted content; no shell tool or implicit action |
| Private/loopback/link-local/mixed DNS and cross-origin navigation | Reject; `tests/security/test_ssrf_dns.py`, browser controller and Chromium route tests |
| Malicious target/nonce/capability and path traversal | Existing typed validators and deterministic policy/session/checkpoint tests reject |
| Unmarked/reparse-point installer/uninstaller target | Reject; Windows packaging contract and required physical follow-up |
| Unstable/invalid package metadata | CycloneDX inventory generation fails; `tests/security/test_sbom.py` |

## Security supply-chain evidence

The `Adversarial security regression` required check runs `pytest tests/security` and creates `artifacts/ci/sbom.cdx.json` (CycloneDX 1.6) from the installed distributions. The separate `Dependency audit` check continues to run pip-audit and secret scanning. An SBOM is inventory, **not** proof the dependencies have no vulnerabilities. Review the audited lock/requirements and CycloneDX artifact during the final release audit.

## Residual risks — block production release until closed

**High risk: DNS rebinding/time-of-check to time-of-use.** The browser checks that every resolved address is public before `route.fetch`, and blocks redirects. A malicious DNS responder may still return a different address after the check, because DNS resolution is not pinned to the actual TLS connection. Final release must either pin the validated public resolution in the browser/network transport, use a network-isolated outbound proxy that enforces destination-IP allowlists at connection time, or provide an equally strong verified defense. Track this as a release blocker in Issue #10; do not claim comprehensive SSRF immunity.

**High risk: physical-device acceptance is not yet verified.** Headless CI does not establish that Windows lock-screen/UAC refusal, real UI Automation/input behavior, visual safety-panel prominence, screen-reader accessibility and emergency-stop behavior work on an actual user workstation. Complete the specified manual Windows scripts and record results in Issue #10 before production release.

**Medium risk: prompt-injection and user-consent quality.** A model could treat hostile webpage text as a trusted instruction despite explicit metadata. Deterministic executor checks and local per-mutation approval reduce effects but cannot prove a human will recognize every deceptive request. Review the action UI content and include real-world misuse scenarios during acceptance.

**Medium risk: local checkpoint file races and user-supplied filesystem permissions.** A hostile local process with write access to the workflow-state directory could tamper with a checkpoint or race local path checks. No secrets are written, but resume logic may be confused; use a private per-user directory, and validate file/reparse-point behavior on Windows before release.

The **production `./ci/run release` stage now invokes `workflow/check_release_blockers.py`**. It exits nonzero as long as any high-risk record in `security/release_blockers.json` is open; a closed record requires a repository evidence URL. Do not remove or weaken this gate to ship an unfinished release.

**Release rule:** Never mark `Complete`, merge to production `main`, or assert the project secure when a high-risk item remains. Track any new high-risk finding with owner, reproducible scenario, mitigation and regression test; update Issue #10's acceptance evidence.
