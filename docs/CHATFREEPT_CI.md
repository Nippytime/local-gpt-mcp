# Chat FreePT CI contract — Local GPT MCP

## Source and selective vendoring
Source reviewed: [mlookhere/CI-Pipline at `08b19629516dd5da9e781e0e8cfb69d1f2ae44b0`](https://github.com/mlookhere/CI-Pipline/tree/08b19629516dd5da9e781e0e8cfb69d1f2ae44b0). This repository does **not** execute Claude, Claude Code, Claude hooks or Claude credentials. Python/bash pipeline mechanics and policy approaches may be ported, not copied unreviewed.

| Template assets | Decision |
| --- | --- |
| `ci/run`, `ci/run.py`, `scripts/bootstrap`, `scripts/lib/python.sh` | Port cross-platform command handling and fail-closed stage reports for this package. |
| `.github/workflows/ci-pr.yml` | Adapt to `dev`, real test/build/security commands and required named jobs. |
| `.github/workflows/ci-release.yml` | Adapt `master`→`main`; release PRs only from `dev`. |
| `.github/workflows/security.yml` | Retain workflow-policy and dependency audits; do not claim skipped optional Advanced Security features ran. |
| `.github/workflows/nightly-quality.yml` | Defer scheduled deep-quality until reproducible fast/PR gates succeed. |
| `.github/workflows/sync-control.yml` | Defer privileged event-triggered write workflow until all control scripts and event security are adapted and tested; GitHub MCP updates control Issue meanwhile. |
| `workflow/` | Selectively port only generic validation and secret/security checks; template repository-specific state files cannot be assumed valid. |
| `.pre-commit-config.yaml`, `.gitattributes`, `.gitignore` | Translate neutral hooks; delete all Claude-specific paths and settings; add local build/secret excludes. |
| `.claude/`, `.claude-workflow.json`, `.github/claude/`, Claude CLIs/auth/hooks/agents/skills | **Never vendor or execute.** |

## Branches and lifecycle
- Production is `main` (also repository default), integration is `dev`, work branches are `work/<issue-number>-<slug>` branched from `dev`.
- Initial repository seeding only is allowed directly on integration/production. All development proceeds by PR to `dev`; verified release PR from `dev` to `main`.
- PRs must reference an existing Issue, contain Result, Implementation, Verification, Risk and Remaining work sections, carry appropriate labels once label creation access exists, and obey changed-line/file limits.
- Available Nippytime GitHub connector exposes file/branch/Issue/PR and Actions/log reads; **no label listing/creation tool**. Intended label sets are recorded in Issue text; don't silently bypass other gates to compensate.

## Expected named checks and genuine evidence
Integration: `PR metadata`, `Fast deterministic gates`, `PR test/build gates`, `Dependency audit`, `Workflow policy`.
Production: `Release metadata`, `Full regression and production build`, `Workflow policy`.

The CI runner must create a JSON record of each executed command and checkout SHA. Unknown stages, absent interpreters, missing command implementations, failing commands and missing tests **fail**. No external Windows interaction is simulated by Linux CI: real Windows acceptance is a separately documented gate. `CI: Passed` is reserved for verified, completed required GitHub Actions checks. In the setup state, there are **zero runs**; CI status remains `Not run`.

## Execution contract
The first delivery Issue [#2](https://github.com/Nippytime/local-gpt-mcp/issues/2) implements the actual buildable toolchain, reviewed CI assets, and tests. Until those files are landed and a PR verifies all named checks, this document is a specification, **not evidence of a functioning pipeline**.
