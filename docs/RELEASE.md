# Release acceptance and recovery — Item 9

**Status:** Not release-ready. `dev` contains eight CI-verified implementation slices, but the production `main` branch remains unchanged. High-risk release blockers are open in `security/release_blockers.json` and are checked automatically by `./ci/run release`. Do not override that check to ship.

## Prerequisites for production approval

1. Review [THREAT_MODEL.md](THREAT_MODEL.md), the latest [control Issue #1](https://github.com/Nippytime/local-gpt-mcp/issues/1), and [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10). Confirm every high-risk record has verified fix/acceptance evidence and the blocker manifest is updated only after evidence is attached.
2. Resolve DNS-rebinding/TOCTOU at **network connection time**. Item 9 now contains a candidate pinned public-IP HTTPS fetcher and mock socket-level rebinding tests. Verify a **real** Playwright/Chromium browser load through this transport, no private/reserved outbound IP under DNS changes, TLS hostname checks, blocked redirects and blocked alternate browser channels. Keep the high-risk blocker open until reproducible end-to-end evidence is recorded.
3. Verify the local Windows safety panel, user-typed pairing and grants, scope display, direct-action approval, emergency stop, and denial for headless/missing UI. Use a real standard-user Windows 10/11 PC, not just GitHub-hosted runners.
4. Run `python tests/windows/manual_ui_smoke.py` and `python tests/windows/manual_smoke.py` on the actual machine, record the OS build, accessibility (including keyboard/screen reader), screenshots and logs with sensitive content removed, and test refusal on the lock screen and UAC secure desktop **without interacting with UAC automatically**.
5. Execute `packaging/windows/install.ps1`, the safe unpaired launcher, `uninstall.ps1 -WhatIf`, and the actual uninstaller on a fresh non-administrator profile. Confirm no services, administrator prompts, scheduled tasks, registry autorun, or residue in the owned installation directory.
6. Review the latest `Adversarial security regression` CycloneDX inventory (`artifacts/ci/sbom.cdx.json`), the separate dependency audit, and all existing PR CI checks. Document the package/version and dependency evidence in Issue #10.

## Reproducible build and provenance

After blockers are closed and `dev` has passed its entire integration matrix, use the checked-out repository and locked CI toolchain to build a package and compute its SHA-256 checksum. On Windows PowerShell:

```powershell
python -m build
Get-ChildItem .\dist\* | Get-FileHash -Algorithm SHA256
```

The normal PR build gate now emits `artifacts/ci/build-manifest.json` containing actual wheel/source archive hashes, package version and the full checked Git commit; `dist/` is uploaded alongside the CI JSON reports. These artifacts are **unsigned and not an attestation**. Independently compare the downloaded bytes to their recorded SHA-256 before distributing.

Record the Git commit, workflow run links, GitHub Actions check names/conclusions, build artifact names, hashes, Python version, Windows OS version and release approval in Issue #10. Do not fabricate a signed artifact, timestamp or provenance statement; signed MSI/MSIX and a standalone Windows executable are not currently delivered.

Only after acceptance, propose a PR from verified `dev` into `main` under the repository's release workflow. The production release workflow must report all required checks **completed successfully**, including `Full regression and production build` with the high-risk release blocker check. Pending, missing, zero or failed checks are not passing. Keep `main` unchanged until then.

## User setup and ChatGPT connection

The current companion exposes **local stdio MCP only**, not an Internet HTTP server. ChatGPT web cannot automatically connect to a user's Windows PC. A supported local MCP-capable host must be installed, locally invoked, authenticated and bound to the user's explicit desktop/browser scope; any future remote tunnel requires separate network authentication, encrypted transport, scope binding and end-to-end attack review. Do not imply remote access is available without those pieces.

See [OPERATIONS.md](OPERATIONS.md) for opt-in per-user installation, active safety controls, diagnostic and uninstall procedures.

## Emergency disable, rollback and recovery

- The local user can press the prominent emergency-stop button or close the safety panel. This revokes all pairings/grants and denies subsequent calls; an already delivered OS event cannot be undone.
- Stop the local MCP host, then run `packaging/windows/uninstall.ps1 -WhatIf` and `uninstall.ps1` for a verified per-user installation. No automatic startup tasks were registered by the installer.
- Keep `main` at the last verified production SHA until the release PR is green and user acceptance complete. If a proposed release fails, close or revert the release PR rather than bypassing gates or silently modifying the production branch.
- An uncertain mutating workflow checkpoint must be reconciled by a human inspecting the application. Never automatically replay a click, form submit, text entry or Windows input after an ambiguous timeout.

**No release certificate exists at this point.** Owner-verified acceptance, resolved security blockers, actual Checks and a final GitHub audit are mandatory before reporting `Complete`.
