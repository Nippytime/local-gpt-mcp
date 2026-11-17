# Physical Windows smoke evidence — operator-only

This is a **local standard-user test helper**, not a production release certificate.
The hosted Windows CI contract and browser simulations cannot prove a real user's
Windows lock/UAC/STOP behavior. Do not close any HIGH release blocker from this file.

## Run on a real Windows 10/11 PC

1. Use a checked-out, trusted repository on the actual PC with **Python 3.12+**
   and the project's dependencies installed. Open a real interactive PowerShell
   console **as a standard user**, not an administrator or Windows service.
   Do not run unattended, over SSH, from Task Scheduler or from a CI runner.
2. In the checkout, run:

   ```powershell
   python -m ci.windows_acceptance
   ```

3. For each test, read the console instruction and type `RUN` only when
   physically ready. The first test opens a disposable Tk window and uses
   console-approved scoped operations. The second opens a visible safety
   panel: **you** must type the pairing/grant challenges and physically press
   its red emergency STOP button. The runner **never** presses STOP for you.
   Any refusal, error or timeout ends the sequence without an automatic retry.
4. The runner writes `artifacts/acceptance/windows-<UTC>.json` with the full
   checked source SHA, UTC time and only test names/statuses/exit codes. It
   does not copy console output, keys, OAuth tokens, passkey contents, typed
   challenges, usernames, filenames from your PC or screenshots. Review it
   locally before sharing a redacted copy in [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10).

**A passing smoke report is not full physical acceptance.** Its
`physical_acceptance` remains `unverified`, `release_ready` is always
`false` and all HIGH blockers remain `open`. This is deliberate.

## Separate physical tests still required

- Test foreground changes, elevated/occluded windows, locked sessions and
  UAC secure desktop with a disposable target. Record **refusals** and local
  STOP, never bypass/automate the UAC prompt or the Windows lock screen.
- On a new standard-user profile, validate the per-user installer, default
  unpaired launcher, `uninstall.ps1 -WhatIf` and actual clean uninstall.
  Verify there are no services, scheduled tasks, autorun entries or
  unexpected elevation prompts.
- Confirm revocation and local STOP while the gateway is disconnected,
  expiry and replay denial, and uncertain side effects without auto-retry.
  Use only approved test targets, not consequential user applications.
- Separately verify the independently authenticated owner OAuth/browser
  passkey on a **different physical device/network** and supported
  `chatgpt.com` custom MCP to the PC. Record redacted evidence in
  [Issue #24](https://github.com/Nippytime/local-gpt-mcp/issues/24).
- Verify real DNS rebinding/Chromium alternate-channel egress in the target
  network. Hosted socket mocks and Chromium smoke tests do not suffice.

Keep [owner Issue #23](https://github.com/Nippytime/local-gpt-mcp/issues/23)
and [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10)
open, leave both draft PRs unmerged, and do not change
`security/release_blockers.json` or production `main` without verified
independent evidence and all required production checks.
