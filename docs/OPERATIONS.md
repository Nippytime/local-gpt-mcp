# Windows local safety and operations

Item 7 provides an opt-in native Windows safety panel and a per-user installer. The MCP transport remains **local stdio only**. ChatGPT in a browser cannot directly connect to a Windows process without a separate, locally running MCP-capable host.

## Install and start

Requirements: Windows 10/11, Python 3.12+, standard non-administrator user, and a trusted project checkout.

```powershell
.\packaging\windows\install.ps1
```

The installer creates a Python virtual environment and `Start-LocalGPTMCP.ps1` under `%LOCALAPPDATA%\Programs\LocalGPTMCP`. It creates **no** scheduled task, startup shortcut, registry Run key, service, admin request, automatic background agent, or global Python changes.

From a locally configured MCP-capable host, explicitly select a browser origin (or a window HWND) and start the local stdio companion:

```powershell
& "$env:LOCALAPPDATA\Programs\LocalGPTMCP\Start-LocalGPTMCP.ps1" --stdio --browser-origin https://example.com
```

Windows automatically displays a visible topmost safety panel **before registering device/browser tools**. If that panel cannot open, startup fails closed without a fallback. No remote MCP tool can choose a new target, create the panel or make the device start at login. Running the launcher with no arguments prints the safe, unpaired status and exits.

For a locally selected Windows target, supply `--allow-window HWND`; see [WINDOWS_DESKTOP.md](WINDOWS_DESKTOP.md). For workflow recovery, the local operator may also specify `--workflow-state-dir PATH`. That folder contains only a plan hash, checkpoint index and state, never bearer tokens or input contents.

## Visible safety controls

The panel shows current authorization state, approved targets and scopes, the latest 15 redacted security events and a prominent **EMERGENCY STOP — REVOKE ALL ACCESS** button. Closing the panel is an irreversible stop for the running authority.

Pairing, capability grants and each workflow mutation require their own displayed local approval request. The local user must type the exact randomized `APPROVE ...` challenge in the panel's entry field. **Deny**, an incorrect response, a request timeout, or panel closure rejects the request. No MCP stdin or remote flag can satisfy the approval.

Only the local screen receives target/scope details for meaningful consent. Audit events contain no grant tokens, passwords, cookies, typed text or screenshots. Visible page/window content may still disclose private data when the user explicitly grants reading.

Emergency stop invalidates all pairings/grants, denies outstanding requests and rejects later MCP requests. An OS input already dispatched before stop cannot be undone. A new subprocess and fresh approvals are needed to regain access.

## Diagnostics

The local panel displays pairing count, authorized scopes and recent security events. The status is **not exposed as an MCP tool**, and no automatic telemetry or remote logging is provided. Check that Windows is unlocked, the target remains foreground, and browser origin/grants still match when diagnosing denied actions. Workflow mutations with unknown outcomes remain uncertain and are never automatically replayed.

## Uninstall

Close the local MCP host and safety panel first. Preview the removal, then uninstall:

```powershell
.\packaging\windows\uninstall.ps1 -WhatIf
.\packaging\windows\uninstall.ps1
```

The uninstaller only removes an installation **inside the current user's LocalAppData** with an exact ownership marker, and refuses arbitrary or reparse-point directories. It does not delete the checkout, user browser data, system Python, or optional workflow-state directories. There is no automatic startup configuration to remove.

Hosted Windows CI executes `packaging/windows/verify.ps1` to verify a fresh actual package install, deny-first launcher and uninstall. That test does **not** demonstrate a physical interactive Windows desktop.

## Required physical acceptance before release

- On a standard-user Windows workstation, run `python tests/windows/manual_ui_smoke.py`. Verify two separate typed challenges, target/scope display, and the red emergency-stop button. Check keyboard navigation and accessibility with the user's screen reader.
- Run `python tests/windows/manual_smoke.py` for a disposable window, real UI Automation, screenshot and bounded input.
- Lock the workstation and open a UAC secure-desktop prompt. Verify refusal without clicking UAC or unlocking Windows through automation.
- Check clean install, default deny behavior, `uninstall.ps1 -WhatIf`, uninstall and reinstall. Confirm no administrator privilege, background process or leftover managed files.
- Record Windows build, screen-reader observations, denial/revocation outcomes and install/uninstall evidence under [release Issue #10](https://github.com/Nippytime/local-gpt-mcp/issues/10). Green headless CI does **not** mean physical Windows acceptance.

**Not delivered:** a system-tray icon, signed MSI/MSIX installer, native automatic startup, or a ChatGPT remote transport. This release slice provides a visible control panel and script-based per-user setup, not those separate features.
