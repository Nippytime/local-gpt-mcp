# Windows desktop adapter — locally selected single-window scope

**Implementation:** Issue #5. Windows 10/11 interactive desktop only. The Windows adapter is disabled unless a human launches the MCP subprocess locally with a selected window HWND.

## Launch and approval

1. Open the target application as the logged-in non-administrator Windows user and bring its top-level window to the foreground.
2. Start the local MCP subprocess with `python -m local_gpt_mcp --stdio --allow-window HWND` using the positive native HWND selected on the device. Browser ChatGPT alone cannot spawn a Windows subprocess.
3. The native backend binds HWND, process ID, **process creation time**, same Windows user/session, non-elevated process checks and foreground state into an immutable allowlist. It denies known shells, registry/system tools, unknown owners, locked desktops, UAC prompts and changed window identities.
4. The MCP caller must then separately request local console pairing and a grant for exactly `window:HWND`, with `window.read` or `window.input`. Each action requires a new nonce, authenticated session and approved grant.
5. If the trusted user changes foreground window, locks Windows, revokes a grant, or activates emergency stop, subsequent actions fail closed.

There is no remote API to add window IDs or elevate the process. Restart requires fresh local selections and approvals. There is no network listener, automatic privilege escalation or arbitrary shell-command tool.

## Opt-in MCP desktop tools

- `desktop_window_info`: selected foreground window title and dimensions
- `desktop_capture`: PNG of the window (not full desktop), max 1280×800 and 4 MB
- `desktop_controls`: bounded UI Automation tree (up to 64 nodes / 3 levels); edit/password fields are redacted and no value patterns are read
- `desktop_click`: absolute pixel hit-tested inside approved window; rejects occlusion
- `desktop_type`: 1–256 printable characters; no control sequences or newlines
- `desktop_scroll`: up to three wheel steps
- `desktop_key`: navigation keys only (Tab, Escape, Backspace, arrows, Home, End); no Win/Alt/Ctrl or Enter

Observation and input are distinct granted capabilities. Screenshots and non-editable UI labels can still disclose visible sensitive content; do not approve banking or confidential applications unless that disclosure is intended.

## CI evidence versus physical Windows acceptance

- GitHub PR CI performs deterministic Linux tests and an additional **Windows adapter contract** job on `windows-latest`. The Windows job verifies toolchain, SDK installation, static checks, and mocked backend contracts in a headless runner; **it does not demonstrate physical interactive control**.
- The opt-in acceptance script is `tests/windows/manual_smoke.py`. On a non-elevated, unlocked Windows PC, run it from a real interactive console. The script opens its own disposable Tkinter test window, requires actual pairing/grant challenges, captures and inspects that window, clicks its test button, types into its test field, sends bounded scroll/key actions, and verifies emergency stop.
- Real-device verification must separately confirm denial after Windows lock and when a UAC secure desktop becomes active, without clicking UAC or unlocking Windows via automation.
- Record actual Windows build/version, screenshot/keyboard outcomes, and denial results in the control Issue before claiming interactive acceptance. A green GitHub Actions job is **not** evidence of the physical tests.

## Known boundaries

Multiple-monitor DPI scaling, UI Automation differences between apps, input focus changes and overlays require later acceptance feedback. No automatic consequence-sensitive actions or per-action workflow approvals are implemented in this slice. This project never bypasses operating-system permission prompts.
