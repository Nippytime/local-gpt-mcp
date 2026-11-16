# Isolated browser automation

This item implements an opt-in, one-tab Playwright/Chromium browser adapter via the local MCP stdio transport. It **does not** attach to an existing logged-in Chrome profile, read existing browser cookies, or open an HTTP listener.

## Start and approve

From a local, user-controlled MCP host, start the companion with:

```bash
python -m local_gpt_mcp --stdio --browser-origin https://example.com
```

The origin must be an **exact public HTTPS origin**, without paths, query parameters, embedded credentials, localhost/private IP destinations, or nonstandard ports. At launch the companion creates a fresh temporary Chromium context and a single new tab. The remote MCP host cannot register, select or create an additional tab. The browser is visible by default.

An MCP client must obtain the user's local-console pairing approval, then call `browser_selected_tabs` with an authenticated session and a fresh request nonce. It must separately request a `browser.read` and/or `browser.input` grant for **that exact origin**. A grant is short-lived and revocable. Declining any local prompt blocks the request.

## Supported controlled operations

- `browser_selected_tabs`: list only the local isolated tab IDs and their exact origin, after authenticated pairing
- `browser_navigate`: navigate within the approved HTTPS origin, verifying the resulting URL after redirects
- `browser_read`: read up to 2,048 characters of visible text from one unambiguous non-editable element
- `browser_click`: click one visible, enabled, non-sensitive element; form submission controls are blocked
- `browser_fill`: enter 1–256 printable characters into a visible, non-sensitive editable field
- `browser_scroll`: scroll by at most three steps per operation
- `browser_capture`: viewport screenshot (at most 4 MB) with editable controls masked

Every operation requires a valid session bearer, new nonce, approved grant, locally created tab ID, and matching current origin. The Playwright context has service workers blocked, download acceptance disabled, WebSockets blocked, and outgoing network requests filtered to the exact allowed HTTPS origin. Other tabs/popups are closed rather than controlled.

**Candidate pinned HTTPS network transport (Item 9):** In the release-validation branch, intercepted GET/HEAD requests are resolved, checked for **only public IP addresses**, and connected directly to an approved IP while TLS verifies the original site hostname. The transport blocks redirects, HTTP and nonstandard ports, all POST/PUT form submissions, unsupported third-party resources, responses above 4 MB, and browser/WebSocket transfers. These strict limits mean dynamic sites and third-party assets may fail to load. The new transport is **under CI and real-browser review** and is not certified for all network channels; the high-risk release blocker remains open.

**File transfers:** Upload controls are never filled; downloads are not accepted by the automation context. There is no silent upload/download path or ability to read local files. Future opt-in file transfers require a separate local chooser and per-transfer confirmation workflow.

**Privacy:** The adapter does not extract passwords, cookie jars, local browser credentials, browser profile storage, clipboard contents, or payment form values. Editable fields are masked on screenshots and excluded from text extraction. Visible non-editable page text can still contain personal data; grant only on sites where you intend to disclose such content.

## CI and acceptance

- The **Browser integration contract** runs on GitHub-hosted Linux, installs Playwright's Chromium browser, and uses synthetic local HTML to test real browser actions, MCP tool contracts, network restrictions and sensitive-field blocking.
- The fast PR gate uses deterministic mock browser/page tests. The Windows contract, dependency audit, workflow-policy, metadata, and test/build checks remain required.
- This is not verification of an existing user Chrome profile, SSO identity, file chooser, or all production websites. Real user-facing acceptance and any remote ChatGPT connector remain later plan items.

## Security limits

New contexts do not import user sessions, extensions, browser settings or persistent profile data. They have no administrator access or browser security bypass. Browser content may still execute arbitrary JavaScript within its origin; do not allow untrusted local hosts, private addresses or cross-origin redirects. A future remote connector must be separately authenticated and bound to the same local authority and visible UI.
