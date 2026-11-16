# Bounded workflow orchestration

Issue #7 adds a sequential, consent-gated workflow runner for the existing local-only MCP desktop and isolated-browser adapters. This is **not** a remote scheduler, background task service, arbitrary command runner, or unattended computer controller.

## Local activation

Run an MCP server with at least one explicitly selected local capability:

```bash
python -m local_gpt_mcp --stdio --browser-origin https://example.com
```

For crash-persistent checkpoints, the **local operator** may select a private directory at launch:

```bash
python -m local_gpt_mcp --stdio --browser-origin https://example.com --workflow-state-dir ./private-workflows
```

Omitting `--workflow-state-dir` keeps checkpoints in process memory. A remote MCP caller cannot choose the checkpoint path, add windows, select browser origins or enable any adapter. The server does not run until the local user starts its process.

## Authenticated workflow tool

`workflow_execute` is advertised only when at least one local adapter is enabled. It requires an authenticated session token, a fresh client nonce, previously approved read/input grant tokens, an opaque plan ID, and a list of **1–8 validated typed steps**. Supported step actions are:

| Browser | Windows |
| --- | --- |
| `browser.read` | `desktop.info` |
| `browser.navigate` | `desktop.click` |
| `browser.click` | `desktop.type` |
| `browser.fill` | `desktop.scroll` |
| `browser.scroll` | `desktop.key` |

Each step specifies the **locally selected tab ID** or **exact `window:HWND`** target. Browser selectors, navigation URLs and input values are bounded and validated. No shell commands, file transfers, arbitrary JavaScript execution or new window-selection operations are available.

Optional `before` and `after` conditions check that a browser text selector or Windows title contains an expected substring. These observations require a separately approved read grant. Input steps require a separate input grant. The existing controller rechecks the session, nonce, actual window/browser target and capability **before every operation**.

**Every mutating step requires a fresh independent confirmation typed in the actual local console**, in addition to the prior pairing and grant approvals. This includes navigation, clicks, typing, form filling, scrolling and navigation key presses, regardless of whether an MCP caller describes the action as harmless. There is no auto-approve parameter or local prompt bypass. Sensitive browser fields and privileged Windows UI remain prohibited by the underlying adapters.

## Timeouts, cancellation and recovery

- Each operation and condition has a hard 12-second async timeout. **Only read-only operations** may retry, at most twice with bounded backoff; clicks, text entry, navigation, scrolling and other mutations never auto-repeat.
- An application-owned `Cancellation` object stops the sequence. The MCP client can also cancel its ongoing tool request. The existing `session_emergency_stop` revokes local authority so subsequent actions are rejected.
- The checkpoint is written **before** a mutating operation. If the action fails, times out, or is cancelled, that step becomes `uncertain`. An uncertain side effect cannot be automatically resumed or retried: a real local operator must inspect the actual application and start a new, approved plan when appropriate.
- Successful steps advance a checkpoint and `resume=True` skips already completed steps only when the full plan digest matches, the checkpoint is not uncertain, and the caller still has a valid session and grants. Completed plans cannot be replayed without explicitly requesting `resume`.
- Disk checkpoint JSON stores **only** the SHA-256 plan digest, completed index and state; no session tokens, URLs, entered text, screenshots or workflow action payloads. Files are written by atomic replacement and private file permissions where supported.
- An in-flight native `SendInput` call cannot be forcibly undone. A cancelled native call may finish in the OS after cancellation; the checkpoint remains uncertain and there is no automatic retry. Desktop secure-desktop and active-target checks still apply.

## Example plan payload

The `steps` portion of a call to `workflow_execute`, targeting a tab ID returned after authenticated `browser_selected_tabs`:

```json
[
  {
    "step_id": "observe",
    "action": "browser.read",
    "target": "LOCALLY_SELECTED_TAB_ID",
    "selector": "#status"
  },
  {
    "step_id": "open",
    "action": "browser.click",
    "target": "LOCALLY_SELECTED_TAB_ID",
    "selector": "#open",
    "before": { "selector": "#status", "contains": "Ready" },
    "after": { "selector": "#status", "contains": "Opened" }
  }
]
```

The second step requires explicit local action approval. The placeholder tab ID must be replaced with the one returned by the approved local browser. Server-side checkpoints are never an authorization source.

## Acceptance and limits

`tests/orchestrator` covers schema limits, deterministic hashes, private files, session/grant denial, mandatory local action approval, pre/postcondition checks, read-only retries, interrupted-action uncertainty, cancellation, restart-safe checkpoints and in-memory MCP adapter calls. GitHub's required fast, PR build, Windows, browser, metadata, audit and security checks must all pass before merge.

This is a bounded serial workflow engine, not a general-purpose cross-application autonomous agent. Persistent event recovery, accessible local action approval UI, destructive-action semantics, cross-app transaction confirmation and real interactive Windows acceptance remain later delivery or release items.
