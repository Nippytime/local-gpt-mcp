# Durable gateway STOP — single-host foundation (Issue #29)

This is an independently testable, **operator-opt-in** denial ledger for the existing read-only outbound agent. It is not a global Windows STOP, cross-host durable relay, public web release, or owner-approved remote input implementation. Issue #23 remains open until execution-time approval/STOP is integrated; #24 remains unverified.

## Private first-time provisioning

1. On the POSIX gateway host, create a **service-user-owned, private mode-0700 directory** that is not a symlink. Never place the database in the repository, temporary shared folders, or a web-served directory.
2. While running as that service user, **provision exactly once**:

   ```sh
   python -c 'from pathlib import Path; from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger; SQLiteStopLedger.provision(Path("/private/local-mcp/stop.sqlite"))'
   ```

3. Supply `LOCAL_MCP_STOP_DB=/private/local-mcp/stop.sqlite` to the gateway process. This opt-in variable opens **only an existing, valid database**: missing, corrupt, shared-permission, linked or improperly owned state rejects startup and further operations. Ordinary service restart must never reinitialize an erased STOP decision. Keep sensitive credential material out of the ledger.
4. The authenticated owner may `POST /api/owner/halt` with a real `devices:manage` OAuth bearer. The owner identity is **always derived from token verification**, not from request JSON. No model-facing MCP tool can call `halt_owner` or undo an owner halt. `/api/owner/revoke` also persists revocation for the specific authenticated owner/device when the ledger is configured.
5. A stopped owner's future enrollment, signed poll, read and results are denied; pending read jobs are canceled in that process. A revoked device is rejected by every instance sharing this ledger. STOP is irreversible through service APIs and must not be reset by replacing/restoring the database.

## Bounds and limitations

- Without `LOCAL_MCP_STOP_DB`, the existing read-only agent remains available, but `/api/owner/halt` **returns denial** rather than pretending a persistent global STOP exists. Local physical STOP remains independently authoritative.
- SQLite shares denial state across processes on **one** protected host. Existing in-memory pairing/enrollment, nonce caches and job queues are **not** restart-safe or multi-host; do not scale gateway workers or claim durable message delivery based solely on this ledger.
- Network delay, offline PCs and already-dispatched work cannot be canceled retrospectively. Integrate owner STOP checks into the independently authorized remote action relay and locally pinned Windows policy, with real physical lock/UAC/STOP tests before enabling public remote input.
- No new dependencies or relaxed checks. Run strict Fast, PR, Audit, Security and Windows gates on the exact branch head.
