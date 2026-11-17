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
- SQLite shares denial state across processes on **one** protected host. When the nonce schema is installed, signed device request replay nonces also survive restarts and are atomically denied across local processes. With the v2 schema, trusted device public-key enrollment survives a gateway restart and loads **offline** until a fresh signed heartbeat. Pending enrollment codes and job queues are still **in-memory** and not restart-safe or multi-host; do not scale gateway workers or claim durable message delivery based solely on this ledger.
- Network delay, offline PCs and already-dispatched work cannot be canceled retrospectively. Integrate owner STOP checks into the independently authorized remote action relay and locally pinned Windows policy, with real physical lock/UAC/STOP tests before enabling public remote input.
- No new dependencies or relaxed checks. Run strict Fast, PR, Audit, Security and Windows gates on the exact branch head.

## Signed device nonce replay migration (Issue #31)

Fresh `SQLiteStopLedger.provision(...)` installations create both the signed nonce table and trusted-device public-key table automatically. For an **existing** private database provisioned under Issue #29, stop all gateway processes and, as the same POSIX service user, explicitly upgrade it **once** before deploying this code:

```sh
python -c 'from pathlib import Path; from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger; SQLiteStopLedger.upgrade_nonce_store(Path("/private/local-mcp/stop.sqlite"))'
```

Normal startup **never creates** a missing nonce table or silently upgrades the schema. An absent, damaged, downgraded, or already-upgraded store fails closed. Preserve the original halt and revoke decisions; don't delete or restore historical STOP data to permit an old device. The protected store records only device IDs, random nonce IDs, and expiry timestamps (no private keys, bearer tokens, signatures, requests or PC data). At most 20,000 unexpired nonce claims can be accepted per host; capacity and database errors deny traffic, not fall back to an in-memory cache.

**This remains single-host replay protection, not production multi-worker support.** Device identity enrollment and read/action queues still reside in process memory. An already dispatched remote action still requires independent native PC policy and STOP enforcement; owner first-passkey registration, hosted OAuth, physical Windows and ChatGPT web E2E remain unverified.

## Trusted device public-key migration (Issue #33)

An existing private STOP/nonce ledger with schema version **1** requires a deliberate, one-time upgrade before deploying this code. Stop the single gateway worker and run as the same POSIX service user:

```sh
python -c 'from pathlib import Path; from local_gpt_mcp.policy.stop_ledger import SQLiteStopLedger; SQLiteStopLedger.upgrade_device_store(Path("/private/local-mcp/stop.sqlite"))'
```

Fresh provision creates version **2** directly. A historical version-0 ledger may use `upgrade_nonce_store(...)`, which now provisions both nonce and trusted-device tables. Ordinary process startup **never upgrades** any old/missing/corrupt schema and must fail closed.

The store persists only verified owner IDs, device IDs, human-readable labels and their Ed25519 **public** keys. Private credentials, enrollment codes, OAuth tokens, request bodies and approval receipts never enter the database. A restarted relay lists previously enrolled PCs **offline** until a fresh signed authenticated poll; it cannot replay prior jobs, cached heartbeats or pending pairing codes. Revocation/owner STOP remain authoritative over restored keys. In-memory queues and work remain unsafe for distributed execution.
