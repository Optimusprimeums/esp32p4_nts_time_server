# Phase 9B — Operations Hardening Implementation Contract

Status: implementation specification; **not** evidence of completed firmware validation.

## Baseline constraints
- Phase 8 is frozen. Do not modify timing-critical NTP/NTS packet paths, GNSS/PPS discipline, or authenticated time semantics to implement management features.
- Phase 9A ownership and provisioning require fresh-board validation before final acceptance.
- Partition table currently includes NVS, encrypted NVS keys, OTA metadata, factory + two OTA slots, certificate NVS, and encrypted core dump. There is **no dedicated audit-history partition**. Do not assume a writable SD card or unallocated flash.
- Do not store secrets, private keys, Cloudflare tokens, session credentials, NTS cookies, or raw client certificates in logs or configuration exports.

## 9B incremental integration sequence
1. Define a versioned, bounded event record with monotonic sequence, boot ID, monotonic uptime, optional trusted UTC, event type, severity, source, and sanitized metadata.
2. Add non-blocking producer interface. No NVS or SD writes on timing-critical callbacks. Management worker batches writes, enforces quotas, and reports dropped-event counters.
3. Choose persistent backing after inspecting flash budget and write endurance. Use a dedicated partition or an explicitly bounded SD-backed ring; do not silently consume the existing certificate NVS.
4. On startup, record reset reason and firmware identity; correlate crash metadata without exposing sensitive memory through the web API.
5. Add read-only paginated audit endpoint protected by existing ownership/authentication and CSRF rules as applicable; cap page sizes and redact sensitive fields.
6. Add configuration export/import using an explicit allowlist, schema version, size cap, integrity checks and dry-run validation. Exclude all credentials and device identity secrets by default. Apply changes atomically with rollback on validation or storage failure.
7. Extend dashboard and metrics with storage health, audit drops, last reset reason, boot count and restore status; do not expose high-cardinality event data in metrics.
8. Add failure-injection tests: full storage, corruption, interrupted writes, clock unsynchronized, reboots, concurrent requests, unauthenticated access and config rollback.

## Event contract
Suggested event categories: BOOT, RESET, FAULT, OWNERSHIP, AUTH, CONFIG, CERTIFICATE, ACME, OTA, STORAGE, NETWORK, GNSS, PPS, NTP_HEALTH, NTS_HEALTH.
Severity: INFO, WARN, ERROR, CRITICAL.
Each event must carry monotonic ordering even if UTC is unavailable. Trusted UTC must never be synthesized from uptime.

## Acceptance gates
- A full audit store does not block packet processing, GNSS/PPS handling, or management startup.
- Power loss cannot turn a partially written configuration into active settings.
- Unauthenticated clients cannot access audit history, reset details, configuration export, or restore.
- Audit history survives reboot within the chosen retention policy; overflow behavior is observable.
- No private material appears in logs, exports, API responses or metrics.
- NTP/NTS functional and timing regressions pass against the Phase 8 baseline.
- OTA rollback tests remain separate under Phase 9C; the existing dual OTA slots must be validated with the actual bootloader and image sizes.

## Immediate engineering prerequisite
Inspect existing diagnostics.c, device_config.c, web_console.c, app_main.c, CMakeLists.txt and partition/flash sizing before implementing the first persistent event backend. Do not claim this specification is deployed code.
