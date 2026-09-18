# ESP32-P4 GNSS-Disciplined NTP Server

A GNSS-disciplined NTP server for the ESP32-P4 using a u-blox LEA-M8T timing receiver, GPTimer/ETM PPS capture, an IP101 Ethernet PHY, a fail-closed clock discipline, and an authenticated HTTPS management plane.

> **Current baseline:** Phase 5 is frozen. Phase 5B management/security, ACME certificate lifecycle, automatic renewal, and the final management dashboard are part of the frozen baseline.

## Platform

| Item | Configuration |
|---|---|
| MCU | ESP32-P4 |
| ESP-IDF | v6.1.0 |
| Host | Windows 11 / Espressif Installation Manager |
| Flash | 16 MB |
| PSRAM | 32 MB |
| GNSS | u-blox LEA-M8T |
| Ethernet PHY | IP101 |
| Secure Boot | **Disabled by project policy** |
| Flash encryption | Enabled on the provisioned target, Development Mode |
| Management | HTTPS on TCP/443 with mandatory mTLS |
| NTP | UDP/123, NTP versions 1-4 client requests |

### Validated pin assignments

```text
GNSS PPS / TIMEPULSE: GPIO 5
GNSS UART1 RX:        GPIO 2  <- GNSS TXD
GNSS UART1 TX:        GPIO 3  -> GNSS RXD

Ethernet PHY address: 1
Ethernet MDC:         GPIO 31
Ethernet MDIO:        GPIO 52
Ethernet PHY reset:   GPIO 51
```

## Timing architecture

PPS is captured with GPTimer/ETM rather than a software GPIO interrupt timestamp. GNSS UART processing supplies the UTC/time metadata that is correlated with the captured PPS edge.

The clock state machine is:

```text
UNSYNCHRONIZED
    ->
ACQUIRING
    ->
SYNCHRONIZED
    ->
HOLDOVER
    ->
FAIL_CLOSED
```

The service advertises:

```text
SYNCHRONIZED -> NTP Stratum 1
HOLDOVER     -> NTP Stratum 2 with growing root dispersion
otherwise    -> normal NTP service fails closed
```

Implemented timing inputs and quality controls include:

- UBX-NAV-PVT
- UBX-NAV-TIMELS
- UBX-TIM-TP
- NMEA ZDA fallback
- GPS week/TOW to UTC conversion
- leap-second state handling
- PPS/GNSS UTC correlation
- PPS interval/jitter quality gates
- TIM-TP quantization-error quality gate
- holdover dispersion growth
- GNSS receiver identity through UBX-MON-VER

The LEA-M8T NAV-TIMELS compatibility fallback remains deliberately bounded. Pending or imminent leap events remain fail-closed.

### Timing limitations

The Ethernet MAC is not providing hardware RX/TX timestamps to this implementation. NTP timestamps therefore use the software-disciplined timebase; this project does **not** claim nanosecond or sub-microsecond wire-level NTP accuracy.

The NTP reference timestamp is currently a current disciplined timestamp rather than the exact last accepted PPS/GNSS reference instant.

The legacy status field named `timing_quantization_error_ns` contains the raw UBX-TIM-TP `qErr` value interpreted by this code as picoseconds. The web/API correctly presents it as picoseconds.

## NTP server

The NTP service listens on UDP/123 and supports NTPv1 through NTPv4 client requests. NTPv1 acceptance was added for compatibility with Windows `w32tm /stripchart`.

Implemented behavior includes:

- 48-byte NTP request/response handling
- origin timestamp copied from the client's transmit timestamp
- receive/transmit timestamps from the disciplined clock
- Stratum 1 only while synchronized
- Stratum 2 during holdover
- fail-closed behavior outside serviceable clock states
- per-client token-bucket rate limiting
- `RATE` Kiss-o'-Death responses
- operational counters and last-client observability

## Phase 5B management and security

Phase 5B replaced the original unauthenticated HTTP/read-only management plane with an authenticated HTTPS management system.

### Device configuration

The device has persistent protected configuration with schema/version tracking. The current configuration schema stores the device hostname and Cloudflare configuration metadata. Hostname changes persist across reboot.

Default device hostname:

```text
esp32p4-ntp
```

### HTTPS and mutual TLS

Management is served over HTTPS on TCP/443.

```text
HTTP/80:       not used
HTTPS/443:     enabled
Client cert:   mandatory
Management CA: independent of the public server-certificate chain
```

The development management client certificate used during Phase 5 validation was `ntp-admin`. Management authentication must not be weakened merely to avoid browser secondary-connection TLS alerts.

### Management endpoints

Core status endpoints:

```text
GET  /
GET  /api/v1/status
GET  /api/v1/health
GET  /metrics
```

Authenticated configuration/operations include:

```text
GET  /api/v1/config
PUT  /api/v1/config/hostname

PUT    /api/v1/config/cloudflare
DELETE /api/v1/config/cloudflare
POST   /api/v1/config/cloudflare/verify

POST   /api/v1/cloudflare/dns01
POST   /api/v1/cloudflare/dns01/query
DELETE /api/v1/cloudflare/dns01

GET  /api/v1/acme/production/certificate
GET  /api/v1/acme/production/certificate/lifecycle
POST /api/v1/acme/production/certificate/renew
GET  /api/v1/acme/production/renewal/scheduler

POST /api/v1/system/reboot
```

Additional certificate activation/export/lifecycle endpoints exist in the Phase 5B management implementation. Temporary Phase 5B test endpoints were removed before freeze.

### Cloudflare DNS-01

Cloudflare integration stores the required protected configuration without returning or logging the API token.

The DNS-01 implementation supports:

- token and zone verification before configuration commit
- zone ID discovery
- TXT record creation
- exact-content TXT query validation
- exact-content deletion using record ID, type, DNS name, and expected challenge value
- fail-closed handling when the expected TXT content does not match

The API token should be limited to the required Zone Read and DNS Write/Edit permissions.

### ACME / Let's Encrypt

Phase 5B implements Let's Encrypt ACME v2 using DNS-01.

Implemented lifecycle:

- persistent P-256 ACME account key
- ES256 ACME signing
- staging issuance path
- production issuance path
- Cloudflare DNS-01 challenge creation and cleanup
- certificate/key inspection
- persistent production certificate storage
- dual-slot atomic certificate storage
- boot-time production TLS selection
- last-known-good TLS transition handling
- manual renewal
- automatic renewal scheduler
- automatic TLS activation
- persistent renewal attempt/outcome/handoff state
- bounded existing-account `badNonce` retry with a fresh nonce and re-sign
- recovery/cooldown protections

Automatic renewal is policy-gated rather than blindly forcing issuance. The manual management renewal endpoint uses the same renewal policy and refuses an unnecessary production renewal while the certificate has more than the configured renewal threshold remaining.

The current renewal policy uses:

```text
renewal threshold: 30 days remaining
urgent threshold:   7 days remaining
scheduler interval: approximately 6 hours
```

A true persisted "last renewed" timestamp is not currently maintained for every issuance path; the management dashboard therefore reports certificate validity and persisted renewal-attempt/activation information rather than inventing a renewal timestamp.

### Management dashboard

The frozen Phase 5 dashboard displays live clock, PPS, GNSS receiver, NTP, network, certificate/ACME, and system-operation information.

Wide-screen layout uses independent vertical column stacks:

```text
Clock and Time       PPS Capture       GNSS Receiver       Certificate & ACME
NTP Service          Network           System Actions
```

This prevents the taller certificate card from forcing unrelated lower cards downward.

The GNSS card includes receiver-reported UBX-MON-VER identity, software version, and hardware version. The certificate hostname is displayed without wrapping `ts1.nicknewman.au`.

System Actions provides authenticated controls for:

- guarded production certificate renewal
- device reboot

## Protected storage and flash security

The target uses flash encryption. **Secure Boot must remain disabled.**

The current partition layout is:

```csv
# Name,      Type, SubType, Offset,   Size,     Flags
nvs,         data, nvs,     0x10000,  0x6000,
nvs_keys,    data, nvs_keys,0x16000,  0x1000,   encrypted
otadata,     data, ota,     0x17000,  0x2000,
phy_init,    data, phy,     0x19000,  0x1000,
factory,     app,  factory,0x20000,  0x1C0000,
ota_0,       app,  ota_0,   0x1E0000, 0x1C0000,
ota_1,       app,  ota_1,   0x3A0000, 0x1C0000,
nvs_certs,   data, nvs,     0x560000, 0x20000,
coredump,    data, coredump,0x580000, 0x10000,  encrypted
```

The `nvs_certs` partition is intentionally separate and certificate/ACME code must initialize/open it explicitly.

Do **not** erase `nvs_keys` on the provisioned device.

### ESP-IDF v6.1 local workaround

The development ESP-IDF tree currently contains a local guard correction in:

```text
components/nvs_sec_provider/nvs_sec_provider.c
```

using:

```c
#if SOC_HMAC_SUPPORTED && CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC
```

rather than compiling the HMAC-specific path solely on `SOC_HMAC_SUPPORTED`.

This makes the local ESP-IDF checkout appear `v6.1-dirty`. Treat this as technical debt to re-evaluate when moving to a later ESP-IDF release; do not invent an HMAC key ID or change the provisioned eFuse plan to work around it.

## Building and flashing

Build from the project root:

```powershell
idf.py build
```

Because the provisioned target has flash encryption enabled, use the encrypted flash workflow:

```powershell
idf.py -p COM11 encrypted-flash --all
```

Do **not** use ordinary:

```text
idf.py flash
```

on this provisioned target.

Do not manually burn additional eFuses, alter the flash-encryption key/count, or enable Secure Boot unless a separate provisioning plan has first been designed and verified.

## Expected Startup Sequence

A normal Phase 5B boot should progress approximately as follows. Exact log ordering can vary because services run concurrently.

1. **Bootloader / flash security**
   - ESP32-P4 boots the encrypted factory image.
   - Flash-encryption state is checked.
   - Secure Boot remains disabled.

2. **NVS and protected configuration**
   - default NVS is initialized.
   - encrypted NVS key handling is initialized.
   - the custom `nvs_certs` partition is initialized explicitly.
   - device configuration schema/generation is loaded.
   - persisted hostname is restored.
   - Cloudflare configuration metadata is restored without exposing the token.

3. **ACME/certificate persistent state**
   - persistent ACME account key/state is loaded.
   - production certificate dual-slot metadata is inspected.
   - activation intent/outcome/handoff recovery state is evaluated.
   - last-known-good TLS protections are applied if a previous transition was interrupted.
   - the persisted production certificate is selected for boot when configured and valid; otherwise the allowed fallback TLS source is used.

4. **PPS capture**
   - GPTimer and ETM PPS capture are initialized.
   - GPIO 5 rising-edge timing becomes available to the discipline path.

5. **GNSS UART and receiver setup**
   - UART1 starts on GPIO 2 RX / GPIO 3 TX.
   - UBX startup configuration is applied and ACK/NAK processing runs.
   - NAV-PVT, NAV-TIMELS and TIM-TP data begin arriving.
   - a read-only UBX-MON-VER poll obtains receiver model/software/hardware identity.
   - NMEA ZDA remains available as a fallback time source.

6. **Clock acquisition**
   - GNSS UTC validity, leap state, TIM-TP and PPS are correlated.
   - the clock progresses from `UNSYNCHRONIZED` to `ACQUIRING`.
   - only accepted timing samples update the disciplined clock.
   - after quality/acquisition requirements are met, state becomes `SYNCHRONIZED`.

7. **Ethernet**
   - IP101 is initialized at PHY address 1 using MDC 31, MDIO 52 and reset 51.
   - link comes up.
   - DHCP obtains IPv4 configuration.
   - the configured device hostname is used by the management/status plane.

8. **NTP**
   - UDP/123 is bound.
   - while synchronized the server advertises Stratum 1.
   - NTPv1-v4 client requests are accepted.
   - rate limiting and RATE KoD protection are active.
   - if timing later degrades into HOLDOVER, service moves to Stratum 2 with increasing root dispersion.
   - unserviceable timing states fail closed.

9. **HTTPS management**
   - HTTPS starts on TCP/443.
   - the selected server certificate/key are loaded.
   - the independent management CA is configured.
   - TLS client-certificate authentication is mandatory.
   - dashboard, status, health, metrics, configuration, Cloudflare, ACME and system-operation endpoints become available.
   - no unauthenticated HTTP/80 management service is started.

10. **Automatic certificate-renewal scheduler**
    - persisted automatic-renewal configuration is restored.
    - the first scheduler evaluation occurs after the startup delay (approximately 30 seconds).
    - normal evaluation repeats approximately every six hours.
    - certificate eligibility, clock validity, network state, transaction state and activation interlocks are checked.
    - a certificate that is not due is observed without issuing a replacement.
    - when due and all interlocks pass, the reusable production renewal transaction may execute, persist the new candidate, activate it through the protected TLS handoff path, and preserve recovery state.

11. **Healthy steady state**
    - `/api/v1/health` returns HTTP 200 with `ntp_ready:true`.
    - dashboard reports GNSS/PPS/clock/network/NTP state.
    - receiver identity is populated from UBX-MON-VER when reported by the receiver.
    - certificate/ACME lifecycle information is visible to the authenticated administrator.
    - NTP clients such as `w32tm` and NTPTool receive valid service.

Expected healthy timing/NTP state:

```text
clock = SYNCHRONIZED
solution_valid = true
PPS valid = true
GNSS UTC valid = true
GNSS fix valid = true
TIM-TP valid = true
Ethernet IPv4 ready = true
NTP socket bound = true
advertised stratum = 1
```

## Runtime checks

Management requires a trusted client certificate.

```text
https://<device-ip>/
https://<device-ip>/api/v1/status
https://<device-ip>/api/v1/health
https://<device-ip>/metrics
```

Windows NTP compatibility check:

```powershell
w32tm /stripchart /computer:<device-ip> /dataonly /samples:5
```

The Phase 5B validation also used NTPTool successfully after the NTPv1 compatibility update.

## Known technical debt

- No Ethernet hardware RX/TX timestamping or PTP integration.
- NTP reference timestamp is not yet the exact last accepted PPS reference timestamp.
- `timing_quantization_error_ns` remains a legacy/misleading internal field name for raw picosecond qErr data.
- Initial ACME new-account JWK requests do not currently share the bounded existing-account `badNonce` retry path.
- DNS-01 verification currently uses the implemented DNS/Cloudflare verification path; an authoritative DNS resolver path remains a possible hardening addition.
- The local ESP-IDF v6.1 NVS security-provider guard workaround should be revisited on SDK upgrade.
- Secure Boot is intentionally not part of this project's security model.

## Future additions

Phase 5 is frozen. Future work should be added as a new phase rather than silently changing the Phase 5 baseline.

Recommended future additions include:

1. **Symmetric peer health monitoring — observe only**
   - configure one or more peer NTP servers
   - measure reachability, delay and offset
   - expose peer state through HTTPS/API/metrics
   - do not discipline the GNSS clock or alter stratum automatically

2. **Exact NTP reference timestamp**
   - expose the exact last accepted PPS/GNSS reference instant from the clock discipline
   - use it as the NTP reference timestamp

3. **Timestamping/accuracy investigation**
   - characterize software receive/transmit latency
   - investigate any ESP32-P4/IP101 timestamping capabilities that can be used without making unsupported accuracy claims
   - consider PTP only as a separately designed feature

4. **ACME/DNS hardening**
   - extend bounded `badNonce` handling to the initial new-account JWK path
   - consider authoritative DNS propagation verification
   - add further lifecycle diagnostics only where they do not expose secrets

5. **Management-plane hardening and operations**
   - review CSRF protections for mutable browser endpoints
   - expand audit/event history for configuration and certificate operations
   - consider role separation if multiple management identities are introduced

6. **OTA lifecycle**
   - design authenticated OTA around the existing `ota_0`/`ota_1` partition layout
   - define rollback and image-integrity policy compatible with flash encryption and the deliberate decision not to use Secure Boot
   - do not introduce OTA as an incidental management endpoint

7. **Internal cleanup**
   - rename the TIM-TP qErr status field to reflect picoseconds
   - remove obsolete compatibility/development code only after regression testing
   - re-evaluate the ESP-IDF NVS workaround on SDK upgrade

### NTS remains deferred

Network Time Security is **not** part of the Phase 5 frozen baseline.

Do not casually reintroduce the previously deferred NTS modules, TCP/4460 listener, cookie/key-store code, or old provisioning code. If NTS is resumed, treat it as a new explicitly planned phase and reconcile it with the current mTLS/ACME/protected-storage architecture first.

## Engineering invariants

When extending the project:

- preserve ESP-IDF v6.1.0 compatibility until an SDK migration is explicitly planned
- preserve the validated GPIO assignments
- do not enable Secure Boot
- preserve flash-encryption provisioning assumptions
- preserve fail-closed timing behavior
- advertise Stratum 1 only while `SYNCHRONIZED`
- treat HOLDOVER as degraded Stratum 2 service with growing dispersion
- never expose Cloudflare tokens or private keys through status APIs/logs
- preserve mandatory mTLS for management
- preserve the independent management CA when rotating the public server certificate
- do not reintroduce NTS unless explicitly planned
- use complete source replacements for controlled source changes
- do not claim a change is compiled or runtime-tested until it actually has been validated
