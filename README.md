# ESP32-P4 GNSS-Disciplined NTP Server

A GNSS-disciplined NTP server for the ESP32-P4 using a u-blox LEA-M8T
timing receiver, GPTimer/ETM PPS capture, ESP32-P4 EMAC/PTP hardware
timestamping, an IP101 Ethernet PHY, a fail-closed clock discipline, and
an authenticated HTTPS management plane.

> **Current production baseline:** Phase 5B management/security and
> certificate lifecycle are frozen. Phase 6 NTP hardware timestamping,
> precision optimization, end-to-end validation, production stability,
> and startup PTP/UTC correlation optimization are **VALIDATED /
> FROZEN**. The HP-LP independent PPS health-supervision track is **PASS
> / FROZEN / CLOSED**. Phase 7 **NTS-Intergration** is **PASS /
> CLOSED**, with the NTS subsystem **VALIDATED / FROZEN**.


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
| NTS | NTS-KE on TCP/4460; NTS-protected NTP on UDP/123 |
| Ethernet timing | ESP32-P4 EMAC PTP hardware RX/TX timestamp support integrated |
| LP core | Independent passive GNSS PPS health supervisor; no timing authority |

### Validated pin assignments

``` text
GNSS PPS / TIMEPULSE: GPIO 5
GNSS UART1 RX:        GPIO 2  <- GNSS TXD
GNSS UART1 TX:        GPIO 3  -> GNSS RXD

Ethernet PHY address: 1
Ethernet MDC:         GPIO 31
Ethernet MDIO:        GPIO 52
Ethernet PHY reset:   GPIO 51
```

## Timing architecture

PPS is captured with GPTimer/ETM rather than a software GPIO interrupt
timestamp. GNSS UART processing supplies UTC/time metadata correlated
with the captured PPS edge. The disciplined UTC clock remains the timing
authority.

The clock state machine is:

``` text
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

``` text
SYNCHRONIZED -> NTP Stratum 1
HOLDOVER     -> NTP Stratum 2 with growing root dispersion
otherwise    -> normal NTP service fails closed
```

Implemented timing inputs and quality controls include:

-   UBX-NAV-PVT
-   UBX-NAV-TIMELS
-   UBX-TIM-TP
-   NMEA ZDA fallback
-   GPS week/TOW to UTC conversion
-   leap-second state handling
-   PPS/GNSS UTC correlation
-   PPS interval/jitter quality gates
-   TIM-TP quantization-error quality gate
-   holdover dispersion growth
-   GNSS receiver identity through UBX-MON-VER
-   ESP32-P4 EMAC PTP hardware clock
-   qualified PTP-to-UTC correlation
-   authoritative Ethernet hardware RX timestamps
-   late-L2 NTP transmit timestamp placement
-   descriptor hardware TX timestamp verification

The LEA-M8T NAV-TIMELS compatibility fallback remains deliberately
bounded. Pending or imminent leap events remain fail-closed.

### Phase 6 hardware timestamp architecture

Phase 6 replaced the former software-only Ethernet timestamp limitation.

The ESP32-P4 EMAC PTP clock is enabled and used as the Ethernet hardware
timestamp domain. Hardware timestamps are converted into disciplined UTC
through a qualified PTP-to-UTC correlation.

The receive path is fail-closed:

``` text
Ethernet descriptor HW RX timestamp
             +
qualified PTP -> UTC correlation
             |
             v
authoritative NTP receive timestamp
```

If the hardware timestamp or qualified mapping is unavailable, the
implementation does not substitute raw PTP time as UTC.

The transmit path remains standard one-packet NTP:

``` text
build NTP response
      |
late T3/XMT placement
      |
fixed predictive compensation
      |
MAC/DMA handoff
      |
descriptor HW TX timestamp
      |
verification / diagnostics
```

The descriptor hardware TX timestamp is available after transmission, so
it is used to verify the late software T3/XMT path rather than
attempting non-standard two-step NTP.

The final frozen compensation is:

``` c
#define ETH_NTP_TX_COMPENSATION_NS 98941ULL
```

Do not retune this value as incidental cleanup. Recalibration requires a
separate measurement gate if the Ethernet/DMA/toolchain/timestamp path
materially changes.

### PTP-to-UTC correlation startup behavior

The authoritative hardware RX path requires at least two valid PTP/UTC
correlation samples.

The final acquisition policy is:

``` c
#define ETH_PTP_CORRELATION_PERIOD_MS             10000U
#define ETH_PTP_CORRELATION_ACQUIRE_PERIOD_MS      1000U
#define ETH_PTP_CORRELATION_INITIAL_DELAY_MS       5000U
```

Before two valid samples are available, correlation is attempted every 1
second. After qualification, the task automatically returns to the
original 10-second maintenance cadence.

Measured optimized startup:

``` text
34.342 s  PTP correlation n=1
35.342 s  PTP correlation n=2
36.651 s  first authoritative HW RX / confirmed normal NTP response path
37.514 s  first periodic DIAG clock=SYNCHRONIZED print
37.535 s  DIAG valid_rsp=1, stratum=1, li=0
```

The periodic diagnostic task can report `SYNCHRONIZED` after the
underlying disciplined timestamp API is already usable. Diagnostic log
cadence is observational and is not service authority.

The previous observed post-diagnostic readiness delay was approximately
11.8 seconds. With the acquisition optimization, the post-diagnostic
readiness delay is 0 seconds while preserving the two-sample
qualification and fail-closed mapping rules.

### Remaining timing limitations

The legacy status field named `timing_quantization_error_ns` contains
the raw UBX-TIM-TP `qErr` value interpreted by this code as picoseconds.
The web/API correctly presents it as picoseconds.

The fixed 98,941 ns transmit prediction is validated for the current
ESP-IDF v6.1 hardware/software transmit path; it is not a universal
ESP32-P4 constant.

## NTP server

The NTP service listens on UDP/123 and supports NTPv1 through NTPv4
client requests. NTPv1 acceptance was added for compatibility with
Windows `w32tm /stripchart`.

Implemented behavior includes:

-   48-byte NTP request/response handling
-   origin timestamp copied from the client's transmit timestamp
-   disciplined reference/receive/transmit timestamp generation
-   authoritative mapped hardware RX timestamp integration
-   late-L2 T3/XMT timestamp placement
-   descriptor hardware TX timestamp verification
-   fixed 98,941 ns TX prediction
-   Stratum 1 only while synchronized
-   Stratum 2 during holdover
-   fail-closed behavior outside serviceable clock states
-   fail-closed hardware RX mapping qualification
-   per-client token-bucket rate limiting
-   `RATE` Kiss-o'-Death responses
-   operational counters and last-client observability

High-rate repeated `w32tm /samples:1` probing can trigger normal RATE
KoD behavior and is not representative of the intended deployment load.

## Phase 5B management and security

Phase 5B replaced the original unauthenticated HTTP/read-only management
plane with an authenticated HTTPS management system.

### Device configuration

The device has persistent protected configuration with schema/version
tracking. The current configuration schema stores the device hostname
and Cloudflare configuration metadata. Hostname changes persist across
reboot.

The configured device name is intentionally not documented here.

### HTTPS and mutual TLS

Management is served over HTTPS on TCP/443.

``` text
HTTP/80:       not used
HTTPS/443:     enabled
Client cert:   mandatory
Management CA: independent of the public server-certificate chain
```

The development management client certificate used during Phase 5
validation was `ntp-admin`. Management authentication must not be
weakened merely to avoid browser secondary/speculative connection TLS
alerts.

Chromium can create additional connections that fail the mandatory
client-certificate handshake and produce messages such as:

``` text
esp-tls-mbedtls: mbedtls_ssl_handshake returned -0x7780
esp_https_server: esp_tls_create_server_session failed, 0x7780
httpd: httpd_accept_conn: session creation failed
```

These messages have been observed while the valid authenticated
management session continues to work. Do not weaken mTLS to suppress
them.

### Management endpoints

Core status endpoints:

``` text
GET  /
GET  /api/v1/status
GET  /api/v1/health
GET  /metrics
```

Authenticated configuration/operations include:

``` text
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

Additional certificate activation/export/lifecycle endpoints exist in
the Phase 5B management implementation. Temporary Phase 5B test
endpoints were removed before freeze.

### Cloudflare DNS-01

Cloudflare integration stores the required protected configuration
without returning or logging the API token.

The DNS-01 implementation supports:

-   token and zone verification before configuration commit
-   zone ID discovery
-   TXT record creation
-   exact-content TXT query validation
-   exact-content deletion using record ID, type, DNS name, and expected
    challenge value
-   fail-closed handling when the expected TXT content does not match

The API token should be limited to the required Zone Read and DNS
Write/Edit permissions.

### ACME / Let's Encrypt

Phase 5B implements Let's Encrypt ACME v2 using DNS-01.

Implemented lifecycle:

-   persistent P-256 ACME account key
-   ES256 ACME signing
-   staging issuance path
-   production issuance path
-   Cloudflare DNS-01 challenge creation and cleanup
-   certificate/key inspection
-   persistent production certificate storage
-   dual-slot atomic certificate storage
-   boot-time production TLS selection
-   last-known-good TLS transition handling
-   manual renewal
-   automatic renewal scheduler
-   automatic TLS activation
-   persistent renewal attempt/outcome/handoff state
-   bounded existing-account `badNonce` retry with a fresh nonce and
    re-sign
-   recovery/cooldown protections

Automatic renewal is policy-gated rather than blindly forcing issuance.
The manual management renewal endpoint uses the same renewal policy and
refuses an unnecessary production renewal while the certificate has more
than the configured renewal threshold remaining.

The current renewal policy uses:

``` text
renewal threshold: 30 days remaining
urgent threshold:   7 days remaining
scheduler interval: approximately 6 hours
```

A true persisted "last renewed" timestamp is not currently maintained
for every issuance path; the management dashboard therefore reports
certificate validity and persisted renewal-attempt/activation
information rather than inventing a renewal timestamp.

### Management dashboard

The management dashboard displays live clock, PPS, GNSS receiver, NTP,
NTS, network, certificate/ACME, and system-operation information.

Wide-screen layout uses independent vertical column stacks:

``` text
Header: live Clock / NTP / GNSS / Certificate / Renewal status

Column 1             Column 2             Column 3          Column 4
Clock and Time       PPS Capture          GNSS Receiver     Certificate & ACME
NTP Service          NTS Service          Network
System Actions       API Locations
```

The NTS Service card exposes NTS-KE state and exchange counters together
with authenticated-request and protected-response counters. It also
reports TLS handshake, ALPN, verification, and response-protection
failures. The same NTS observability is available through
`/api/v1/status` and `/metrics`.

The GNSS card includes receiver-reported UBX-MON-VER identity, software
version, and hardware version. The certificate identity is displayed
without wrapping.

System Actions provides authenticated controls for:

-   guarded production certificate renewal
-   device reboot

## Phase 6 validation

### Phase 6A --- disciplined clock and NTP behavior

Phase 6A validated synchronized operation, holdover behavior, recovery,
root-dispersion growth, NTP compatibility, rate limiting, and
fail-closed service behavior.

**Status: PASS / FROZEN.**

### Phase 6B --- timestamp-path measurement

Phase 6B instrumented the NTP request/response path to distinguish
disciplined-clock quality from receive/transmit packet-path latency and
established the need for Ethernet hardware timestamping.

**Status: PASS.**

### Phase 6C --- hardware timestamping and TX precision

Phase 6C enabled the ESP32-P4 EMAC PTP clock, established PTP-to-UTC
correlation, made mapped hardware RX timestamps authoritative,
integrated late-L2 transmit timestamp construction, and used descriptor
hardware TX timestamps for verification.

Final precision optimization:

``` text
6C.5   TX architecture/proof        PASS / FROZEN
6C.6   Late-L2 XMT integration      PASS / FROZEN
6C.7A  Structural TX optimization   PASS / FROZEN
6C.7B  Predictive compensation      PASS
6C.7C  +98,941 ns refinement        PASS / FROZEN
6C.7   TX precision optimization    PASS / FROZEN
6C     NTP hardware timestamping    PASS / FROZEN
```

The final 6C.7C validation set contained 151/151 stamped packets, with
an XMT-to-hardware median residual of approximately +0.807 microseconds
and standard deviation approximately 4.402 microseconds.

### Phase 6D --- independent end-to-end validation

Validation included:

-   external Windows `w32tm` testing
-   investigation of an apparent approximately 27 ppm trend
-   resolution of that trend as Windows/common-mode rather than server
    clock drift
-   independent Raspberry Pi Stratum-1 cross-reference
-   independent absolute phase cross-check

``` text
6D.1   External w32tm validation                  PASS
6D.2   apparent ~27 ppm drift                     RESOLVED as Windows/common-mode
6D.3   independent Pi Stratum-1 cross-reference   PASS
6D.4   independent absolute phase cross-check     PASS
6D     end-to-end NTP validation                  PASS / FROZEN
```

### Phase 6E --- stability and production restoration

Validation included:

``` text
6E.1   30-minute disciplined-clock soak          PASS / FROZEN
6E.2   sustained NTP request load:
       service reliability                       PASS
       TX latency variation                      CHARACTERIZED
6E.2A  cadence/state isolation                   PASS / FROZEN
6E.2B  TX latency localization                   PASS / FROZEN
6E.2C  fixed power/clock isolation               PASS / FROZEN
6E.2D  cache/memory path isolation               PASS / FROZEN
6E.2E  descriptor/cache-state isolation          PASS / FROZEN
6E.2F  CPU execution-state isolation             PASS / FROZEN
```

Power management, DFS, and sleep were ruled out as the cause of the
observed TX timing regimes. The remaining variation was localized to the
Ethernet descriptor/cache/DMA preparation region rather than the
disciplined clock.

Broad exploratory TX investigation was closed after 6E.2F.

Production instrumentation was then removed and the clean production
path was revalidated:

``` text
Production restoration               PASS
Single-request production regression PASS
24-request production regression     PASS
Final NTP-specific production soak   WAIVED
6E long-duration/production stability PASS / CLOSED
```

The final extra NTP-specific production soak was waived because the real
deployment is approximately one NTP client updating about hourly and the
completed validation substantially exceeded that request load.

### Final Phase 6 gate

``` text
Startup PTP/UTC correlation optimization PASS / FROZEN
NTP subsystem                            VALIDATED / FROZEN
```

## Phase 7 --- NTS-Intergration

Phase 7 integrated Network Time Security around the frozen production
NTP timing path. NTS adds authentication authority only; it does not own
or alter GNSS/PPS discipline, authoritative hardware RX timestamping,
late-L2 T3/XMT placement, or the frozen transmit compensation.

### Phase 7A --- architecture and integration boundary

The integration reused the existing Phase 5B production ACME certificate
and private-key lifecycle for the NTS-KE TLS server identity. Management
HTTPS on TCP/443 remains independently protected by mandatory
client-certificate mTLS. No second TLS certificate authority or
certificate store was introduced.

``` text
NTS-KE TLS identity          existing production ACME certificate/key
NTS-KE transport             TCP/4460
Management HTTPS             TCP/443, mandatory mTLS, unchanged
NTP transport                UDP/123, unchanged
Timing authority             existing disciplined NTP path, unchanged
HW RX authority              authoritative / fail-closed, unchanged
Late-L2 T3/XMT               unchanged
TX compensation              98,941 ns / FROZEN
```

**Phase 7A: PASS / FROZEN.**

### Phase 7B --- cryptographic and cookie foundation

NTS cookie-key persistence uses the existing encrypted `nvs_certs`
partition under a separate `nts` namespace. The NTS cookie
implementation uses AES-SIV-CMAC-256 with authenticated cookie metadata
and fail-closed validation. The production key ring maintains previous,
active, and next key slots.

``` text
nvs_certs
├── namespace "acme"    ACME account state
└── namespace "nts"     NTS cookie key ring

NTS AEAD                  AES-SIV-CMAC-256 / algorithm 15
Cookie clear prefix       master-key ID + nonce
Cookie validation         key ID, format/version, issue/expiry, authentication
```

**Phase 7B: PASS / FROZEN.**

### Phase 7C --- NTS-KE server

NTS-KE is served on TCP/4460 using TLS 1.3 and ALPN `ntske/1`. The
server negotiates NTPv4 as the next protocol and AES-SIV-CMAC-256 as the
AEAD, and issues eight initial cookies. The NTS-KE endpoint does not
require the management-plane client certificate.

``` text
TCP port                     4460
TLS                          1.3
ALPN                         ntske/1
Next Protocol                NTPv4 / 0
AEAD                         AES-SIV-CMAC-256 / 15
Initial cookies              8
Cookie size                  128 bytes
```

**Phase 7C: PASS / FROZEN.**

### Phase 7D --- NTS-protected NTP

NTS extension-field processing wraps the existing UDP/123 NTP response
path. Authenticated requests are verified with the cookie-derived C2S
key. Responses echo the Unique Identifier, issue fresh cookies, and are
authenticated with the S2C key. The existing authoritative mapped
hardware RX timestamp remains T2, and the existing late-L2 path remains
responsible for T3/XMT.

``` text
NTS request
  -> existing HW RX timestamp
  -> parse UID / Cookie / Authenticator
  -> decrypt cookie and authenticate with C2S
  -> existing production NTP response construction
  -> append NTS response fields and authenticate with S2C
  -> existing late-L2 T3/XMT + 98,941 ns prediction
  -> MAC/DMA
```

Invalid NTS authentication fails closed without producing an
authenticated response. Conventional non-NTS NTP service remains
supported and was regression-tested.

**Phase 7D: PASS / FROZEN.**

### Phase 7E --- key lifecycle and persistence

The previous/active/next cookie-key lifecycle, promotion, persistence
across reboot, and missing/corrupt-state handling were validated.
Production test seams were removed after validation.

**Phase 7E: PASS / FROZEN.**

### Phase 7F --- interoperability and production regression

Interoperability was validated with chrony 4.5 using:

``` text
server <configured-server> nts iburst minpoll 2 maxpoll 4
```

Six consecutive validation trials acquired the NTS source in
approximately 3-4 seconds. A final post-dashboard regression selected
`the configured NTS source` in approximately 3 seconds.

Final live observability confirmed one completed NTS-KE exchange
followed by nine authenticated NTS requests and nine protected
responses, with zero NTS-KE exchange failures, zero ALPN rejections,
zero verification failures, and zero response-protection failures. Two
TLS handshake failures recorded during the final test session were
caused by deliberate raw TCP reachability probes that opened TCP/4460
without performing TLS.

``` text
NTS-KE Running              YES
NTS-KE Exchanges              1
NTS-KE Failures               0
TLS Handshake Failures        2   raw TCP probes
ALPN Rejections               0
Verification Attempts         9
Authenticated Requests        9
Verification Failures         0
Protected Responses           9
Protection Failures           0
```

The NTP production path remained synchronized and fail-closed
protections remained intact during NTS validation.

**Phase 7F: PASS / FROZEN.**

### Final Phase 7 gate

``` text
7A  NTS architecture + integration boundary       PASS / FROZEN
7B  NTS key/cookie cryptographic foundation        PASS / FROZEN
7C  NTS-KE server on TCP/4460                      PASS / FROZEN
7D  NTS-protected NTP packet processing            PASS / FROZEN
7E  key rotation / persistence / failure handling  PASS / FROZEN
7F  interoperability + production regression       PASS / FROZEN

Phase 7 NTS-Intergration                           PASS / CLOSED
NTS subsystem                                      VALIDATED / FROZEN
```

## Protected storage and flash security

The target uses flash encryption. **Secure Boot must remain disabled.**

The current partition layout is:

``` csv
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

The `nvs_certs` partition is intentionally separate and certificate/ACME
code must initialize/open it explicitly.

Do **not** erase `nvs_keys` on the provisioned device.

### ESP-IDF v6.1 local NVS workaround

The development ESP-IDF tree currently contains a local guard correction
in:

``` text
components/nvs_sec_provider/nvs_sec_provider.c
```

using:

``` c
#if SOC_HMAC_SUPPORTED && CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC
```

rather than compiling the HMAC-specific path solely on
`SOC_HMAC_SUPPORTED`.

This makes the local ESP-IDF checkout appear `v6.1-dirty`. Treat this as
technical debt to re-evaluate when moving to a later ESP-IDF release; do
not invent an HMAC key ID or change the provisioned eFuse plan to work
around it.

### ESP-IDF Ethernet maintenance surface

Phase 6 required low-level ESP32-P4 Ethernet DMA/descriptor timestamp
work. Any project-local ESP-IDF Ethernet changes must be treated as an
explicit maintenance surface.

When upgrading ESP-IDF:

-   compare the project-local Ethernet/DMA changes against the new SDK
-   verify RX/TX descriptor timestamp ABI
-   verify descriptor cache writeback/invalidation behavior
-   rebuild the PTP-to-UTC mapping tests
-   rerun the late-TX compensation measurement
-   do not assume 98,941 ns remains correct after a material
    transmit-path change

Temporary 6E diagnostic/instrumentation variants are not production
source.

## Building and flashing

Build from the project root:

``` powershell
idf.py build
```

Because the provisioned target has flash encryption enabled, use the
encrypted flash workflow:

``` powershell
idf.py -p COM11 encrypted-flash --all
```

Do **not** use ordinary:

``` text
idf.py flash
```

on this provisioned target.

Do not manually burn additional eFuses, alter the flash-encryption
key/count, or enable Secure Boot unless a separate provisioning plan has
first been designed and verified.

## Expected startup sequence

Exact log ordering can vary because services run concurrently.

1.  **Bootloader / flash security**
    -   ESP32-P4 boots the encrypted image.
    -   Flash-encryption state is checked.
    -   Secure Boot remains disabled.
2.  **NVS and protected configuration**
    -   default NVS is initialized.
    -   encrypted NVS key handling is initialized.
    -   `nvs_certs` is initialized explicitly.
    -   device configuration and protected Cloudflare metadata are
        restored.
3.  **ACME/certificate persistent state**
    -   persistent ACME account state is loaded.
    -   production certificate dual-slot/recovery state is evaluated.
    -   last-known-good TLS protections are applied.
    -   the permitted TLS source is selected.
4.  **HP-LP PPS health supervision**
    -   LP firmware starts as an independent passive PPS health
        observer.
    -   GPIO 4 is the LP observer input; GPIO 5 remains the
        authoritative HP PPS input.
    -   LP supervision has no GNSS, clock-discipline, Ethernet, or NTP
        authority.
5.  **PPS capture**
    -   GPTimer and ETM PPS capture initialize.
    -   GPIO 5 rising-edge timing becomes available to the discipline
        path.
6.  **GNSS UART and receiver setup**
    -   UART1 starts on GPIO 2 RX / GPIO 3 TX.
    -   UBX startup configuration is applied.
    -   NAV-PVT, NAV-TIMELS and TIM-TP begin arriving.
    -   UBX-MON-VER obtains receiver identity.
    -   NMEA ZDA remains available as fallback.
7.  **Clock acquisition**
    -   GNSS UTC, leap state, TIM-TP and PPS are correlated.
    -   the clock progresses through acquisition.
    -   only accepted timing samples update the disciplined clock.
    -   after quality/acquisition requirements pass, the state becomes
        `SYNCHRONIZED`.
8.  **Ethernet and PTP**
    -   IP101 initializes at PHY address 1.
    -   Ethernet link and IPv4 come up.
    -   ESP32-P4 EMAC PTP hardware clock is active.
    -   PTP-to-UTC correlation acquisition runs.
    -   two valid correlation samples qualify the authoritative mapped
        hardware RX path.
9.  **NTP**
    -   UDP/123 is bound.
    -   synchronized service advertises Stratum 1.
    -   NTPv1-v4 requests are accepted.
    -   rate limiting and RATE KoD protection are active.
    -   hardware RX timestamps are mapped to UTC when qualified.
    -   T3/XMT is placed on the late-L2 path with the frozen 98,941 ns
        prediction.
    -   descriptor hardware TX timestamps provide verification.
    -   HOLDOVER moves service to Stratum 2 with increasing root
        dispersion.
    -   unserviceable states fail closed.
10. **NTS-KE and NTS-protected NTP**
    -   NTS-KE starts on TCP/4460 using TLS 1.3 and ALPN `ntske/1`.
    -   the existing production ACME certificate/key supplies the NTS-KE
        TLS identity.
    -   NTS cookies and cookie-key state are restored from protected
        storage.
    -   authenticated NTS requests wrap the frozen UDP/123 timing path
        without taking timing authority.
11. **HTTPS management**
    -   HTTPS starts on TCP/443.
    -   selected server certificate/key are loaded.
    -   independent management CA is configured.
    -   TLS client-certificate authentication is mandatory.
    -   dashboard/status/health/metrics/configuration/Cloudflare/ACME/system
        endpoints become available.
    -   no unauthenticated HTTP/80 management service is started.
12. **Automatic certificate-renewal scheduler**
    -   persisted automatic-renewal configuration is restored.
    -   the first evaluation occurs after its startup delay.
    -   normal evaluation repeats approximately every six hours.
    -   issuance and activation remain policy/interlock gated.
13. **Healthy steady state**
    -   `/api/v1/health` returns HTTP 200 with `ntp_ready:true`.
    -   dashboard reports GNSS/PPS/clock/network/NTP/NTS state.
    -   PTP/UTC correlation remains maintained at its 10-second
        steady-state cadence.
    -   NTP clients receive validated service.
    -   NTS clients can acquire authenticated time through NTS-KE plus
        protected NTP.
    -   management remains protected by mTLS.

Expected healthy timing/NTP state:

``` text
clock = SYNCHRONIZED
solution_valid = true
PPS valid = true
GNSS UTC valid = true
GNSS fix valid = true
TIM-TP valid = true
Ethernet IPv4 ready = true
PTP clock running = true
PTP/UTC correlation samples >= 2
NTP socket bound = true
advertised stratum = 1
HW RX authority = qualified
TX compensation = 98941 ns
```

## Runtime checks

Management requires a trusted client certificate.

``` text
https://<management-endpoint>/
https://<management-endpoint>/api/v1/status
https://<management-endpoint>/api/v1/health
https://<management-endpoint>/metrics
```

Windows NTP compatibility check:

``` powershell
w32tm /stripchart /computer:<management-endpoint> /dataonly /samples:5
```

The Phase 5B validation also used NTPTool successfully after the NTPv1
compatibility update.

NTS interoperability check uses chrony with the production hostname:

``` text
server <configured-server> nts iburst minpoll 2 maxpoll 4
```

A successful test selects `the configured NTS source` after completing
NTS-KE and authenticated NTP exchanges.

For startup investigation only, repeated one-sample `w32tm` invocations
were used to identify readiness behavior. This is a stress probe and can
trigger RATE KoD responses; it is not the normal runtime validation
cadence.

## HP-LP independent PPS health supervision

The HP-LP track is complete and frozen. The LP core is an independent
passive observer of GNSS PPS health and has no production timing
authority.

``` text
GPIO 5 -> HP authoritative PPS via GPIO ISR + GPIO ETM -> GPTimer
GPIO 4 -> LP passive PPS observer

HP timing authority              UNCHANGED
LP timing authority              NONE
LP interval plausibility         ENABLED
LP autonomous loss watchdog      2.5 PPS periods
LP loss/recovery counters        ENABLED
```

Final fault-injection validation disconnected GPIO 4 while GPIO 5
remained authoritative. The LP observer transitioned HEALTHY -\> LOST
and recorded one loss while production timing remained synchronized with
valid NTP responses and zero drops. Reconnecting GPIO 4 produced LOST
-\> HEALTHY with one recovery and no duplicate events. Final production
NTP regression passed.

``` text
HP-LP.1-7   Core LP proof                         PASS / FROZEN
HP-LP.8     Independent PPS health supervision    PASS / FROZEN
HP-LP.9     Production regression / closeout      PASS / FROZEN
HP-LP                                             CLOSED
```

No further LP timing work is planned for the frozen baseline.

## Known technical debt

-   `timing_quantization_error_ns` remains a legacy/misleading internal
    field name for raw picosecond qErr data.
-   Initial ACME new-account JWK requests do not currently share the
    bounded existing-account `badNonce` retry path.
-   DNS-01 verification currently uses the implemented DNS/Cloudflare
    verification path; an authoritative DNS resolver path remains a
    possible hardening addition.
-   The local ESP-IDF v6.1 NVS security-provider guard workaround should
    be revisited on SDK upgrade.
-   Low-level Ethernet/DMA timestamp integration must be reconciled and
    revalidated on ESP-IDF upgrade.
-   The fixed 98,941 ns TX compensation must be remeasured after a
    material Ethernet/DMA/toolchain path change.
-   Chromium speculative/parallel mTLS handshake failures remain visible
    in logs; authentication must not be weakened to remove them.
-   Diagnostic log cadence can lag actual clock/readiness state and must
    remain observational.
-   The final additional NTP-specific production soak was waived based
    on the very low deployment request rate and heavier completed
    validation; reopen only if deployment load or architecture changes
    materially.
-   LP PPS supervision remains strictly non-authoritative; future LP
    changes must preserve GPIO 5 HP timing authority and the validated
    GPIO 4 observer path.
-   NTS cookie-key persistence and NTS-KE certificate reuse must remain
    aligned with the protected-storage and ACME lifecycle when those
    subsystems change.
-   Secure Boot is intentionally not part of this project's security
    model.

## Phase 8 --- Peer Health Monitoring

Phase 8 adds read-only NTP peer observation around the frozen
GNSS/PPS-disciplined clock. Peer measurements are telemetry only and
have no timing authority.

``` text
GNSS / PPS -> disciplined UTC -> Peer Monitor (READ ONLY)
                                      |
                                      X
                               NO WRITE-BACK
```

The peer monitor supports up to four configured peers using IPv4
addresses or DNS names. It performs NTPv4 client polling and records
T1/T2/T3/T4-derived offset and delay, reachability, jitter, rolling
statistics, stratum, leap indicator, reference ID, root delay, root
dispersion, success/failure counts, last-success age, and
protocol-validation counters.

Per-peer health states are:

``` text
UNKNOWN
HEALTHY
DEGRADED
UNREACHABLE
DIVERGENT
KOD
INVALID
DISABLED
```

Cross-peer telemetry includes observed offset spread, divergence
detection, and a best-observed-peer indicator. The best-observed
calculation is telemetry only and cannot select or discipline the
production clock.

### Phase 8A --- architecture and peer-monitor engine

The implementation preserves the one-way timing-authority boundary. T1
and T4 are read from the existing disciplined clock, but peer
observations are never submitted to clock discipline.

Response validation covers source/length, leap indicator, NTP version
and mode, stratum, originate timestamp, nonzero receive/transmit
timestamps, KoD, duplicate/stale transmit timestamps, negative delay,
malformed responses, and timeouts.

Rolling statistics use integer arithmetic. Floating-point `long double`,
`llroundl()`, and `sqrtl()` were removed from the peer-monitor task
after runtime fault isolation.

**Status: PASS / FROZEN**

### Phase 8B --- configuration and observability

Peer configuration supports up to four peers with persisted enable
state, server, poll interval, and response timeout. The validated limits
are:

``` text
maximum peers          4
poll interval minimum  4 seconds
poll interval maximum  3600 seconds
default poll interval  16 seconds
timeout minimum        250 ms
timeout maximum        10000 ms
default timeout        2000 ms
rolling window         16 samples
```

Peer-monitor state is exposed through the authenticated management
dashboard, `/api/v1/status`, and `/metrics`. Configuration changes reset
the affected slot's runtime statistics.

The management dashboard includes peer health, reachability, offset,
delay, jitter, stratum, reference ID, rolling sample count, last-success
age, poll counts, rejected responses, duplicate responses, cross-peer
spread, and the best-observed peer.

The final management layout is:

``` text
Column 1: Clock and Time -> PPS Capture -> GNSS Receiver
Column 2: NTP Service -> NTS Service -> API Locations
Column 3: Network -> Peer Monitoring
Column 4: Certificate & ACME -> System Actions
```

The status-only advertised-stratum reporting path reads the existing
server quality without mutating production timing state.

**Status: PASS / FROZEN**

### Phase 8C --- validation and production regression

Validation exercised normal and adverse peer behavior while observing
the production timing, NTP, NTS, and management paths.

``` text
8C.1  Peer response / packet validation       PASS / FROZEN
8C.2  Unreachable peer + recovery             PASS / FROZEN
8C.3  KoD / invalid / malformed handling      PASS / FROZEN
8C.4  Multi-peer disagreement / divergence    PASS / FROZEN
8C.5  Extended peer-monitor soak              PASS / FROZEN
8C.6  Production NTP regression               PASS / FROZEN
8C.7  Production NTS regression               PASS / FROZEN
8C.8  Timing-authority isolation proof        PASS / FROZEN
8C.9  Phase 8 closeout / freeze               PASS / CLOSED
```

Deterministic response testing covered valid replies, KoD, bad originate
timestamps, short/malformed packets, duplicate transmit timestamps, and
clean recovery. Additional testing proved unreachable-peer isolation and
multi-peer divergence reporting.

Peer polling is deliberately serialized. At most one peer-monitor UDP
socket is active at a time. This prevents an unreachable peer from
holding multiple peer sockets concurrently and preserves production
service availability under resource pressure.

The extended production soak exceeded 60 minutes and 225 peer-monitor
cycles. The three normal production peers accumulated 906 successful
polls with zero failures during the targeted soak. No reboot, stack
fault, or timing-authority disturbance occurred.

The final conventional-NTP regression completed 100 requests at a
5-second cadence with valid synchronized Stratum-1 responses.

The final NTS regression completed NTS-KE with TLS 1.3, ALPN `ntske/1`,
AEAD 15, and eight initial cookies, followed by 100 authenticated NTS
requests and 100 protected responses with zero verification or
protection failures.

Timing-authority isolation was demonstrated while peer states included
HEALTHY, DEGRADED, DIVERGENT, UNREACHABLE, KOD, INVALID, malformed,
duplicate, timeout, and recovery conditions. The GNSS/PPS-disciplined
clock remained authoritative and synchronized. Peer-monitor observations
never write back into clock discipline.

### Phase 8 frozen runtime invariants

``` text
NTP peer task stack       12288 bytes
HTTPS management stack   12288 bytes
ACME renewal task stack   12288 bytes
Peer polling              sequential
Maximum active peer UDP sockets during polling  1
Peer timing authority     NONE
```

Do not reduce these task stacks without a new fault-driven validation
gate. Do not restore concurrent peer polling without an explicit
resource and production-regression gate.

Phase 8 does not change any Phase 6 or Phase 7 timing/security
authority:

-   GNSS/PPS remains the only production clock-discipline authority.
-   GPIO 5 HP PPS remains authoritative; GPIO 4 LP remains
    observational.
-   Ethernet hardware RX timestamp authority remains fail-closed.
-   Late-L2 T3/XMT placement remains frozen.
-   `ETH_NTP_TX_COMPENSATION_NS = 98941ULL` remains frozen.
-   Peer measurements cannot alter clock discipline, stratum, leap
    state, PTP/UTC mapping, NTP timestamps, NTS authentication, or
    NTS-KE.
-   NTS remains an authentication wrapper around the frozen NTP timing
    path.
-   Management mTLS remains mandatory.

**Phase 8 Peer Health Monitoring: PASS / CLOSED**

**Peer-monitor subsystem: VALIDATED / FROZEN**

## Future additions

Phase 5B, Phase 6, HP-LP supervision, Phase 7 NTS-Intergration, and
Phase 8 Peer Health Monitoring are frozen. Future work must be
introduced through explicit new gates rather than silently changing the
validated baseline.

1.  **Symmetric peer health monitoring --- observe only**
    -   configure one or more peer NTP servers
    -   measure reachability, delay and offset
    -   expose peer state through HTTPS/API/metrics
    -   do not discipline the GNSS clock or alter stratum automatically
2.  **ACME/DNS hardening**
    -   extend bounded `badNonce` handling to the initial new-account
        JWK path
    -   consider authoritative DNS propagation verification
    -   add lifecycle diagnostics only where they do not expose secrets
3.  **Management-plane hardening and operations**
    -   review CSRF protections for mutable browser endpoints
    -   expand audit/event history for configuration and certificate
        operations
    -   consider role separation if multiple management identities are
        introduced
4.  **OTA lifecycle**
    -   design authenticated OTA around the existing `ota_0`/`ota_1`
        partition layout
    -   define rollback and image-integrity policy compatible with flash
        encryption and the deliberate decision not to use Secure Boot
    -   do not introduce OTA as an incidental management endpoint
5.  **SDK/toolchain maintenance**
    -   re-evaluate the local NVS workaround on SDK upgrade
    -   reconcile Ethernet/DMA timestamp changes with upstream ESP-IDF
    -   rerun Phase 6 hardware timestamp and TX compensation validation
        after material SDK/toolchain changes
    -   rerun NTS interoperability and protected-storage regression
        after material TLS/crypto/storage changes
6.  **Internal cleanup**
    -   rename the TIM-TP qErr status field to reflect picoseconds
    -   remove obsolete compatibility/development code only after
        regression testing
    -   preserve clean production copies of low-level Ethernet changes

## Engineering invariants

When extending the project:

-   preserve ESP-IDF v6.1.0 compatibility until an SDK migration is
    explicitly planned
-   preserve the validated GPIO assignments
-   do not enable Secure Boot
-   preserve flash-encryption provisioning assumptions
-   preserve fail-closed timing behavior
-   advertise Stratum 1 only while `SYNCHRONIZED`
-   treat HOLDOVER as degraded Stratum 2 service with growing dispersion
-   preserve authoritative hardware RX fail-closed behavior
-   preserve the two-sample PTP/UTC correlation qualification
-   preserve 1-second acquisition and 10-second steady-state correlation
    cadence
-   preserve the PTP/UTC mapping mathematics
-   preserve the standard one-packet late-L2 NTP transmit architecture
-   preserve `ETH_NTP_TX_COMPENSATION_NS = 98941ULL` until an explicit
    recalibration gate
-   never expose Cloudflare tokens or private keys through status
    APIs/logs
-   preserve mandatory mTLS for management
-   preserve the independent management CA when rotating the public
    server certificate
-   do not weaken mTLS to hide expected rejected/speculative browser
    connections
-   preserve HP PPS/GNSS/clock/Ethernet/NTP authority; LP PPS
    supervision remains non-authoritative
-   preserve NTS-KE use of the existing production ACME certificate/key
    lifecycle
-   preserve separation between management mTLS authentication and
    NTS-KE TLS
-   preserve NTS authentication as a wrapper around, not a replacement
    for, the frozen NTP timing path
-   preserve peer monitoring as telemetry only with no clock-discipline
    write-back
-   preserve sequential peer polling with at most one peer-monitor UDP
    socket active at a time
-   preserve `NTP_PEER_TASK_STACK_SIZE = 12288U`
-   preserve `APP_WEB_CONSOLE_STACK_SIZE = 12288U`
-   preserve `APP_ACME_RENEWAL_TASK_STACK_SIZE = 12288U`
-   use complete source replacements for controlled source changes
-   do not claim a change is compiled or runtime-tested until it
    actually has been validated

## Current engineering gate

``` text
Phase 5B management/security baseline       PASS / FROZEN

Phase 6A disciplined-clock/NTP behavior     PASS / FROZEN
Phase 6B timestamp-path measurement         PASS
Phase 6C hardware timestamping              PASS / FROZEN
Phase 6D end-to-end validation              PASS / FROZEN
Phase 6E production stability               PASS / CLOSED
Startup PTP/UTC correlation optimization    PASS / FROZEN
NTP subsystem                               VALIDATED / FROZEN

HP-LP.1-7 core LP proof                     PASS / FROZEN
HP-LP.8 independent PPS health supervision  PASS / FROZEN
HP-LP.9 production regression / closeout    PASS / FROZEN
HP-LP                                       CLOSED

Phase 7A architecture / integration         PASS / FROZEN
Phase 7B crypto / cookie foundation         PASS / FROZEN
Phase 7C NTS-KE TCP/4460                    PASS / FROZEN
Phase 7D NTS-protected NTP                  PASS / FROZEN
Phase 7E key lifecycle / persistence        PASS / FROZEN
Phase 7F interoperability / regression      PASS / FROZEN
Phase 7 NTS-Intergration                    PASS / CLOSED
NTS subsystem                               VALIDATED / FROZEN


Phase 8A architecture / peer-monitor engine PASS / FROZEN
Phase 8B config / observability             PASS / FROZEN
Phase 8C validation / production regression PASS / FROZEN
Phase 8 Peer Health Monitoring              PASS / CLOSED
Peer-monitor subsystem                      VALIDATED / FROZEN
```
