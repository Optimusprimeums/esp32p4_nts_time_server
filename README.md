# ESP32-P4 GNSS-Disciplined NTP Server

An ESP32-P4-based GNSS-disciplined Network Time Protocol version 4 (NTPv4) server using a u-blox LEA-M8T timing receiver, hardware-latched 1 PPS capture, IP101 Ethernet, basic NTP service, diagnostics, rate limiting, and a read-only web management console.

> **Current scope:** GNSS-disciplined basic NTP service and read-only operational management.  
> **Deferred scope:** NTS, TLS/mTLS, ACME, Cloudflare DNS-01, certificate lifecycle, authenticated configuration, mutable web endpoints, and symmetric peer operation.

---

## Contents

- [Current Features](#current-features)
- [Hardware Configuration](#hardware-configuration)
- [Build Environment](#build-environment)
- [Project Structure](#project-structure)
- [Build and Flash](#build-and-flash)
- [Runtime Validation](#runtime-validation)
- [Web Console](#web-console)
- [NTP Rate Limiting](#ntp-rate-limiting)
- [Clock States](#clock-states)
- [Security Posture](#security-posture)
- [Known Limitations](#known-limitations)
- [Future Additions](#future-additions)
- [Development Rules](#development-rules)

---

## Current Features

### GNSS Timing Reference

- u-blox **LEA-M8T** GNSS timing receiver support.
- UART1 GNSS interface at 115200 baud.
- Mixed NMEA and UBX receiver-stream processing.
- NMEA ZDA UTC fallback during commissioning.
- UBX startup configuration with ACK/NAK handling.
- UBX configuration for:
  - `UBX-NAV-PVT`
  - `UBX-NAV-TIMELS`
  - `UBX-TIM-TP`
  - NMEA ZDA
- UBX frame synchronization.
- UBX payload-length validation.
- UBX Fletcher checksum validation.
- GNSS UTC validity tracking.
- GNSS fix validity tracking.
- Satellite-count reporting.
- Fully-resolved UTC state tracking.
- Leap-second state handling.
- GPS-to-UTC leap-second offset handling.
- Bounded LEA-M8T NAV-TIMELS compatibility fallback when a plausible current leap-second value is present but the receiver does not assert the expected validity flag.

### PPS Capture and Clock Discipline

- Hardware-latched rising-edge 1 PPS capture using GPTimer and Event Task Matrix (ETM).
- PPS input on GPIO 5.
- PPS interval validation.
- PPS jitter measurement.
- PPS edge counter.
- PPS queue-drop counter.
- PPS stale-reference detection.
- GNSS/PPS UTC correlation using `UBX-TIM-TP`.
- GPS week/time-of-week conversion to UTC.
- TIM-TP quantization-error handling.
- Clock quality gates for:
  - Invalid PPS intervals.
  - Excessive PPS jitter.
  - Invalid GNSS UTC state.
  - Invalid GNSS fix state.
  - Invalid leap-second state.
  - Stale TIM-TP data.
  - Excessive timing-pulse quantization error.
- Bounded frequency estimation from PPS interval measurements.
- Conservative holdover root-dispersion growth.
- Fail-closed behavior after configured reference-loss limits.

### Clock State Model

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

### Ethernet

- IP101 Ethernet PHY support.
- ESP32-P4 internal Ethernet MAC support.
- DHCP IPv4 address acquisition.
- Ethernet link-up and link-down event handling.
- MAC address reporting.
- IPv4 address, netmask, and gateway reporting.
- Indefinite DHCP wait behavior without a timeout-triggered startup panic.

### Basic NTPv4 Service

- UDP NTP server on port 123.
- NTP version 3 and version 4 client-mode request handling.
- 48-byte NTP packet parsing and response generation.
- Client transmit timestamp copied into the NTP origin timestamp.
- Disciplined-clock server receive timestamp.
- Disciplined-clock server transmit timestamp.
- Stratum 1 advertisement while the clock is `SYNCHRONIZED`.
- Stratum 2 advertisement while the clock is in `HOLDOVER`.
- Fail-closed normal-request drops while the clock is:
  - `UNSYNCHRONIZED`
  - `ACQUIRING`
  - `FAIL_CLOSED`
- Per-client token-bucket rate limiting.
- `RATE` Kiss-o’-Death responses.
- NTP operational counters:
  - Requests received.
  - Normal responses sent.
  - Invalid requests.
  - Fail-closed drops.
  - `RATE` KoD responses.
  - Socket failures.
  - Send failures.
  - Last-client IPv4 address.
  - Advertised stratum.
  - Advertised leap indicator.
  - Root dispersion.

### Read-Only Web Console

The web console is intentionally read-only.

Available endpoints:

```text
GET /
GET /api/v1/status
GET /api/v1/health
GET /metrics
```

Console features:

- Live browser dashboard with automatic refresh.
- Clock state and synchronization status.
- Trusted UTC display when the clock is serviceable.
- Phase-error and frequency metrics.
- Holdover duration and root-dispersion display.
- GNSS UTC, fix, satellite, leap, and TIM-TP status.
- PPS period, jitter, age, edge count, and queue-drop status.
- Ethernet IPv4, netmask, gateway, link state, and MAC address.
- NTP request, response, KoD, fail-closed-drop, and socket state metrics.
- JSON status endpoint.
- Health endpoint:
  - `200 OK` when Ethernet, NTP socket, and trusted clock are ready.
  - `503 Service Unavailable` otherwise.
- Prometheus-style text metrics endpoint.
- Responsive metric layout with separated labels and values.

The web console does **not** currently provide:

- Authentication.
- HTTPS.
- Mutual TLS.
- Configuration changes.
- DNS changes.
- API-token storage.
- Certificate management.
- Private-key export.
- Reboot controls.
- Symmetric-peer management.

---

## Hardware Configuration

### Supported Hardware Baseline

| Item | Configuration |
|---|---|
| Target MCU | ESP32-P4 |
| Development Board | Guition JC-ESP32P4-M3-DEV |
| GNSS Receiver | u-blox LEA-M8T |
| Ethernet PHY | IP101 |
| Flash | 16 MB |
| PSRAM | 32 MB |

### Validated GPIO Assignments

| Function | Hardware Signal | ESP32-P4 GPIO |
|---|---|---:|
| GNSS PPS | LEA-M8T TIMEPULSE / TP1 | GPIO 5 |
| GNSS UART RX | LEA-M8T TXD to ESP32 RX | GPIO 2 |
| GNSS UART TX | ESP32 TX to LEA-M8T RXD | GPIO 3 |
| Ethernet PHY Address | IP101 | 1 |
| Ethernet MDC | IP101 management clock | GPIO 31 |
| Ethernet MDIO | IP101 management data | GPIO 52 |
| Ethernet PHY Reset | IP101 reset | GPIO 51 |

### GNSS Wiring

```text
LEA-M8T TIMEPULSE / TP1  ---> ESP32-P4 GPIO 5
LEA-M8T TXD              ---> ESP32-P4 GPIO 2
LEA-M8T RXD              <--- ESP32-P4 GPIO 3
LEA-M8T GND              ---  ESP32-P4 GND
```

### LEA-M8T Timing-Pulse Configuration

Expected receiver timing configuration:

```text
TIMEPULSE output:        TP1
Frequency unlocked:      1 Hz
Frequency locked:        1 Hz
Pulse width:             approximately 100 ms
Polarity:                rising edge / active high
ESP32 capture edge:      rising edge
```

---

## Build Environment

### Required Environment

| Item | Configuration |
|---|---|
| Operating System | Windows 11 |
| ESP-IDF Version | v6.1.0 |
| Installation Method | Espressif Installation Manager |
| Target | `esp32p4` |
| Toolchain | ESP32-P4 RISC-V toolchain installed by ESP-IDF |

### Security Configuration

```text
Secure Boot project features: disabled
Flash encryption:         board-specific hardware state
```

Do not assume a board is unencrypted merely because Secure Boot is disabled. Verify device eFuse state separately when required.

---

## Project Structure

```text
.
├── CMakeLists.txt
├── partitions.csv
├── sdkconfig.defaults
└── main/
    ├── CMakeLists.txt
    ├── app_config.h
    ├── app_main.c
    ├── app_state.c
    ├── app_state.h
    ├── clock_discipline.c
    ├── clock_discipline.h
    ├── diagnostics.c
    ├── diagnostics.h
    ├── eth_service.c
    ├── eth_service.h
    ├── gnss_service.c
    ├── gnss_service.h
    ├── ntp_packet.c
    ├── ntp_packet.h
    ├── ntp_rate_limit.c
    ├── ntp_rate_limit.h
    ├── ntp_server.c
    ├── ntp_server.h
    ├── ntp_types.h
    ├── pps_service.c
    ├── pps_service.h
    ├── web_console.c
    └── web_console.h
```

### Active Build Sources

The active `main/CMakeLists.txt` should include:

```text
app_main.c
app_state.c
pps_service.c
gnss_service.c
clock_discipline.c
diagnostics.c
eth_service.c
ntp_packet.c
ntp_rate_limit.c
ntp_server.c
web_console.c
```

---

## Build and Flash

Open an ESP-IDF v6.1 Command Prompt or PowerShell environment.

Build:

```powershell
idf.py build
```

Flash and monitor:

```powershell
idf.py flash monitor
```

When changing `main/CMakeLists.txt`, component dependencies, source-file lists, or major project configuration:

```powershell
Remove-Item -Recurse -Force .\build
idf.py reconfigure
idf.py build
idf.py flash monitor
```

---

## Expected Startup Sequence

A healthy system should report messages similar to:

```text
PPS: PPS ETM capture active
GNSS: LEA-M8T UBX configuration acknowledged
GNSS: LEA-M8T GNSS parser active
CLOCK: accepted initial PPS/GNSS sample
ETH: Ethernet link up
ETH: DHCP IPv4 acquired
NTP: NTP UDP server listening on port 123
WEB: Read-only HTTP console active on TCP/80
```

A healthy timing state should eventually show:

```text
clock=SYNCHRONIZED
solution=1
pps valid=1
GNSS UTC valid=1
GNSS fix valid=1
TIM-TP valid=1
Ethernet IPv4 ready=1
NTP socket bound=1
NTP advertised stratum=1
```

---

## Runtime Validation

### Web Console

```text
http://<device-ip>/
http://<device-ip>/api/v1/status
http://<device-ip>/api/v1/health
http://<device-ip>/metrics
```

### Windows NTP Test

```powershell
w32tm /stripchart /computer:<device-ip> /dataonly /samples:5
```

### Linux NTP Test

```bash
ntpdate -q <device-ip>
```

---

## NTP Rate Limiting

The default NTP rate limiter is intentionally conservative:

```c
#define APP_NTP_RATE_BURST                      8U
#define APP_NTP_RATE_PER_MINUTE                 30U
```

During high-rate testing, the normal-response count can be significantly lower than total requests received because excess requests receive `RATE` Kiss-o’-Death responses.

For a temporary laboratory stress test only:

```c
#define APP_NTP_RATE_BURST                      1000U
#define APP_NTP_RATE_PER_MINUTE                 60000U
```

Do not retain those values for deployment.

A more moderate operational setting is:

```c
#define APP_NTP_RATE_BURST                      16U
#define APP_NTP_RATE_PER_MINUTE                 120U
```

---

## Security Posture

Current security model:

```text
Trusted local management network required
Read-only HTTP status console
No secrets displayed
No write endpoints
No configuration updates
No certificate/key operations
No NTS
No TLS/mTLS
```

Before exposing the device outside a trusted management network, implement and validate:

```text
HTTPS
Mutual TLS
Authenticated authorization policy
Protected configuration storage
Certificate lifecycle
Management audit logging
```

---

## Known Limitations

- No Network Time Security (NTS).
- No NTS-KE service.
- No NTS cookies.
- No NTS authenticated NTP extension processing.
- No TLS.
- No mutual TLS.
- No ACME certificate lifecycle.
- No Cloudflare DNS-01 automation.
- No authenticated management controls.
- No mutable web configuration.
- No private-key export.
- No symmetric-peer implementation.
- No automatic NTP peer failover.
- No EMAC hardware receive timestamping.
- No EMAC hardware transmit timestamping.
- No PTP hardware time-counter integration.
- No claim of nanosecond or sub-microsecond wire-level NTP accuracy.

The current NTP timestamp path uses the software disciplined GPTimer timebase.

---

## Technical Debt

### TIM-TP Quantization Field Naming

The GNSS status member currently named:

```c
timing_quantization_error_ns
```

contains the raw `UBX-TIM-TP qErr` value interpreted as picoseconds.

Clock-discipline code converts it before use:

```c
qerr_ns = timing_quantization_error_ns / 1000;
```

A future cleanup should rename the field to:

```c
timing_quantization_error_ps
```

### NTP Reference Timestamp

The NTP server currently uses a current disciplined timestamp as its reference timestamp marker.

A future refinement should expose the exact timestamp of the most recent accepted GNSS/PPS reference sample from the clock-discipline module.

---

## Deferred Modules

The following modules are deferred and should not be reintroduced without deliberate integration work:

```text
nts_aes_siv.c
nts_aes_siv.h
nts_cookie.c
nts_cookie.h
nts_packet.c
nts_packet.h
nts_ke.c
nts_ke.h
key_store.c
key_store.h
nts_provisioning.c
nts_provisioning_uart.c
health.c
```

### NTS Status

```text
NTS is intentionally deferred.
Do not start TCP/4460.
Do not add NTS files back to CMake.
Do not enable certificate, cookie, key-store, or provisioning code.
```

---

## Future Additions

### Management Plane Phase 5B

- Device DNS hostname storage and display.
- Device hostname update workflow.
- Persistent non-secret configuration abstraction.
- Authenticated management controls.
- HTTPS web server.
- Mutual TLS client-certificate authentication.
- Role-based management authorization.
- Configuration audit logging.
- Controlled reboot workflow.
- Configuration import/export policy.

### ACME and DNS Lifecycle

- Let’s Encrypt ACME client.
- Cloudflare DNS-01 challenge support.
- Cloudflare API-token storage.
- ACME account-key storage.
- DNS zone-ID storage.
- Certificate-renewal monitoring.
- Certificate validity display in the web console.
- Controlled certificate replacement workflow.

### Symmetric Peer and Peer Monitoring

- Configurable NTP peer monitoring.
- Peer reachability tracking.
- Peer offset and delay measurement.
- Peer health display in the web console.
- Peer anomaly alerting.
- Symmetric peer-key storage.
- Symmetric peer-key upload through authenticated management.
- Optional controlled failover policy after validation and review.

### NTS

NTS remains deferred and must not be enabled unless specifically required.

Potential future NTS work:

- Protected key storage.
- Custom NVS certificate partition initialization.
- NTS cookie key ring.
- Cookie rotation.
- NTS packet extension-field handling.
- AEAD authentication.
- NTS-KE TLS server.
- TLS exporter handling.
- Certificate provisioning.
- NTS client interoperability testing.

---

## Development Rules

1. Preserve ESP-IDF v6.1.0 compatibility.
2. Preserve current GPIO assignments:
   - PPS GPIO 5
   - GNSS RX GPIO 2
   - GNSS TX GPIO 3
   - Ethernet MDC GPIO 31
   - Ethernet MDIO GPIO 52
   - Ethernet reset GPIO 51
3. Do not enable Secure Boot project features.
4. Do not reintroduce NTS unless explicitly directed.
5. Preserve PPS/GNSS clock fail-closed behavior.
6. Advertise NTP Stratum 1 only while `SYNCHRONIZED`.
7. Treat `HOLDOVER` as degraded service with increased root dispersion.
8. Keep the web console read-only until authenticated management is implemented.
9. Provide complete replacement files when modifying source.
10. Do not claim a build or test passed unless verified by actual build or test output.