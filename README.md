# ESP32-P4 NTP/NTS Time Server

## Baseline

- Target: ESP32-P4
- Framework: ESP-IDF v6.1.x
- Service ports:
  - NTP/NTS: UDP 123
  - NTS-KE: TCP 4460
- Full NTP Intergration - PPS/NMEA sourced timing with Leap Second adjustments
- NTS intergation - Work in progress
  - NTS profile:
    - TLS 1.3
    - ALPN `ntske/1`
    - AEAD_AES_SIV_CMAC_256
- Web management - Not fully implemented, only stats
- Interleaved NTP, ACME, and symmetric peering currently in the works
