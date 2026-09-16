# ESP32-P4 NTP/NTS Time Server

## Baseline

- Target: ESP32-P4
- Framework: ESP-IDF v6.1.x
- Service ports:
  - NTP/NTS: UDP 123
  - NTS-KE: TCP 4460
- NTS profile:
  - TLS 1.3
  - ALPN `ntske/1`
  - AEAD_AES_SIV_CMAC_256
- Interleaved NTP: disabled by default
- Web management, ACME, and symmetric peering: disabled by default
