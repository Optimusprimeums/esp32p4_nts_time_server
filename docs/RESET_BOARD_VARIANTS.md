# Reset support across ESP32-P4 board variants

The firmware supports boards with and without an externally accessible main ESP32-P4 `CHIP_PU` reset signal. **No physical PCB modifications or additional GPIO allocation are required.**

| Capability | Main `CHIP_PU` exposed | Main `CHIP_PU` not exposed |
| --- | --- | --- |
| Authenticated HTTPS management reboot | Yes | Yes |
| Firmware-triggered reboot via `esp_restart()` | Yes | Yes |
| Onboard physical reset button, if fitted | Yes | Yes |
| External dedicated hardware reset connection | Yes, via the manufacturer's exposed reset interface | Not supported without external reset access |
| Reset-reason display | Yes | Yes |

## Existing management interface

- The web UI already exposes **Reboot Device**.
- `POST /api/v1/system/reboot` schedules `esp_restart()` and returns HTTP 202 when successfully scheduled.
- The management interface displays the current boot's reset reason.
- This endpoint is part of the management HTTPS interface; preserve its existing access controls.

## Hardware guidance

- `CHIP_PU` is a dedicated chip enable/reset input, **not** a configurable GPIO.
- Where the manufacturer exposes main `CHIP_PU`, an appropriately designed external open-drain or normally-open pull-down reset may be used, subject to board-specific electrical verification. Do not drive it high externally.
- **Do not confuse ESP32-C6 `C6_CHIP_PU` with the main ESP32-P4 `CHIP_PU`.**
- Where main `CHIP_PU` is not exposed, do not claim that a spare GPIO or `esp_restart()` provides an equivalent out-of-band hardware reset.
- Do not solder to reset switches, modify traces, or change either board to gain reset access.

## Operational limits

An authenticated software reboot requires the firmware, scheduler and management network to be functioning. It cannot recover a fully unresponsive device in every failure mode. Hardware watchdog recovery and the onboard physical reset button remain independent recovery mechanisms to the extent supported by each board.

## Deployment safety

TS1 production hardware must remain untouched pending the established release gates and explicit authorization. Validate any changed reset behavior only on TS2. This documentation update does not change firmware or initiate flashing.
