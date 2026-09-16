#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#include "app_state.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool initialized;

    /*
     * UTC state. UTC becomes valid only after a valid UBX-NAV-PVT frame
     * provides valid date, valid time, fully resolved time, and GNSS fix.
     *
     * NMEA ZDA remains an initial commissioning fallback until UBX PVT has
     * been received.
     */
    bool utc_valid;
    bool utc_from_ubx_pvt;
    int64_t utc_seconds;
    int64_t utc_age_us;

    bool gnss_fix_valid;
    bool gnss_time_fully_resolved;
    uint8_t fix_type;
    uint8_t satellites_used;

    app_leap_indicator_t leap_indicator;
    bool leap_information_valid;
    int8_t current_leap_seconds;
    int8_t pending_leap_change;
    int32_t seconds_to_leap_event;

    bool timing_pulse_valid;
    uint16_t timing_week;
    uint32_t timing_tow_ms;
    int32_t timing_tow_sub_ms;
    int32_t timing_quantization_error_ns;
    uint8_t timing_pulse_flags;
    int64_t timing_pulse_age_us;

    bool ubx_configuration_attempted;
    bool ubx_configuration_complete;
    bool ubx_timepulse_configuration_attempted;
    bool ubx_timepulse_configuration_complete;

    uint32_t ubx_ack_count;
    uint32_t ubx_nak_count;
    uint32_t ubx_configuration_failures;

    uint32_t ubx_frames_valid;
    uint32_t ubx_frames_invalid_checksum;
    uint32_t ubx_frames_invalid_length;
    uint32_t ubx_frames_unsupported;

    uint32_t ubx_nav_pvt_messages;
    uint32_t ubx_nav_timels_messages;
    uint32_t ubx_tim_tp_messages;

    uint32_t valid_zda_messages;
    uint32_t invalid_messages;
    uint32_t uart_bytes_received;
} gnss_service_status_t;

esp_err_t gnss_service_init(void);

bool gnss_service_get_status(gnss_service_status_t *out_status);

#ifdef __cplusplus
}
#endif