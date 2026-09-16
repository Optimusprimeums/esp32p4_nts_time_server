#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#include "app_state.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t seconds;
    uint32_t fraction;
} clock_ntp_timestamp_t;

typedef struct {
    bool initialized;
    bool solution_valid;

    app_clock_state_t state;

    int64_t phase_error_ns;
    double frequency_ppm;

    uint32_t accepted_samples;
    uint32_t rejected_samples;
    uint32_t holdover_seconds;
    uint32_t root_dispersion_16_16;
} clock_discipline_status_t;

esp_err_t clock_discipline_init(void);

/*
 * Point 4C calls this only after a PPS edge has been correlated to a
 * valid GNSS UTC second.
 */
esp_err_t clock_discipline_submit_sample(uint64_t pps_capture_us,
                                         int64_t utc_seconds,
                                         int32_t timing_quantization_error_ns,
                                         app_leap_indicator_t leap_indicator);

bool clock_discipline_get_ntp_timestamp(clock_ntp_timestamp_t *out_timestamp);

bool clock_discipline_get_status(clock_discipline_status_t *out_status);

#ifdef __cplusplus
}
#endif
