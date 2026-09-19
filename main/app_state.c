#include "app_state.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static portMUX_TYPE s_state_lock = portMUX_INITIALIZER_UNLOCKED;
static app_state_snapshot_t s_state;

void app_state_init(void)
{
    portENTER_CRITICAL(&s_state_lock);

    memset(&s_state, 0, sizeof(s_state));
    s_state.initialized = true;
    s_state.leap_indicator = APP_LEAP_UNKNOWN;
    s_state.clock_state = APP_CLOCK_UNSYNCHRONIZED;

    portEXIT_CRITICAL(&s_state_lock);
}

void app_state_set_device_hostname(const char *hostname)
{
    if (hostname == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_state_lock);

    (void)snprintf(s_state.device_hostname,
                   sizeof(s_state.device_hostname),
                   "%s",
                   hostname);

    portEXIT_CRITICAL(&s_state_lock);
}

void app_state_set_ipv4_ready(bool ready)
{
    portENTER_CRITICAL(&s_state_lock);
    s_state.ipv4_ready = ready;
    portEXIT_CRITICAL(&s_state_lock);
}

void app_state_set_gnss_valid(bool valid,
                              int64_t utc_seconds,
                              app_leap_indicator_t leap_indicator,
                              int64_t age_us)
{
    portENTER_CRITICAL(&s_state_lock);

    s_state.gnss_valid = valid;
    s_state.gnss_utc_seconds = utc_seconds;
    s_state.leap_indicator = leap_indicator;
    s_state.gnss_age_us = age_us;

    portEXIT_CRITICAL(&s_state_lock);
}

void app_state_set_pps_status(bool valid,
                              uint64_t last_capture_us,
                              uint32_t period_us,
                              uint32_t jitter_us,
                              uint32_t edge_count,
                              uint32_t queue_drops,
                              int64_t age_us)
{
    portENTER_CRITICAL(&s_state_lock);

    s_state.pps_valid = valid;
    s_state.pps_last_capture_us = last_capture_us;
    s_state.pps_period_us = period_us;
    s_state.pps_jitter_us = jitter_us;
    s_state.pps_edge_count = edge_count;
    s_state.pps_queue_drops = queue_drops;
    s_state.pps_age_us = age_us;

    portEXIT_CRITICAL(&s_state_lock);
}

void app_state_set_clock_solution(app_clock_state_t state,
                                  bool solution_valid,
                                  int64_t phase_error_ns,
                                  double frequency_ppm,
                                  uint32_t accepted_samples,
                                  uint32_t rejected_samples,
                                  uint32_t holdover_seconds,
                                  uint32_t root_dispersion_16_16)
{
    portENTER_CRITICAL(&s_state_lock);

    s_state.clock_state = state;
    s_state.clock_solution_valid = solution_valid;
    s_state.phase_error_ns = phase_error_ns;
    s_state.frequency_ppm = frequency_ppm;
    s_state.accepted_samples = accepted_samples;
    s_state.rejected_samples = rejected_samples;
    s_state.holdover_seconds = holdover_seconds;
    s_state.root_dispersion_16_16 = root_dispersion_16_16;

    portEXIT_CRITICAL(&s_state_lock);
}

app_clock_state_t app_state_get_clock_state(void)
{
    app_clock_state_t state;

    portENTER_CRITICAL(&s_state_lock);
    state = s_state.clock_state;
    portEXIT_CRITICAL(&s_state_lock);

    return state;
}

bool app_state_get_snapshot(app_state_snapshot_t *out_snapshot)
{
    if (out_snapshot == NULL) {
        return false;
    }

    portENTER_CRITICAL(&s_state_lock);
    *out_snapshot = s_state;
    portEXIT_CRITICAL(&s_state_lock);

    return true;
}
