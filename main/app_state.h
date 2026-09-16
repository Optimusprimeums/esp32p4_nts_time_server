#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    APP_LEAP_NO_WARNING = 0,
    APP_LEAP_ADD_SECOND = 1,
    APP_LEAP_DELETE_SECOND = 2,
    APP_LEAP_UNKNOWN = 3,
} app_leap_indicator_t;

typedef enum {
    APP_CLOCK_UNSYNCHRONIZED = 0,
    APP_CLOCK_ACQUIRING,
    APP_CLOCK_SYNCHRONIZED,
    APP_CLOCK_HOLDOVER,
    APP_CLOCK_FAIL_CLOSED,
} app_clock_state_t;

typedef struct {
    bool initialized;

    bool ipv4_ready;

    bool gnss_valid;
    int64_t gnss_utc_seconds;
    app_leap_indicator_t leap_indicator;
    int64_t gnss_age_us;

    bool pps_valid;
    uint64_t pps_last_capture_us;
    uint32_t pps_period_us;
    uint32_t pps_jitter_us;
    uint32_t pps_edge_count;
    uint32_t pps_queue_drops;
    int64_t pps_age_us;

    app_clock_state_t clock_state;
    bool clock_solution_valid;
    int64_t phase_error_ns;
    double frequency_ppm;
    uint32_t accepted_samples;
    uint32_t rejected_samples;
    uint32_t holdover_seconds;
    uint32_t root_dispersion_16_16;
} app_state_snapshot_t;

void app_state_init(void);

void app_state_set_ipv4_ready(bool ready);

void app_state_set_gnss_valid(bool valid,
                              int64_t utc_seconds,
                              app_leap_indicator_t leap_indicator,
                              int64_t age_us);

void app_state_set_pps_status(bool valid,
                              uint64_t last_capture_us,
                              uint32_t period_us,
                              uint32_t jitter_us,
                              uint32_t edge_count,
                              uint32_t queue_drops,
                              int64_t age_us);

void app_state_set_clock_solution(app_clock_state_t state,
                                  bool solution_valid,
                                  int64_t phase_error_ns,
                                  double frequency_ppm,
                                  uint32_t accepted_samples,
                                  uint32_t rejected_samples,
                                  uint32_t holdover_seconds,
                                  uint32_t root_dispersion_16_16);

app_clock_state_t app_state_get_clock_state(void);

bool app_state_get_snapshot(app_state_snapshot_t *out_snapshot);

#ifdef __cplusplus
}
#endif