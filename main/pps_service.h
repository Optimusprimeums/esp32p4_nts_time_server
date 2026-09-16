#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t capture_us;
    uint64_t capture_ticks;
} pps_capture_event_t;

typedef struct {
    bool initialized;
    bool etm_active;

    /*
     * True only after two PPS edges establish a plausible interval.
     * The first PPS edge has no previous edge and is therefore warm-up only.
     */
    bool interval_valid;

    uint64_t last_capture_us;
    uint32_t period_us;
    uint32_t jitter_us;

    uint32_t edge_count;
    uint32_t valid_interval_count;
    uint32_t invalid_interval_count;
    uint32_t queue_drops;

    int64_t age_us;
} pps_service_status_t;

esp_err_t pps_service_init(void);

/*
 * Returns a physical PPS event that was hardware-latched by the GPTimer ETM
 * capture task. The GPIO interrupt is notification only; it does not create
 * the timestamp.
 */
bool pps_service_wait_for_capture(pps_capture_event_t *out_event,
                                  uint32_t timeout_ms);

bool pps_service_get_monotonic_us(uint64_t *out_us);

bool pps_service_get_status(pps_service_status_t *out_status);

#ifdef __cplusplus
}
#endif