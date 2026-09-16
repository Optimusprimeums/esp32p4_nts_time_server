#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool ethernet_link_up;
    bool ipv4_ready;

    bool gnss_valid;
    bool pps_present;
    bool time_locked;

    uint8_t ntp_stratum;
    uint8_t leap_indicator;

    uint32_t valid_pps_samples;

    uint64_t last_gnss_us;
    uint64_t last_pps_us;
} health_snapshot_t;

void health_get_snapshot(
    health_snapshot_t *snapshot);

bool health_is_ready_for_ntp(void);

bool health_is_ready_for_admin(void);