#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "device_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NTP_PEER_HEALTH_DISABLED = 0,
    NTP_PEER_HEALTH_UNKNOWN,
    NTP_PEER_HEALTH_HEALTHY,
    NTP_PEER_HEALTH_DEGRADED,
    NTP_PEER_HEALTH_UNREACHABLE,
    NTP_PEER_HEALTH_DIVERGENT,
    NTP_PEER_HEALTH_KOD,
    NTP_PEER_HEALTH_INVALID,
} ntp_peer_health_t;

typedef struct {
    bool configured;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U];
    ntp_peer_health_t health;
    uint8_t reachability;
    uint8_t stratum;
    uint8_t leap;
    char reference_id[9];
    int64_t offset_ns;
    int64_t delay_ns;
    int64_t jitter_ns;
    int64_t min_offset_ns;
    int64_t max_offset_ns;
    int64_t mean_offset_ns;
    int64_t rms_offset_ns;
    int64_t min_delay_ns;
    int64_t mean_delay_ns;
    int32_t root_delay_16_16;
    uint32_t root_dispersion_16_16;
    uint32_t successful_polls;
    uint32_t failed_polls;
    uint32_t rejected_responses;
    uint32_t duplicate_responses;
    uint32_t consecutive_failures;
    uint32_t kod_responses;
    uint32_t dns_failures;
    uint32_t timeout_failures;
    uint32_t samples;
    uint32_t rolling_samples;
    uint32_t last_success_age_seconds;
} ntp_peer_status_t;

typedef struct {
    bool initialized;
    bool running;
    bool enabled;
    uint32_t poll_interval_seconds;
    uint32_t response_timeout_ms;
    uint32_t poll_cycles;
    uint32_t configured_peers;
    uint32_t healthy_peers;
    bool cross_peer_spread_valid;
    int64_t cross_peer_spread_ns;
    bool best_observed_peer_valid;
    uint32_t best_observed_peer_index;
    ntp_peer_status_t peers[APP_NTP_PEER_MAX_COUNT];
} ntp_peer_monitor_status_t;

esp_err_t ntp_peer_monitor_start(void);
bool ntp_peer_monitor_is_running(void);
bool ntp_peer_monitor_get_status(ntp_peer_monitor_status_t *out_status);
const char *ntp_peer_monitor_health_name(ntp_peer_health_t health);

#ifdef __cplusplus
}
#endif
