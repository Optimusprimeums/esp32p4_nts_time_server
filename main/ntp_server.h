#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool started;
    bool socket_bound;

    uint32_t requests_received;
    uint32_t invalid_requests;
    uint32_t unsynchronized_drops;
    uint32_t rate_kod_responses;
    uint32_t normal_responses;
    uint32_t send_failures;
    uint32_t socket_open_failures;

    uint32_t last_client_ipv4;
    int64_t last_request_monotonic_us;
    int64_t last_response_monotonic_us;

    /*
     * Phase 6B diagnostic-only software timestamp path measurements.
     * All values are microseconds measured with esp_timer_get_time().
     */
    uint32_t timing_samples;

    uint32_t rx_timestamp_start_min_us;
    uint32_t rx_timestamp_start_avg_us;
    uint32_t rx_timestamp_start_max_us;

    uint32_t rx_timestamp_call_min_us;
    uint32_t rx_timestamp_call_avg_us;
    uint32_t rx_timestamp_call_max_us;

    uint32_t response_build_min_us;
    uint32_t response_build_avg_us;
    uint32_t response_build_max_us;

    uint32_t tx_timestamp_to_send_min_us;
    uint32_t tx_timestamp_to_send_avg_us;
    uint32_t tx_timestamp_to_send_max_us;

    uint32_t send_call_min_us;
    uint32_t send_call_avg_us;
    uint32_t send_call_max_us;

    uint32_t total_response_min_us;
    uint32_t total_response_avg_us;
    uint32_t total_response_max_us;

    /* Phase 6C.4B diagnostic-only HW RX versus existing SW RX comparison. */
    uint32_t hw_rx_compare_samples;
    uint32_t hw_rx_compare_misses;
    int64_t hw_rx_delta_last_ns;
    int64_t hw_rx_delta_min_ns;
    int64_t hw_rx_delta_avg_ns;
    int64_t hw_rx_delta_max_ns;
    uint32_t hw_rx_mapping_bracket_last_ns;
    uint32_t hw_rx_mapping_age_last_us;

    /* Phase 6C.4C authoritative hardware receive timestamping. */
    uint32_t hw_rx_authoritative_responses;
    uint32_t hw_rx_authority_drops;

    uint8_t advertised_stratum;
    uint8_t advertised_leap_indicator;
    uint32_t advertised_root_dispersion;
} ntp_server_status_t;

esp_err_t ntp_server_start(void);

bool ntp_server_get_status(ntp_server_status_t *out_status);

#ifdef __cplusplus
}
#endif