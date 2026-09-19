#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool initialized;
    bool started;
    bool link_up;
    bool ipv4_ready;

    bool ptp_supported;
    bool ptp_enabled;
    bool ptp_clock_readable;
    bool ptp_clock_running;
    uint32_t ptp_timestamp_resolution_ns;

    bool ptp_correlation_valid;
    uint32_t ptp_correlation_samples;
    int64_t ptp_utc_offset_ns;
    int64_t ptp_utc_offset_change_ns;
    int64_t ptp_utc_estimated_rate_ppb;
    uint32_t ptp_utc_bracket_ns;

    bool rx_hw_timestamp_all_enabled;
    uint32_t rx_hw_frames;
    uint32_t rx_hw_timestamp_valid;
    uint32_t rx_hw_timestamp_invalid;
    uint32_t rx_hw_ntp_requests;
    uint32_t rx_hw_ntp_timestamp_valid;
    uint32_t rx_hw_ntp_timestamp_invalid;
    uint32_t rx_hw_last_ntp_seconds;
    uint32_t rx_hw_last_ntp_nanoseconds;

    /* Phase 6C.4B/6C.4C RX timestamp mapping and authority diagnostics. */
    uint32_t rx_hw_queue_enqueued;
    uint32_t rx_hw_queue_overruns;
    uint32_t rx_hw_queue_matches;
    uint32_t rx_hw_queue_misses;
    uint32_t rx_hw_map_successes;
    uint32_t rx_hw_map_failures;
    uint32_t rx_hw_last_map_bracket_ns;
    uint32_t rx_hw_last_map_age_us;

    uint8_t mac[6];

    uint32_t ipv4_address;
    uint32_t ipv4_netmask;
    uint32_t ipv4_gateway;
} eth_service_status_t;

esp_err_t eth_service_init(void);

esp_err_t eth_service_start(void);

/*
 * Waits indefinitely. This function deliberately retries rather than
 * returning a timeout that could trigger a startup panic.
 */
void eth_service_wait_for_ip(void);

bool eth_service_get_status(eth_service_status_t *out_status);

typedef struct {
    uint32_t seconds;
    uint32_t fraction;
    uint32_t mapping_bracket_ns;
    uint32_t mapping_age_us;
} eth_service_ntp_rx_timestamp_t;

/*
 * Phase 6C.4C. Removes the oldest queued hardware RX timestamp matching
 * this UDP client and maps it into disciplined NTP time. Mapping fails closed
 * unless the PTP/UTC rate correlation is established and fresh.
 * client_ipv4 is in the same network-byte-order representation as
 * sockaddr_in.sin_addr.s_addr; client_port is host byte order.
 */
bool eth_service_take_ntp_rx_timestamp(uint32_t client_ipv4,
                                       uint16_t client_port,
                                       eth_service_ntp_rx_timestamp_t *out_timestamp);

#ifdef __cplusplus
}
#endif