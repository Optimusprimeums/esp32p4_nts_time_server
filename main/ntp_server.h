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

    uint8_t advertised_stratum;
    uint8_t advertised_leap_indicator;
    uint32_t advertised_root_dispersion;
} ntp_server_status_t;

esp_err_t ntp_server_start(void);

bool ntp_server_get_status(ntp_server_status_t *out_status);

#ifdef __cplusplus
}
#endif