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

#ifdef __cplusplus
}
#endif