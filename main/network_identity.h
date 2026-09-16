#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "esp_netif.h"

#define NETWORK_HOSTNAME_MAX_LEN    63U

esp_err_t network_identity_init(
    esp_netif_t *eth_netif);

esp_err_t network_identity_get_hostname(
    char *hostname,
    size_t hostname_len);

esp_err_t network_identity_set_hostname(
    const char *hostname);

esp_err_t network_identity_get_mac_string(
    char *buffer,
    size_t buffer_len);

esp_err_t network_identity_get_ipv4(
    char *buffer,
    size_t buffer_len);