#include "network_identity.h"

#include <stdio.h>
#include <string.h>

#include "eth_service.h"

#include "nvs.h"

#define NETWORK_NVS_NAMESPACE       "netcfg"
#define NETWORK_HOSTNAME_KEY         "hostname"
#define NETWORK_DEFAULT_HOSTNAME     "ntp-p4"

static esp_netif_t *s_eth_netif;

static bool hostname_is_valid(
    const char *hostname)
{
    if (hostname == NULL) {
        return false;
    }

    size_t length = strlen(hostname);

    if (length == 0U ||
        length > NETWORK_HOSTNAME_MAX_LEN) {
        return false;
    }

    if (hostname[0] == '-' ||
        hostname[length - 1U] == '-') {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        char value = hostname[i];

        bool allowed =
            (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') ||
            value == '-';

        if (!allowed) {
            return false;
        }
    }

    return true;
}

static esp_err_t network_load_hostname(
    char *hostname,
    size_t hostname_len)
{
    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NETWORK_NVS_NAMESPACE,
        NVS_READONLY,
        &handle);

    if (err != ESP_OK) {
        return err;
    }

    size_t length = hostname_len;

    err = nvs_get_str(
        handle,
        NETWORK_HOSTNAME_KEY,
        hostname,
        &length);

    nvs_close(handle);

    return err;
}

static esp_err_t network_save_hostname(
    const char *hostname)
{
    nvs_handle_t handle;

    esp_err_t err = nvs_open(
        NETWORK_NVS_NAMESPACE,
        NVS_READWRITE,
        &handle);

    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(
        handle,
        NETWORK_HOSTNAME_KEY,
        hostname);

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    return err;
}

esp_err_t network_identity_init(
    esp_netif_t *eth_netif)
{
    if (eth_netif == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    s_eth_netif = eth_netif;

    char hostname[
        NETWORK_HOSTNAME_MAX_LEN + 1U] = {0};

    esp_err_t err = network_load_hostname(
        hostname,
        sizeof(hostname));

    if (err != ESP_OK ||
        !hostname_is_valid(hostname)) {
        strncpy(hostname,
                NETWORK_DEFAULT_HOSTNAME,
                sizeof(hostname) - 1U);

        (void)network_save_hostname(hostname);
    }

    return esp_netif_set_hostname(
        s_eth_netif,
        hostname);
}

esp_err_t network_identity_get_hostname(
    char *hostname,
    size_t hostname_len)
{
    if (hostname == NULL ||
        hostname_len == 0U ||
        s_eth_netif == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const char *netif_hostname = NULL;

    esp_err_t err = esp_netif_get_hostname(
        s_eth_netif,
        &netif_hostname);

    if (err != ESP_OK ||
        netif_hostname == NULL) {
        return err;
    }

    size_t length = strlen(netif_hostname);

    if (length >= hostname_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(hostname,
           netif_hostname,
           length + 1U);

    return ESP_OK;
}

esp_err_t network_identity_set_hostname(
    const char *hostname)
{
    if (!hostname_is_valid(hostname) ||
        s_eth_netif == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = esp_netif_set_hostname(
        s_eth_netif,
        hostname);

    if (err != ESP_OK) {
        return err;
    }

    return network_save_hostname(hostname);
}

esp_err_t network_identity_get_mac_string(
    char *buffer,
    size_t buffer_len)
{
    if (buffer == NULL ||
        buffer_len < 18U) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t mac[6] = {0};

    esp_err_t err = eth_service_get_mac(mac);

    if (err != ESP_OK) {
        return err;
    }

    snprintf(buffer,
             buffer_len,
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0],
             mac[1],
             mac[2],
             mac[3],
             mac[4],
             mac[5]);

    return ESP_OK;
}

esp_err_t network_identity_get_ipv4(
    char *buffer,
    size_t buffer_len)
{
    return eth_service_get_ipv4(
        buffer,
        buffer_len);
}