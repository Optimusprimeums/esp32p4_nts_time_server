#include "device_config.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "app_state.h"

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "DEVICE_CFG";

#define APP_DEVICE_CONFIG_NVS_NAMESPACE         "device_cfg"
#define APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY      "hostname"

static bool s_initialized;
static char s_hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];

bool device_config_hostname_is_valid(const char *hostname)
{
    if (hostname == NULL) {
        return false;
    }

    const size_t length = strlen(hostname);

    if (length == 0U || length > APP_DEVICE_HOSTNAME_MAX_LENGTH) {
        return false;
    }

    if (!isalnum((unsigned char)hostname[0]) ||
        !isalnum((unsigned char)hostname[length - 1U])) {
        return false;
    }

    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)hostname[i];

        if (!isalnum(c) && c != '-') {
            return false;
        }
    }

    return true;
}

static void normalize_hostname(char *hostname)
{
    for (size_t i = 0; hostname[i] != '\0'; ++i) {
        hostname[i] = (char)tolower((unsigned char)hostname[i]);
    }
}

static esp_err_t persist_hostname(const char *hostname)
{
    nvs_handle_t handle = 0;

    esp_err_t err = nvs_open(APP_DEVICE_CONFIG_NVS_NAMESPACE,
                             NVS_READWRITE,
                             &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(handle,
                      APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY,
                      hostname);

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

esp_err_t device_config_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    if (!device_config_hostname_is_valid(APP_DEVICE_HOSTNAME_DEFAULT)) {
        ESP_LOGE(TAG, "Default device hostname is invalid");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(APP_DEVICE_CONFIG_NVS_NAMESPACE,
                             NVS_READONLY,
                             &handle);

    bool use_default = false;

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        use_default = true;
    } else if (err != ESP_OK) {
        return err;
    } else {
        size_t required = sizeof(s_hostname);

        err = nvs_get_str(handle,
                          APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY,
                          s_hostname,
                          &required);
        nvs_close(handle);

        if (err == ESP_ERR_NVS_NOT_FOUND) {
            use_default = true;
        } else if (err == ESP_ERR_NVS_INVALID_LENGTH ||
                   err == ESP_ERR_NVS_TYPE_MISMATCH) {
            ESP_LOGW(TAG,
                     "Stored hostname is unusable; restoring safe default");
            use_default = true;
        } else if (err != ESP_OK) {
            return err;
        } else if (!device_config_hostname_is_valid(s_hostname)) {
            ESP_LOGW(TAG,
                     "Stored hostname failed validation; restoring safe default");
            use_default = true;
        }
    }

    if (use_default) {
        (void)snprintf(s_hostname,
                       sizeof(s_hostname),
                       "%s",
                       APP_DEVICE_HOSTNAME_DEFAULT);
        normalize_hostname(s_hostname);

        err = persist_hostname(s_hostname);
        if (err != ESP_OK) {
            ESP_LOGE(TAG,
                     "Failed to persist default hostname: %s",
                     esp_err_to_name(err));
            return err;
        }
    } else {
        normalize_hostname(s_hostname);
    }

    s_initialized = true;
    app_state_set_device_hostname(s_hostname);

    ESP_LOGI(TAG, "Device hostname: %s", s_hostname);
    return ESP_OK;
}

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (buffer == NULL || buffer_size == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    const size_t required = strlen(s_hostname) + 1U;

    if (buffer_size < required) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(buffer, s_hostname, required);
    return ESP_OK;
}

esp_err_t device_config_set_hostname(const char *hostname)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!device_config_hostname_is_valid(hostname)) {
        return ESP_ERR_INVALID_ARG;
    }

    char normalized[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];

    (void)snprintf(normalized,
                   sizeof(normalized),
                   "%s",
                   hostname);
    normalize_hostname(normalized);

    esp_err_t err = persist_hostname(normalized);

    if (err != ESP_OK) {
        return err;
    }

    memcpy(s_hostname, normalized, strlen(normalized) + 1U);
    app_state_set_device_hostname(s_hostname);

    ESP_LOGI(TAG, "Device hostname updated: %s", s_hostname);
    return ESP_OK;
}
