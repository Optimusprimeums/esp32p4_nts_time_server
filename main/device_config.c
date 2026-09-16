#include "device_config.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "app_state.h"

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "DEVICE_CFG";

#define APP_DEVICE_CONFIG_NVS_NAMESPACE         "device_cfg"
#define APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY      "hostname"
#define APP_DEVICE_CONFIG_NVS_SCHEMA_KEY        "schema"
#define APP_DEVICE_CONFIG_NVS_GENERATION_KEY    "generation"

static SemaphoreHandle_t s_lock;
static bool s_initialized;
static device_config_snapshot_t s_config;

static bool lock_config(void)
{
    return s_lock != NULL &&
           xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_config(void)
{
    (void)xSemaphoreGive(s_lock);
}

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

static void make_default_config(device_config_snapshot_t *config)
{
    memset(config, 0, sizeof(*config));
    config->schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    config->generation = 1U;

    (void)snprintf(config->hostname,
                   sizeof(config->hostname),
                   "%s",
                   APP_DEVICE_HOSTNAME_DEFAULT);

    normalize_hostname(config->hostname);
}

static esp_err_t persist_config(const device_config_snapshot_t *config)
{
    nvs_handle_t handle = 0;

    esp_err_t err = nvs_open(APP_DEVICE_CONFIG_NVS_NAMESPACE,
                             NVS_READWRITE,
                             &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_u32(handle,
                      APP_DEVICE_CONFIG_NVS_SCHEMA_KEY,
                      config->schema_version);

    if (err == ESP_OK) {
        err = nvs_set_u32(handle,
                          APP_DEVICE_CONFIG_NVS_GENERATION_KEY,
                          config->generation);
    }

    if (err == ESP_OK) {
        err = nvs_set_str(handle,
                          APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY,
                          config->hostname);
    }

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

static esp_err_t load_config(device_config_snapshot_t *config,
                             bool *out_needs_default)
{
    if (config == NULL || out_needs_default == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_needs_default = false;
    memset(config, 0, sizeof(*config));

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(APP_DEVICE_CONFIG_NVS_NAMESPACE,
                             NVS_READONLY,
                             &handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        *out_needs_default = true;
        return ESP_OK;
    }

    if (err != ESP_OK) {
        return err;
    }

    uint32_t schema = 0U;
    uint32_t generation = 0U;
    size_t hostname_size = sizeof(config->hostname);

    err = nvs_get_u32(handle,
                      APP_DEVICE_CONFIG_NVS_SCHEMA_KEY,
                      &schema);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        /*
         * Phase 5B.1 stored only the hostname. Preserve it and migrate it
         * into the versioned Phase 5B.2 record.
         */
        err = nvs_get_str(handle,
                          APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY,
                          config->hostname,
                          &hostname_size);

        nvs_close(handle);

        if (err == ESP_ERR_NVS_NOT_FOUND ||
            err == ESP_ERR_NVS_INVALID_LENGTH ||
            err == ESP_ERR_NVS_TYPE_MISMATCH) {
            *out_needs_default = true;
            return ESP_OK;
        }

        if (err != ESP_OK) {
            return err;
        }

        if (!device_config_hostname_is_valid(config->hostname)) {
            *out_needs_default = true;
            return ESP_OK;
        }

        normalize_hostname(config->hostname);
        config->schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
        config->generation = 1U;

        ESP_LOGI(TAG, "Migrating Phase 5B.1 device configuration");
        return persist_config(config);
    }

    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (schema != APP_DEVICE_CONFIG_SCHEMA_VERSION) {
        nvs_close(handle);
        ESP_LOGE(TAG,
                 "Unsupported device-config schema %" PRIu32,
                 schema);
        return ESP_ERR_INVALID_VERSION;
    }

    err = nvs_get_u32(handle,
                      APP_DEVICE_CONFIG_NVS_GENERATION_KEY,
                      &generation);

    if (err == ESP_OK) {
        err = nvs_get_str(handle,
                          APP_DEVICE_CONFIG_NVS_HOSTNAME_KEY,
                          config->hostname,
                          &hostname_size);
    }

    nvs_close(handle);

    if (err == ESP_ERR_NVS_NOT_FOUND ||
        err == ESP_ERR_NVS_INVALID_LENGTH ||
        err == ESP_ERR_NVS_TYPE_MISMATCH) {
        *out_needs_default = true;
        return ESP_OK;
    }

    if (err != ESP_OK) {
        return err;
    }

    if (generation == 0U ||
        !device_config_hostname_is_valid(config->hostname)) {
        *out_needs_default = true;
        return ESP_OK;
    }

    normalize_hostname(config->hostname);
    config->schema_version = schema;
    config->generation = generation;

    return ESP_OK;
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

    s_lock = xSemaphoreCreateMutex();

    if (s_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    device_config_snapshot_t loaded;
    bool needs_default = false;

    esp_err_t err = load_config(&loaded, &needs_default);

    if (err != ESP_OK) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        return err;
    }

    if (needs_default) {
        make_default_config(&loaded);

        err = persist_config(&loaded);

        if (err != ESP_OK) {
            ESP_LOGE(TAG,
                     "Failed to persist default configuration: %s",
                     esp_err_to_name(err));
            vSemaphoreDelete(s_lock);
            s_lock = NULL;
            return err;
        }
    }

    if (!lock_config()) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        return ESP_FAIL;
    }

    s_config = loaded;
    s_initialized = true;

    unlock_config();

    app_state_set_device_hostname(loaded.hostname);

    ESP_LOGI(TAG,
             "Device configuration ready: schema=%" PRIu32
             " generation=%" PRIu32 " hostname=%s",
             loaded.schema_version,
             loaded.generation,
             loaded.hostname);

    return ESP_OK;
}

esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot)
{
    if (out_snapshot == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_initialized || s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!lock_config()) {
        return ESP_FAIL;
    }

    *out_snapshot = s_config;

    unlock_config();
    return ESP_OK;
}

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    device_config_snapshot_t snapshot;
    esp_err_t err = device_config_get_snapshot(&snapshot);

    if (err != ESP_OK) {
        return err;
    }

    const size_t required = strlen(snapshot.hostname) + 1U;

    if (buffer_size < required) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(buffer, snapshot.hostname, required);
    return ESP_OK;
}

esp_err_t device_config_set_hostname(const char *hostname)
{
    if (!s_initialized || s_lock == NULL) {
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

    if (!lock_config()) {
        return ESP_FAIL;
    }

    if (strcmp(normalized, s_config.hostname) == 0) {
        unlock_config();
        return ESP_OK;
    }

    device_config_snapshot_t candidate = s_config;

    (void)snprintf(candidate.hostname,
                   sizeof(candidate.hostname),
                   "%s",
                   normalized);

    candidate.generation++;

    if (candidate.generation == 0U) {
        candidate.generation = 1U;
    }

    esp_err_t err = persist_config(&candidate);

    if (err == ESP_OK) {
        s_config = candidate;
    }

    unlock_config();

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Hostname update was not committed: %s",
                 esp_err_to_name(err));
        return err;
    }

    app_state_set_device_hostname(candidate.hostname);

    ESP_LOGI(TAG,
             "Device configuration committed: generation=%" PRIu32
             " hostname=%s",
             candidate.generation,
             candidate.hostname);

    return ESP_OK;
}
