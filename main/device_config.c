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

#define CFG_NS              "device_cfg"
#define KEY_HOSTNAME        "hostname"
#define KEY_SCHEMA          "schema"
#define KEY_GENERATION      "generation"
#define KEY_CF_ZONE_NAME    "cf_zone"
#define KEY_CF_ZONE_ID      "cf_zone_id"
#define KEY_CF_API_TOKEN    "cf_token"

typedef struct {
    device_config_snapshot_t public_config;
    char cloudflare_api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
} stored_config_t;

static SemaphoreHandle_t s_lock;
static bool s_initialized;
static stored_config_t s_config;

static bool lock_config(void)
{
    return s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_config(void)
{
    (void)xSemaphoreGive(s_lock);
}

bool device_config_hostname_is_valid(const char *hostname)
{
    if (hostname == NULL) return false;
    const size_t length = strlen(hostname);
    if (length == 0U || length > APP_DEVICE_HOSTNAME_MAX_LENGTH) return false;
    if (!isalnum((unsigned char)hostname[0]) ||
        !isalnum((unsigned char)hostname[length - 1U])) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)hostname[i];
        if (!isalnum(c) && c != '-') return false;
    }
    return true;
}

bool device_config_cloudflare_zone_is_valid(const char *zone_name)
{
    if (zone_name == NULL) return false;
    const size_t length = strlen(zone_name);
    if (length == 0U || length > APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH) return false;
    if (zone_name[0] == '.' || zone_name[length - 1U] == '.') return false;

    size_t label_len = 0U;
    bool label_first = true;
    char previous = '\0';
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)zone_name[i];
        if (c == '.') {
            if (label_len == 0U || previous == '-') return false;
            label_len = 0U;
            label_first = true;
            previous = '.';
            continue;
        }
        if (!isalnum(c) && c != '-') return false;
        if (label_first && c == '-') return false;
        label_first = false;
        if (++label_len > 63U) return false;
        previous = (char)c;
    }
    return label_len > 0U && previous != '-';
}

static bool api_token_is_valid(const char *token)
{
    if (token == NULL) return false;
    const size_t length = strlen(token);
    if (length < 20U || length > APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)token[i];
        if (c <= 0x20U || c >= 0x7fU) return false;
    }
    return true;
}

static bool zone_id_is_valid(const char *zone_id)
{
    if (zone_id == NULL || strlen(zone_id) != APP_CLOUDFLARE_ZONE_ID_LENGTH) return false;
    for (size_t i = 0; i < APP_CLOUDFLARE_ZONE_ID_LENGTH; ++i) {
        if (!isxdigit((unsigned char)zone_id[i])) return false;
    }
    return true;
}

static void lowercase(char *value)
{
    for (size_t i = 0; value[i] != '\0'; ++i) {
        value[i] = (char)tolower((unsigned char)value[i]);
    }
}

static void make_default_config(stored_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    config->public_config.generation = 1U;
    (void)snprintf(config->public_config.hostname,
                   sizeof(config->public_config.hostname), "%s",
                   APP_DEVICE_HOSTNAME_DEFAULT);
    lowercase(config->public_config.hostname);
}

static esp_err_t persist_config(const stored_config_t *config)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(CFG_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    err = nvs_set_u32(handle, KEY_SCHEMA, config->public_config.schema_version);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_GENERATION, config->public_config.generation);
    if (err == ESP_OK) err = nvs_set_str(handle, KEY_HOSTNAME, config->public_config.hostname);

    if (err == ESP_OK && config->public_config.cloudflare_configured) {
        err = nvs_set_str(handle, KEY_CF_ZONE_NAME, config->public_config.cloudflare_zone_name);
        if (err == ESP_OK) err = nvs_set_str(handle, KEY_CF_ZONE_ID, config->public_config.cloudflare_zone_id);
        if (err == ESP_OK) err = nvs_set_str(handle, KEY_CF_API_TOKEN, config->cloudflare_api_token);
    } else if (err == ESP_OK) {
        esp_err_t erase_err = nvs_erase_key(handle, KEY_CF_ZONE_NAME);
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        erase_err = nvs_erase_key(handle, KEY_CF_ZONE_ID);
        if (err == ESP_OK && erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        erase_err = nvs_erase_key(handle, KEY_CF_API_TOKEN);
        if (err == ESP_OK && erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
    }

    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

static esp_err_t read_string(nvs_handle_t handle, const char *key,
                             char *buffer, size_t buffer_size)
{
    size_t required = buffer_size;
    return nvs_get_str(handle, key, buffer, &required);
}

static esp_err_t load_config(stored_config_t *config, bool *out_needs_default)
{
    if (config == NULL || out_needs_default == NULL) return ESP_ERR_INVALID_ARG;
    *out_needs_default = false;
    memset(config, 0, sizeof(*config));

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(CFG_NS, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        *out_needs_default = true;
        return ESP_OK;
    }
    if (err != ESP_OK) return err;

    uint32_t schema = 0U;
    err = nvs_get_u32(handle, KEY_SCHEMA, &schema);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        size_t hostname_size = sizeof(config->public_config.hostname);
        err = nvs_get_str(handle, KEY_HOSTNAME, config->public_config.hostname, &hostname_size);
        nvs_close(handle);
        if (err != ESP_OK || !device_config_hostname_is_valid(config->public_config.hostname)) {
            *out_needs_default = true;
            return ESP_OK;
        }
        lowercase(config->public_config.hostname);
        config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
        config->public_config.generation = 1U;
        ESP_LOGI(TAG, "Migrating Phase 5B.1 device configuration to schema 2");
        return persist_config(config);
    }
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (schema != 1U && schema != APP_DEVICE_CONFIG_SCHEMA_VERSION) {
        nvs_close(handle);
        ESP_LOGE(TAG, "Unsupported device-config schema %" PRIu32, schema);
        return ESP_ERR_INVALID_VERSION;
    }

    err = nvs_get_u32(handle, KEY_GENERATION, &config->public_config.generation);
    if (err == ESP_OK) {
        err = read_string(handle, KEY_HOSTNAME, config->public_config.hostname,
                          sizeof(config->public_config.hostname));
    }
    if (err != ESP_OK || config->public_config.generation == 0U ||
        !device_config_hostname_is_valid(config->public_config.hostname)) {
        nvs_close(handle);
        *out_needs_default = true;
        return ESP_OK;
    }
    lowercase(config->public_config.hostname);
    config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;

    if (schema == 1U) {
        nvs_close(handle);
        ESP_LOGI(TAG, "Migrating Phase 5B.5 configuration schema 1 -> 2");
        return persist_config(config);
    }

    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U] = {0};
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U] = {0};
    char token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U] = {0};
    esp_err_t zone_err = read_string(handle, KEY_CF_ZONE_NAME, zone_name, sizeof(zone_name));
    esp_err_t id_err = read_string(handle, KEY_CF_ZONE_ID, zone_id, sizeof(zone_id));
    esp_err_t token_err = read_string(handle, KEY_CF_API_TOKEN, token, sizeof(token));
    nvs_close(handle);

    if (zone_err == ESP_OK && id_err == ESP_OK && token_err == ESP_OK &&
        device_config_cloudflare_zone_is_valid(zone_name) &&
        zone_id_is_valid(zone_id) && api_token_is_valid(token)) {
        lowercase(zone_name);
        config->public_config.cloudflare_configured = true;
        (void)snprintf(config->public_config.cloudflare_zone_name,
                       sizeof(config->public_config.cloudflare_zone_name), "%s", zone_name);
        (void)snprintf(config->public_config.cloudflare_zone_id,
                       sizeof(config->public_config.cloudflare_zone_id), "%s", zone_id);
        (void)snprintf(config->cloudflare_api_token,
                       sizeof(config->cloudflare_api_token), "%s", token);
    }
    return ESP_OK;
}

esp_err_t device_config_init(void)
{
    if (s_initialized) return ESP_OK;
    if (!device_config_hostname_is_valid(APP_DEVICE_HOSTNAME_DEFAULT)) return ESP_ERR_INVALID_ARG;
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;

    stored_config_t loaded;
    bool needs_default = false;
    esp_err_t err = load_config(&loaded, &needs_default);
    if (err != ESP_OK) goto fail;
    if (needs_default) {
        make_default_config(&loaded);
        err = persist_config(&loaded);
        if (err != ESP_OK) goto fail;
    }
    if (!lock_config()) { err = ESP_FAIL; goto fail; }
    s_config = loaded;
    s_initialized = true;
    unlock_config();
    app_state_set_device_hostname(loaded.public_config.hostname);
    ESP_LOGI(TAG, "Device configuration ready: schema=%" PRIu32 " generation=%" PRIu32
             " hostname=%s cloudflare=%s",
             loaded.public_config.schema_version, loaded.public_config.generation,
             loaded.public_config.hostname,
             loaded.public_config.cloudflare_configured ? "configured" : "not-configured");
    return ESP_OK;
fail:
    if (s_lock != NULL) vSemaphoreDelete(s_lock);
    s_lock = NULL;
    return err;
}

esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot)
{
    if (out_snapshot == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    *out_snapshot = s_config.public_config;
    unlock_config();
    return ESP_OK;
}

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0U) return ESP_ERR_INVALID_ARG;
    device_config_snapshot_t snapshot;
    esp_err_t err = device_config_get_snapshot(&snapshot);
    if (err != ESP_OK) return err;
    const size_t required = strlen(snapshot.hostname) + 1U;
    if (buffer_size < required) return ESP_ERR_INVALID_SIZE;
    memcpy(buffer, snapshot.hostname, required);
    return ESP_OK;
}

esp_err_t device_config_get_cloudflare_credentials(device_config_cloudflare_credentials_t *out_credentials)
{
    if (out_credentials == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_credentials, 0, sizeof(*out_credentials));
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    if (!s_config.public_config.cloudflare_configured) {
        unlock_config();
        return ESP_ERR_NOT_FOUND;
    }
    (void)snprintf(out_credentials->api_token, sizeof(out_credentials->api_token), "%s",
                   s_config.cloudflare_api_token);
    (void)snprintf(out_credentials->zone_name, sizeof(out_credentials->zone_name), "%s",
                   s_config.public_config.cloudflare_zone_name);
    (void)snprintf(out_credentials->zone_id, sizeof(out_credentials->zone_id), "%s",
                   s_config.public_config.cloudflare_zone_id);
    unlock_config();
    return ESP_OK;
}

static uint32_t next_generation(uint32_t generation)
{
    generation++;
    return generation == 0U ? 1U : generation;
}

esp_err_t device_config_set_hostname(const char *hostname)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!device_config_hostname_is_valid(hostname)) return ESP_ERR_INVALID_ARG;
    char normalized[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    (void)snprintf(normalized, sizeof(normalized), "%s", hostname);
    lowercase(normalized);
    if (!lock_config()) return ESP_FAIL;
    if (strcmp(normalized, s_config.public_config.hostname) == 0) {
        unlock_config();
        return ESP_OK;
    }
    stored_config_t candidate = s_config;
    (void)snprintf(candidate.public_config.hostname,
                   sizeof(candidate.public_config.hostname), "%s", normalized);
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err != ESP_OK) return err;
    app_state_set_device_hostname(candidate.public_config.hostname);
    ESP_LOGI(TAG, "Device configuration committed: generation=%" PRIu32 " hostname=%s",
             candidate.public_config.generation, candidate.public_config.hostname);
    return ESP_OK;
}

esp_err_t device_config_set_cloudflare(const char *api_token,
                                       const char *zone_name,
                                       const char *zone_id)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!api_token_is_valid(api_token) ||
        !device_config_cloudflare_zone_is_valid(zone_name) ||
        !zone_id_is_valid(zone_id)) return ESP_ERR_INVALID_ARG;

    char normalized_zone[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    (void)snprintf(normalized_zone, sizeof(normalized_zone), "%s", zone_name);
    lowercase(normalized_zone);
    if (!lock_config()) return ESP_FAIL;
    stored_config_t candidate = s_config;
    candidate.public_config.cloudflare_configured = true;
    (void)snprintf(candidate.public_config.cloudflare_zone_name,
                   sizeof(candidate.public_config.cloudflare_zone_name), "%s", normalized_zone);
    (void)snprintf(candidate.public_config.cloudflare_zone_id,
                   sizeof(candidate.public_config.cloudflare_zone_id), "%s", zone_id);
    (void)snprintf(candidate.cloudflare_api_token,
                   sizeof(candidate.cloudflare_api_token), "%s", api_token);
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Cloudflare configuration committed: generation=%" PRIu32 " zone=%s",
                 candidate.public_config.generation,
                 candidate.public_config.cloudflare_zone_name);
    }
    return err;
}

esp_err_t device_config_clear_cloudflare(void)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    if (!s_config.public_config.cloudflare_configured) {
        unlock_config();
        return ESP_OK;
    }
    stored_config_t candidate = s_config;
    candidate.public_config.cloudflare_configured = false;
    candidate.public_config.cloudflare_zone_name[0] = '\0';
    candidate.public_config.cloudflare_zone_id[0] = '\0';
    memset(candidate.cloudflare_api_token, 0, sizeof(candidate.cloudflare_api_token));
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK) ESP_LOGI(TAG, "Cloudflare configuration cleared");
    return err;
}
