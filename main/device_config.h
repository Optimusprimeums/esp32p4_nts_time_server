#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_DEVICE_CONFIG_SCHEMA_VERSION        2U
#define APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH     253U
#define APP_CLOUDFLARE_ZONE_ID_LENGTH           32U
#define APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH     512U

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    bool cloudflare_configured;
    char cloudflare_zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char cloudflare_zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
} device_config_snapshot_t;

typedef struct {
    char api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
} device_config_cloudflare_credentials_t;

esp_err_t device_config_init(void);
bool device_config_hostname_is_valid(const char *hostname);
bool device_config_cloudflare_zone_is_valid(const char *zone_name);
esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot);
esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size);
esp_err_t device_config_get_cloudflare_credentials(device_config_cloudflare_credentials_t *out_credentials);
esp_err_t device_config_set_hostname(const char *hostname);
esp_err_t device_config_set_cloudflare(const char *api_token,
                                       const char *zone_name,
                                       const char *zone_id);
esp_err_t device_config_clear_cloudflare(void);

#ifdef __cplusplus
}
#endif
