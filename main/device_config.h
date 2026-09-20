#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_DEVICE_CONFIG_SCHEMA_VERSION             3U
#define APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH          253U
#define APP_CLOUDFLARE_ZONE_ID_LENGTH                32U
#define APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH          512U

#define APP_NTP_PEER_MAX_COUNT                       4U
#define APP_NTP_PEER_SERVER_MAX_LENGTH               253U
#define APP_NTP_PEER_POLL_MIN_SECONDS                4U
#define APP_NTP_PEER_POLL_MAX_SECONDS                3600U
#define APP_NTP_PEER_POLL_DEFAULT_SECONDS            16U
#define APP_NTP_PEER_TIMEOUT_MIN_MS                  250U
#define APP_NTP_PEER_TIMEOUT_MAX_MS                  10000U
#define APP_NTP_PEER_TIMEOUT_DEFAULT_MS              2000U

typedef struct {
    bool enabled;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U];
} device_config_ntp_peer_t;

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    bool cloudflare_configured;
    char cloudflare_zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char cloudflare_zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    bool ntp_peer_monitor_enabled;
    uint32_t ntp_peer_poll_interval_seconds;
    uint32_t ntp_peer_response_timeout_ms;
    device_config_ntp_peer_t ntp_peers[APP_NTP_PEER_MAX_COUNT];
} device_config_snapshot_t;

typedef struct {
    char api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
} device_config_cloudflare_credentials_t;

esp_err_t device_config_init(void);
bool device_config_hostname_is_valid(const char *hostname);
bool device_config_cloudflare_zone_is_valid(const char *zone_name);
bool device_config_ntp_peer_server_is_valid(const char *server);
esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot);
esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size);
esp_err_t device_config_get_cloudflare_credentials(device_config_cloudflare_credentials_t *out_credentials);
esp_err_t device_config_set_hostname(const char *hostname);
esp_err_t device_config_set_cloudflare(const char *api_token,
                                       const char *zone_name,
                                       const char *zone_id);
esp_err_t device_config_clear_cloudflare(void);
esp_err_t device_config_set_ntp_peer_monitor(bool enabled,
                                             uint32_t poll_interval_seconds,
                                             uint32_t response_timeout_ms,
                                             const device_config_ntp_peer_t peers[APP_NTP_PEER_MAX_COUNT]);

#ifdef __cplusplus
}
#endif
