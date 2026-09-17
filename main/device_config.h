#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_DEVICE_CONFIG_SCHEMA_VERSION        1U

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
} device_config_snapshot_t;

esp_err_t device_config_init(void);

bool device_config_hostname_is_valid(const char *hostname);

esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot);

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size);

/*
 * Persistent mutation API used by the mTLS-authenticated management
 * endpoint introduced in Phase 5B.5.
 *
 * A new value is validated, normalized, committed to NVS, and only then
 * published to the runtime state.
 */
esp_err_t device_config_set_hostname(const char *hostname);

#ifdef __cplusplus
}
#endif
