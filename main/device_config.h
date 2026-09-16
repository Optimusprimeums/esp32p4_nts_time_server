#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t device_config_init(void);

bool device_config_hostname_is_valid(const char *hostname);

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size);

/*
 * Internal configuration-storage API for later authenticated management work.
 * Phase 5B.1 does not expose this function through HTTP.
 */
esp_err_t device_config_set_hostname(const char *hostname);

#ifdef __cplusplus
}
#endif
