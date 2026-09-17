#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Verify that an API token can see the requested Cloudflare zone and return
 * that zone's immutable 32-character ID. No credential is logged or retained.
 */
esp_err_t cloudflare_client_resolve_zone(const char *api_token,
                                         const char *zone_name,
                                         char *zone_id,
                                         size_t zone_id_size,
                                         int *out_http_status);

#ifdef __cplusplus
}
#endif
