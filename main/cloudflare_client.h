#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLOUDFLARE_DNS_RECORD_ID_LENGTH 32U
#define CLOUDFLARE_DNS01_VALUE_MAX_LENGTH 255U

/* Verify token access to a zone and return its immutable 32-character ID. */
esp_err_t cloudflare_client_resolve_zone(const char *api_token,
                                         const char *zone_name,
                                         char *zone_id,
                                         size_t zone_id_size,
                                         int *out_http_status);

/* Create an unproxied TXT record with automatic TTL for an ACME DNS-01 challenge. */
esp_err_t cloudflare_client_create_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_name,
                                             const char *txt_value,
                                             char *record_id,
                                             size_t record_id_size,
                                             int *out_http_status);

/* Verify that a record ID still names the expected DNS-01 TXT record. */
esp_err_t cloudflare_client_verify_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_id,
                                             const char *expected_record_name,
                                             int *out_http_status);

/* Verify record type, name, and exact ACME TXT content before challenge trigger. */
esp_err_t cloudflare_client_verify_dns01_txt_content(const char *api_token,
                                                     const char *zone_id,
                                                     const char *record_id,
                                                     const char *expected_record_name,
                                                     const char *expected_txt_value,
                                                     int *out_http_status);

/*
 * Delete a DNS-01 record only after verifying that the record ID still names
 * the expected TXT record. This prevents the management API from deleting an
 * unrelated DNS record by ID.
 */
esp_err_t cloudflare_client_delete_dns01_txt(const char *api_token,
                                             const char *zone_id,
                                             const char *record_id,
                                             const char *expected_record_name,
                                             int *out_http_status);

#ifdef __cplusplus
}
#endif
