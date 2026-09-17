#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACME_ACCOUNT_PRIVATE_KEY_LENGTH 32U
#define ACME_ACCOUNT_URL_MAX_LENGTH     384U

typedef struct {
    bool initialized;
    bool private_key_present;
    bool account_url_present;
    char account_url[ACME_ACCOUNT_URL_MAX_LENGTH];
} acme_storage_status_t;

/*
 * Initialize the dedicated nvs_certs partition using NVS XTS encryption keys
 * stored in the nvs_keys partition. This function refuses to initialize the
 * ACME secret store if hardware flash encryption is not active.
 */
esp_err_t acme_storage_init(void);

esp_err_t acme_storage_get_status(acme_storage_status_t *out_status);

esp_err_t acme_storage_load_private_key(
    uint8_t private_key[ACME_ACCOUNT_PRIVATE_KEY_LENGTH]);

esp_err_t acme_storage_store_private_key(
    const uint8_t private_key[ACME_ACCOUNT_PRIVATE_KEY_LENGTH]);

esp_err_t acme_storage_load_account_url(char *account_url,
                                        size_t account_url_size);

esp_err_t acme_storage_store_account_url(const char *account_url);

#ifdef __cplusplus
}
#endif
