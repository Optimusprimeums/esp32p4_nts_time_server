#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACME_URL_MAX_LENGTH       384U
#define ACME_THUMBPRINT_LENGTH     44U

typedef struct {
    bool reachable;
    int http_status;
    char new_nonce_url[ACME_URL_MAX_LENGTH];
    char new_account_url[ACME_URL_MAX_LENGTH];
    char new_order_url[ACME_URL_MAX_LENGTH];
} acme_directory_status_t;

typedef struct {
    bool key_present;
    bool registered;
    int http_status;
    char account_url[ACME_URL_MAX_LENGTH];
    char jwk_thumbprint[ACME_THUMBPRINT_LENGTH];
} acme_account_status_t;

esp_err_t acme_client_probe_staging(acme_directory_status_t *out_status);

/* Read local account identity state. Does not contact Let's Encrypt. */
esp_err_t acme_client_get_account_status(acme_account_status_t *out_status);

/*
 * Ensure a persistent P-256 account key exists and register/recover the
 * corresponding account against Let's Encrypt staging.
 */
esp_err_t acme_client_provision_staging_account(acme_account_status_t *out_status);

#ifdef __cplusplus
}
#endif
