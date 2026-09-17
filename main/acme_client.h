#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACME_URL_MAX_LENGTH       384U
#define ACME_THUMBPRINT_LENGTH     44U
#define ACME_DNS_NAME_MAX_LENGTH    253U
#define ACME_CHALLENGE_TOKEN_MAX_LENGTH 255U
#define ACME_DNS01_VALUE_LENGTH      44U

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

typedef struct {
    bool discovered;
    int new_order_http_status;
    int authorization_http_status;
    char identifier[ACME_DNS_NAME_MAX_LENGTH + 1U];
    char order_url[ACME_URL_MAX_LENGTH];
    char authorization_url[ACME_URL_MAX_LENGTH];
    char finalize_url[ACME_URL_MAX_LENGTH];
    char challenge_url[ACME_URL_MAX_LENGTH];
    char challenge_token[ACME_CHALLENGE_TOKEN_MAX_LENGTH + 1U];
    char challenge_status[24];
    char dns01_record_name[ACME_DNS_NAME_MAX_LENGTH + 32U];
    char dns01_value[ACME_DNS01_VALUE_LENGTH];
} acme_order_discovery_t;

typedef struct {
    bool triggered;
    bool valid;
    int trigger_http_status;
    int poll_http_status;
    unsigned poll_count;
    char authorization_status[24];
    char challenge_status[24];
} acme_challenge_validation_t;

esp_err_t acme_client_probe_staging(acme_directory_status_t *out_status);

/* Read local account identity state. Does not contact Let's Encrypt. */
esp_err_t acme_client_get_account_status(acme_account_status_t *out_status);

/*
 * Ensure a persistent P-256 account key exists and register/recover the
 * corresponding account against Let's Encrypt staging.
 */
esp_err_t acme_client_provision_staging_account(acme_account_status_t *out_status);

/* Creates a staging order and discovers DNS-01 data; does not create DNS or trigger validation. */
esp_err_t acme_client_discover_staging_order(const char *hostname,
                                             acme_order_discovery_t *out_status);

/* Trigger a discovered staging DNS-01 challenge and poll its authorization. */
esp_err_t acme_client_validate_staging_dns01(const acme_order_discovery_t *order,
                                             acme_challenge_validation_t *out_status);

#ifdef __cplusplus
}
#endif
