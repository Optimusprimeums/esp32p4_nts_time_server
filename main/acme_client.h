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

typedef struct {
    bool finalized;
    bool certificate_retrieved;
    bool stored;
    int finalize_http_status;
    int order_poll_http_status;
    int certificate_http_status;
    unsigned order_poll_count;
    size_t certificate_pem_length;
    char identifier[ACME_DNS_NAME_MAX_LENGTH + 1U];
    char order_status[24];
    char certificate_url[ACME_URL_MAX_LENGTH];
} acme_certificate_issue_status_t;




typedef struct {
    char *certificate_pem;
    size_t certificate_pem_length;
    char *private_key_pem;
    size_t private_key_pem_length;
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
} acme_tls_credentials_t;

typedef struct {
    bool key_present;
    bool certificate_present;
    bool hostname_present;
    bool certificate_parse_valid;
    bool hostname_matches_certificate;
    bool private_key_matches_certificate;
    unsigned chain_certificate_count;
    size_t certificate_pem_length;
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    char valid_from[32];
    char valid_to[32];
    char leaf_sha256[65];
} acme_certificate_inspection_t;

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

/* Finalize an already validated staging order, retrieve and securely store its certificate/key. */
esp_err_t acme_client_finalize_staging_order(const acme_order_discovery_t *order,
                                             acme_certificate_issue_status_t *out_status);

/* Inspect protected stored certificate material without exposing the private key or PEM. */
esp_err_t acme_client_inspect_stored_certificate(acme_certificate_inspection_t *out_status);

/* Read-only inspection of separately stored production certificate material. */
esp_err_t acme_client_inspect_stored_production_certificate(acme_certificate_inspection_t *out_status);

/* Load only public production certificate PEM for authenticated export. Caller frees *out_pem. */
esp_err_t acme_client_load_production_certificate_pem(char **out_pem, size_t *out_pem_length,
                                                       char *out_hostname, size_t hostname_size);

/* Load validated stored TLS material for in-process server use. Never expose via HTTP. */
esp_err_t acme_client_load_stored_tls_credentials(acme_tls_credentials_t *out_credentials);
esp_err_t acme_client_load_production_tls_credentials(acme_tls_credentials_t *out_credentials);
void acme_client_free_tls_credentials(acme_tls_credentials_t *credentials);

/* Persisted boot TLS selection. Only production may be selected persistently. */
esp_err_t acme_client_get_production_boot_selected(bool *out_selected);
esp_err_t acme_client_set_production_boot_selected(bool selected);
/* Prepare/migrate the production credential store. ESP_ERR_NOT_FOUND means no production credential exists. */
esp_err_t acme_client_prepare_production_storage(void);

/* Dual-slot production credential storage diagnostics. active_slot is 'A' or 'B'. */
esp_err_t acme_client_get_production_storage_status(char *active_slot,
                                                     bool *slot_a_valid,
                                                     bool *slot_b_valid,
                                                     bool *legacy_material_present);

/* Phase 5B.8h production ACME APIs. Production account KID and certificate
 * material are stored separately from staging state. These APIs never activate
 * the resulting server credential. */
esp_err_t acme_client_provision_production_account(acme_account_status_t *out_status);
esp_err_t acme_client_discover_production_order(const char *hostname, acme_order_discovery_t *out_status);
esp_err_t acme_client_validate_production_dns01(const acme_order_discovery_t *order, acme_challenge_validation_t *out_status);
esp_err_t acme_client_finalize_production_order(const acme_order_discovery_t *order, acme_certificate_issue_status_t *out_status);

#ifdef __cplusplus
}
#endif
