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

/* Persistent unattended-renewal policy switch. Defaults disabled when absent. */
esp_err_t acme_client_get_automatic_renewal_enabled(bool *out_enabled);
esp_err_t acme_client_set_automatic_renewal_enabled(bool enabled);
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


/*
 * Phase 5B.10e.1 reusable production certificate transaction core.
 *
 * This API is deliberately inert until a caller invokes it. It does not alter
 * the persisted automatic-renewal policy and it never activates TLS credentials.
 * DNS-01 publication remains owned by the caller through the hooks below so the
 * ACME client does not acquire Cloudflare credentials or provider-specific logic.
 * prepare_dns01 must publish, verify, and perform any required propagation wait
 * before returning ESP_OK. cleanup_dns01 is attempted on every path after a
 * successful prepare_dns01 call, including ACME validation/finalization failure.
 */
typedef esp_err_t (*acme_production_dns01_prepare_fn)(
    const acme_order_discovery_t *order,
    void *context);

typedef esp_err_t (*acme_production_dns01_cleanup_fn)(
    const acme_order_discovery_t *order,
    void *context);

typedef struct {
    acme_production_dns01_prepare_fn prepare_dns01;
    acme_production_dns01_cleanup_fn cleanup_dns01;
    void *context;
} acme_production_dns01_hooks_t;

typedef enum {
    ACME_PRODUCTION_TRANSACTION_STAGE_NONE = 0,
    ACME_PRODUCTION_TRANSACTION_STAGE_ACCOUNT,
    ACME_PRODUCTION_TRANSACTION_STAGE_ORDER,
    ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_PREPARE,
    ACME_PRODUCTION_TRANSACTION_STAGE_CHALLENGE,
    ACME_PRODUCTION_TRANSACTION_STAGE_FINALIZE,
    ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_CLEANUP,
    ACME_PRODUCTION_TRANSACTION_STAGE_COMPLETE,
} acme_production_transaction_stage_t;

typedef struct {
    acme_production_transaction_stage_t stage;
    esp_err_t primary_result;
    esp_err_t cleanup_result;
    bool dns01_prepared;
    bool cleanup_attempted;
    bool completed;
    acme_account_status_t account;
    acme_order_discovery_t order;
    acme_challenge_validation_t validation;
    acme_certificate_issue_status_t certificate;
} acme_production_transaction_status_t;

#define ACME_RENEWAL_ATTEMPT_RECORD_VERSION 1U
typedef struct {
    uint32_t version;
    uint32_t attempt_count;
    int64_t last_attempt_unix;
    int64_t retry_not_before_unix;
    bool attempt_was_in_progress;
    bool last_attempt_result_valid;
    esp_err_t last_attempt_result;
    acme_production_transaction_stage_t last_transaction_stage;
    bool last_transaction_completed;
    bool last_dns01_prepared;
    bool last_cleanup_attempted;
    esp_err_t last_cleanup_result;
} acme_renewal_attempt_record_t;

esp_err_t acme_client_load_renewal_attempt_record(acme_renewal_attempt_record_t *out_record);
esp_err_t acme_client_store_renewal_attempt_record(const acme_renewal_attempt_record_t *record);

/*
 * Run one complete production issuance/replacement transaction using the
 * existing protected account identity and dual-slot production store.
 * Successful finalization stores the new credential atomically through the
 * existing production storage path, but does NOT activate it for management TLS.
 * No scheduler or HTTP endpoint calls this function in 5B.10e.1.
 */
esp_err_t acme_client_run_production_certificate_transaction(
    const char *hostname,
    const acme_production_dns01_hooks_t *dns01_hooks,
    acme_production_transaction_status_t *out_status);

#ifdef __cplusplus
}
#endif
