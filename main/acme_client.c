#include "acme_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acme_storage.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"

static const char *TAG = "ACME";

#define ACME_STAGING_DIRECTORY_URL \
    "https://acme-staging-v02.api.letsencrypt.org/directory"
#define ACME_PRODUCTION_DIRECTORY_URL \
    "https://acme-v02.api.letsencrypt.org/directory"
#define ACME_PROD_ACCOUNT_NVS_KEY "acct_prod"

#define ACME_RESPONSE_MAX      16384U
#define ACME_NONCE_MAX           256U
#define ACME_JWK_MAX             256U
#define ACME_PROTECTED_MAX       896U
#define ACME_JWS_MAX            3072U
#define ACME_WORKER_STACK_SIZE  20480U
#define ACME_WORKER_PRIORITY        5U

typedef struct {
    char data[ACME_RESPONSE_MAX];
    size_t used;
    bool overflow;
    char replay_nonce[ACME_NONCE_MAX];
    char location[ACME_URL_MAX_LENGTH];
} acme_response_buffer_t;

typedef enum {
    ACME_WORK_PROBE = 0,
    ACME_WORK_PROVISION_ACCOUNT,
    ACME_WORK_DISCOVER_ORDER,
    ACME_WORK_VALIDATE_DNS01,
    ACME_WORK_FINALIZE_ORDER,
} acme_work_type_t;

typedef struct {
    TaskHandle_t caller;
    acme_work_type_t type;
    acme_directory_status_t directory;
    acme_account_status_t account;
    acme_order_discovery_t order;
    acme_challenge_validation_t validation;
    acme_certificate_issue_status_t certificate;
    char requested_hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    bool production;
    esp_err_t result;
} acme_worker_context_t;

static bool copy_header(char *destination,
                        size_t destination_size,
                        const char *data)
{
    if (destination == NULL || destination_size < 2U || data == NULL) {
        return false;
    }

    const size_t data_len = strnlen(data, destination_size);
    if (data_len == 0U || data_len >= destination_size) {
        return false;
    }

    memcpy(destination, data, data_len);
    destination[data_len] = '\0';
    return true;
}

static esp_err_t http_event_handler(esp_http_client_event_t *event)
{
    if (event == NULL || event->user_data == NULL) {
        return ESP_OK;
    }

    acme_response_buffer_t *response =
        (acme_response_buffer_t *)event->user_data;

    if (event->event_id == HTTP_EVENT_ON_HEADER &&
        event->header_key != NULL &&
        event->header_value != NULL) {
        if (strcasecmp(event->header_key, "Replay-Nonce") == 0) {
            (void)copy_header(response->replay_nonce,
                              sizeof(response->replay_nonce),
                              event->header_value);
        } else if (strcasecmp(event->header_key, "Location") == 0) {
            (void)copy_header(response->location,
                              sizeof(response->location),
                              event->header_value);
        }
    }

    if (event->event_id == HTTP_EVENT_ON_DATA &&
        event->data != NULL &&
        event->data_len > 0) {
        const size_t incoming = (size_t)event->data_len;

        if (incoming > sizeof(response->data) - 1U - response->used) {
            response->overflow = true;
            return ESP_OK;
        }

        memcpy(response->data + response->used, event->data, incoming);
        response->used += incoming;
        response->data[response->used] = '\0';
    }

    return ESP_OK;
}

static const char *skip_ws(const char *p)
{
    while (p != NULL &&
           (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        ++p;
    }
    return p;
}

static bool extract_json_string(const char *json,
                                const char *name,
                                char *output,
                                size_t output_size)
{
    if (json == NULL || name == NULL ||
        output == NULL || output_size < 2U) {
        return false;
    }

    char key[64];
    const int key_len = snprintf(key, sizeof(key), "\"%s\"", name);
    if (key_len < 0 || key_len >= (int)sizeof(key)) {
        return false;
    }

    const char *p = strstr(json, key);
    if (p == NULL) return false;
    p += strlen(key);
    p = skip_ws(p);
    if (p == NULL || *p++ != ':') return false;
    p = skip_ws(p);
    if (p == NULL || *p++ != '"') return false;

    size_t used = 0U;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' ||
            (unsigned char)*p < 0x20U ||
            used + 1U >= output_size) {
            return false;
        }
        output[used++] = *p++;
    }

    if (*p != '"' || used == 0U) return false;
    output[used] = '\0';
    return true;
}

static bool is_https_url(const char *url)
{
    return url != NULL &&
           strncmp(url, "https://", 8U) == 0;
}

static esp_err_t base64url(const uint8_t *input,
                           size_t input_length,
                           char *output,
                           size_t output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    if (input == NULL || output == NULL || output_size < 2U) {
        return ESP_ERR_INVALID_ARG;
    }

    const size_t required = ((input_length + 2U) / 3U) * 4U;
    const size_t padding = (3U - (input_length % 3U)) % 3U;
    const size_t unpadded = required - padding;

    if (unpadded + 1U > output_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t in = 0U;
    size_t out = 0U;

    while (in + 3U <= input_length) {
        const uint32_t value =
            ((uint32_t)input[in] << 16) |
            ((uint32_t)input[in + 1U] << 8) |
            (uint32_t)input[in + 2U];

        output[out++] = alphabet[(value >> 18) & 0x3FU];
        output[out++] = alphabet[(value >> 12) & 0x3FU];
        output[out++] = alphabet[(value >> 6) & 0x3FU];
        output[out++] = alphabet[value & 0x3FU];
        in += 3U;
    }

    const size_t remaining = input_length - in;
    if (remaining == 1U) {
        const uint32_t value = (uint32_t)input[in] << 16;
        output[out++] = alphabet[(value >> 18) & 0x3FU];
        output[out++] = alphabet[(value >> 12) & 0x3FU];
    } else if (remaining == 2U) {
        const uint32_t value =
            ((uint32_t)input[in] << 16) |
            ((uint32_t)input[in + 1U] << 8);
        output[out++] = alphabet[(value >> 18) & 0x3FU];
        output[out++] = alphabet[(value >> 12) & 0x3FU];
        output[out++] = alphabet[(value >> 6) & 0x3FU];
    }

    output[out] = '\0';
    return ESP_OK;
}

static esp_err_t sha256_bytes(const void *data,
                              size_t data_length,
                              uint8_t digest[32])
{
    size_t digest_length = 0U;
    const psa_status_t status =
        psa_hash_compute(PSA_ALG_SHA_256,
                         (const uint8_t *)data,
                         data_length,
                         digest,
                         32U,
                         &digest_length);

    return (status == PSA_SUCCESS && digest_length == 32U)
               ? ESP_OK
               : ESP_FAIL;
}

static esp_err_t probe_directory_sync(const char *directory_url, acme_directory_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) return ESP_ERR_NO_MEM;

    esp_http_client_config_t config = {
        .url = directory_url,
        .event_handler = http_event_handler,
        .user_data = response,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .keep_alive_enable = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        free(response);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err =
        esp_http_client_set_header(client, "Accept", "application/json");
    if (err == ESP_OK) {
        err = esp_http_client_set_header(
            client, "User-Agent", "esp32p4-ntp/phase5b8b");
    }
    if (err == ESP_OK) err = esp_http_client_perform(client);

    out_status->http_status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        free(response);
        return err;
    }
    if (response->overflow) {
        free(response);
        return ESP_ERR_INVALID_SIZE;
    }
    if (out_status->http_status != 200) {
        free(response);
        return ESP_ERR_INVALID_RESPONSE;
    }

    if (!extract_json_string(response->data, "newNonce",
                             out_status->new_nonce_url,
                             sizeof(out_status->new_nonce_url)) ||
        !extract_json_string(response->data, "newAccount",
                             out_status->new_account_url,
                             sizeof(out_status->new_account_url)) ||
        !extract_json_string(response->data, "newOrder",
                             out_status->new_order_url,
                             sizeof(out_status->new_order_url)) ||
        !is_https_url(out_status->new_nonce_url) ||
        !is_https_url(out_status->new_account_url) ||
        !is_https_url(out_status->new_order_url)) {
        free(response);
        return ESP_ERR_INVALID_RESPONSE;
    }

    free(response);
    out_status->reachable = true;
    return ESP_OK;
}

static esp_err_t import_account_key(const uint8_t private_key[32],
                                    psa_key_usage_t usage,
                                    psa_key_id_t *out_key_id)
{
    if (private_key == NULL || out_key_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256U);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    const psa_status_t status =
        psa_import_key(&attributes,
                       private_key,
                       ACME_ACCOUNT_PRIVATE_KEY_LENGTH,
                       out_key_id);
    psa_reset_key_attributes(&attributes);

    return status == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

static esp_err_t probe_staging_sync(acme_directory_status_t *out_status)
{
    return probe_directory_sync(ACME_STAGING_DIRECTORY_URL, out_status);
}

static esp_err_t probe_production_sync(acme_directory_status_t *out_status)
{
    return probe_directory_sync(ACME_PRODUCTION_DIRECTORY_URL, out_status);
}

static esp_err_t load_production_account_url(char *url, size_t url_size)
{
    if (url == NULL || url_size < 2U) return ESP_ERR_INVALID_ARG;
    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;
    size_t len = url_size;
    err = nvs_get_str(handle, ACME_PROD_ACCOUNT_NVS_KEY, url, &len);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_NOT_FOUND;
    return err;
}

static esp_err_t store_production_account_url(const char *url)
{
    if (!is_https_url(url)) return ESP_ERR_INVALID_ARG;
    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_str(handle, ACME_PROD_ACCOUNT_NVS_KEY, url);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

static esp_err_t ensure_account_key(uint8_t private_key[32],
                                    bool *out_created)
{
    if (private_key == NULL || out_created == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_created = false;

    esp_err_t err = acme_storage_load_private_key(private_key);
    if (err == ESP_OK) {
        return ESP_OK;
    }
    if (err != ESP_ERR_NOT_FOUND) {
        return err;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256U);
    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_generate_key(&attributes, &key_id);
    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    size_t private_length = 0U;
    status = psa_export_key(key_id,
                            private_key,
                            ACME_ACCOUNT_PRIVATE_KEY_LENGTH,
                            &private_length);

    const psa_status_t destroy_status = psa_destroy_key(key_id);
    (void)destroy_status;

    if (status != PSA_SUCCESS ||
        private_length != ACME_ACCOUNT_PRIVATE_KEY_LENGTH) {
        memset(private_key, 0, ACME_ACCOUNT_PRIVATE_KEY_LENGTH);
        return ESP_FAIL;
    }

    err = acme_storage_store_private_key(private_key);
    if (err != ESP_OK) {
        memset(private_key, 0, ACME_ACCOUNT_PRIVATE_KEY_LENGTH);
        return err;
    }

    *out_created = true;
    ESP_LOGI(TAG, "Generated persistent P-256 ACME account key");
    return ESP_OK;
}

static esp_err_t build_jwk_and_thumbprint(
    const uint8_t private_key[32],
    char *jwk,
    size_t jwk_size,
    char thumbprint[ACME_THUMBPRINT_LENGTH])
{
    psa_key_id_t key_id = 0;
    esp_err_t err =
        import_account_key(private_key, PSA_KEY_USAGE_SIGN_HASH, &key_id);
    if (err != ESP_OK) {
        return err;
    }

    /*
     * PSA exports a secp-r1 public key in SEC1 uncompressed form:
     * 0x04 || X(32) || Y(32).
     */
    uint8_t public_key[65];
    size_t public_length = 0U;
    const psa_status_t export_status =
        psa_export_public_key(key_id,
                              public_key,
                              sizeof(public_key),
                              &public_length);
    const psa_status_t destroy_status = psa_destroy_key(key_id);
    (void)destroy_status;

    if (export_status != PSA_SUCCESS ||
        public_length != sizeof(public_key) ||
        public_key[0] != 0x04U) {
        memset(public_key, 0, sizeof(public_key));
        return ESP_FAIL;
    }

    char x[44];
    char y[44];
    err = base64url(public_key + 1U, 32U, x, sizeof(x));
    if (err == ESP_OK) {
        err = base64url(public_key + 33U, 32U, y, sizeof(y));
    }
    memset(public_key, 0, sizeof(public_key));
    if (err != ESP_OK) {
        return err;
    }

    /*
     * RFC 7638 requires lexicographic member ordering for this EC JWK:
     * crv, kty, x, y.
     */
    const int n = snprintf(jwk, jwk_size,
                           "{\"crv\":\"P-256\",\"kty\":\"EC\","
                           "\"x\":\"%s\",\"y\":\"%s\"}",
                           x, y);
    if (n < 0 || n >= (int)jwk_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t digest[32];
    err = sha256_bytes(jwk, strlen(jwk), digest);
    if (err == ESP_OK) {
        err = base64url(digest, sizeof(digest),
                        thumbprint, ACME_THUMBPRINT_LENGTH);
    }
    memset(digest, 0, sizeof(digest));
    return err;
}

static esp_err_t get_nonce(const char *nonce_url,
                           char nonce[ACME_NONCE_MAX],
                           int *out_http_status)
{
    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) return ESP_ERR_NO_MEM;

    esp_http_client_config_t config = {
        .url = nonce_url,
        .event_handler = http_event_handler,
        .user_data = response,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .keep_alive_enable = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        free(response);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_HEAD);
    if (err == ESP_OK) {
        err = esp_http_client_set_header(
            client, "User-Agent", "esp32p4-ntp/phase5b8b");
    }
    if (err == ESP_OK) err = esp_http_client_perform(client);

    const int status = esp_http_client_get_status_code(client);
    if (out_http_status != NULL) *out_http_status = status;
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        free(response);
        return err;
    }
    if (status < 200 || status >= 400) {
        free(response);
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (response->replay_nonce[0] == '\0') {
        free(response);
        return ESP_ERR_INVALID_RESPONSE;
    }

    snprintf(nonce, ACME_NONCE_MAX, "%s", response->replay_nonce);
    free(response);
    return ESP_OK;
}

static esp_err_t sign_es256(const uint8_t private_key[32],
                            const uint8_t digest[32],
                            uint8_t signature[64])
{
    psa_key_id_t key_id = 0;
    esp_err_t err =
        import_account_key(private_key, PSA_KEY_USAGE_SIGN_HASH, &key_id);
    if (err != ESP_OK) {
        return err;
    }

    size_t signature_length = 0U;
    const psa_status_t sign_status =
        psa_sign_hash(key_id,
                      PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                      digest,
                      32U,
                      signature,
                      64U,
                      &signature_length);

    const psa_status_t destroy_status = psa_destroy_key(key_id);
    (void)destroy_status;

    /*
     * PSA ECDSA signatures use the fixed-width raw r || s encoding required
     * by JWS ES256, rather than ASN.1 DER.
     */
    if (sign_status != PSA_SUCCESS || signature_length != 64U) {
        memset(signature, 0, 64U);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t build_new_account_jws(
    const char *new_account_url,
    const char *nonce,
    const char *jwk,
    const uint8_t private_key[32],
    char *out_jws,
    size_t out_jws_size)
{
    char protected_json[ACME_PROTECTED_MAX];
    int n = snprintf(protected_json, sizeof(protected_json),
                     "{\"alg\":\"ES256\",\"jwk\":%s,"
                     "\"nonce\":\"%s\",\"url\":\"%s\"}",
                     jwk, nonce, new_account_url);
    if (n < 0 || n >= (int)sizeof(protected_json)) {
        return ESP_ERR_INVALID_SIZE;
    }

    static const char payload_json[] =
        "{\"termsOfServiceAgreed\":true}";

    char protected64[1280];
    char payload64[128];
    esp_err_t err = base64url((const uint8_t *)protected_json,
                              strlen(protected_json),
                              protected64,
                              sizeof(protected64));
    if (err == ESP_OK) {
        err = base64url((const uint8_t *)payload_json,
                        strlen(payload_json),
                        payload64,
                        sizeof(payload64));
    }
    if (err != ESP_OK) return err;

    char signing_input[1536];
    n = snprintf(signing_input, sizeof(signing_input),
                 "%s.%s", protected64, payload64);
    if (n < 0 || n >= (int)sizeof(signing_input)) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t digest[32];
    uint8_t signature[64];
    err = sha256_bytes(signing_input, strlen(signing_input), digest);
    if (err == ESP_OK) {
        err = sign_es256(private_key, digest, signature);
    }
    memset(digest, 0, sizeof(digest));
    if (err != ESP_OK) {
        memset(signature, 0, sizeof(signature));
        return err;
    }

    char signature64[96];
    err = base64url(signature, sizeof(signature),
                    signature64, sizeof(signature64));
    memset(signature, 0, sizeof(signature));
    if (err != ESP_OK) return err;

    n = snprintf(out_jws, out_jws_size,
                 "{\"protected\":\"%s\",\"payload\":\"%s\","
                 "\"signature\":\"%s\"}",
                 protected64, payload64, signature64);
    if (n < 0 || n >= (int)out_jws_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}

static esp_err_t post_new_account(const char *url,
                                  const char *jws,
                                  acme_response_buffer_t *response,
                                  int *out_http_status)
{
    memset(response, 0, sizeof(*response));

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = http_event_handler,
        .user_data = response,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .keep_alive_enable = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) return ESP_ERR_NO_MEM;

    esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_POST);
    if (err == ESP_OK) {
        err = esp_http_client_set_header(
            client, "Content-Type", "application/jose+json");
    }
    if (err == ESP_OK) {
        err = esp_http_client_set_header(
            client, "Accept", "application/json");
    }
    if (err == ESP_OK) {
        err = esp_http_client_set_header(
            client, "User-Agent", "esp32p4-ntp/phase5b8b");
    }
    if (err == ESP_OK) {
        err = esp_http_client_set_post_field(client, jws,
                                             (int)strlen(jws));
    }
    if (err == ESP_OK) err = esp_http_client_perform(client);

    const int status = esp_http_client_get_status_code(client);
    if (out_http_status != NULL) *out_http_status = status;
    esp_http_client_cleanup(client);

    if (err != ESP_OK) return err;
    if (response->overflow) return ESP_ERR_INVALID_SIZE;

    /*
     * RFC 8555 newAccount returns 201 for a newly created account and 200
     * when the same account key already identifies an existing account.
     */
    if (status != 200 && status != 201) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (!is_https_url(response->location)) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

static esp_err_t account_status_local(acme_account_status_t *out_status)
{
    memset(out_status, 0, sizeof(*out_status));

    acme_storage_status_t storage;
    esp_err_t err = acme_storage_get_status(&storage);
    if (err != ESP_OK) return err;

    out_status->key_present = storage.private_key_present;
    out_status->registered = storage.account_url_present;
    if (storage.account_url_present) {
        snprintf(out_status->account_url,
                 sizeof(out_status->account_url),
                 "%s", storage.account_url);
    }

    if (storage.private_key_present) {
        uint8_t private_key[32];
        err = acme_storage_load_private_key(private_key);
        if (err == ESP_OK) {
            char jwk[ACME_JWK_MAX];
            err = build_jwk_and_thumbprint(
                private_key, jwk, sizeof(jwk),
                out_status->jwk_thumbprint);
            memset(jwk, 0, sizeof(jwk));
        }
        memset(private_key, 0, sizeof(private_key));
    }
    return err;
}

static esp_err_t provision_account_sync(bool production, acme_account_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;

    uint8_t private_key[32];
    bool created = false;
    err = ensure_account_key(private_key, &created);
    if (err != ESP_OK) return err;

    char jwk[ACME_JWK_MAX];
    err = build_jwk_and_thumbprint(private_key,
                                   jwk, sizeof(jwk),
                                   out_status->jwk_thumbprint);
    if (err != ESP_OK) {
        memset(private_key, 0, sizeof(private_key));
        return err;
    }
    out_status->key_present = true;

    char existing_url[ACME_URL_MAX_LENGTH];
    err = production ? load_production_account_url(existing_url, sizeof(existing_url))
                     : acme_storage_load_account_url(existing_url, sizeof(existing_url));
    if (err == ESP_OK && is_https_url(existing_url)) {
        out_status->registered = true;
        snprintf(out_status->account_url,
                 sizeof(out_status->account_url),
                 "%s", existing_url);
        memset(private_key, 0, sizeof(private_key));
        memset(jwk, 0, sizeof(jwk));
        return ESP_OK;
    }
    if (err != ESP_ERR_NOT_FOUND) {
        memset(private_key, 0, sizeof(private_key));
        memset(jwk, 0, sizeof(jwk));
        return err;
    }

    acme_directory_status_t directory;
    err = production ? probe_production_sync(&directory) : probe_staging_sync(&directory);
    if (err != ESP_OK) goto cleanup;

    char nonce[ACME_NONCE_MAX];
    int nonce_status = 0;
    err = get_nonce(directory.new_nonce_url, nonce, &nonce_status);
    if (err != ESP_OK) {
        out_status->http_status = nonce_status;
        goto cleanup;
    }

    char *jws = calloc(1U, ACME_JWS_MAX);
    if (jws == NULL) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    err = build_new_account_jws(directory.new_account_url,
                                nonce, jwk, private_key,
                                jws, ACME_JWS_MAX);
    memset(nonce, 0, sizeof(nonce));
    if (err != ESP_OK) {
        memset(jws, 0, ACME_JWS_MAX);
        free(jws);
        goto cleanup;
    }

    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) {
        memset(jws, 0, ACME_JWS_MAX);
        free(jws);
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    int status = 0;
    err = post_new_account(directory.new_account_url,
                           jws, response, &status);
    memset(jws, 0, ACME_JWS_MAX);
    free(jws);
    out_status->http_status = status;

    if (err == ESP_OK) {
        err = production ? store_production_account_url(response->location)
                         : acme_storage_store_account_url(response->location);
        if (err == ESP_OK) {
            out_status->registered = true;
            snprintf(out_status->account_url,
                     sizeof(out_status->account_url),
                     "%s", response->location);
            ESP_LOGI(TAG, "%s",
                     production ? "Let's Encrypt production ACME account registered/recovered"
                                : "Let's Encrypt staging ACME account registered/recovered");
        }
    }

    memset(response, 0, sizeof(*response));
    free(response);

cleanup:
    memset(private_key, 0, sizeof(private_key));
    memset(jwk, 0, sizeof(jwk));
    (void)created;
    return err;
}


static bool dns_name_is_valid(const char *name)
{
    if (name == NULL) return false;
    const size_t length = strlen(name);
    if (length == 0U || length > ACME_DNS_NAME_MAX_LENGTH ||
        name[0] == '.' || name[length - 1U] == '.') return false;

    size_t label_length = 0U;
    for (size_t i = 0U; i < length; ++i) {
        const char c = name[i];
        if (c == '.') {
            if (label_length == 0U || label_length > 63U || name[i - 1U] == '-') return false;
            label_length = 0U;
            continue;
        }
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok || (label_length == 0U && c == '-')) return false;
        ++label_length;
    }
    return label_length > 0U && label_length <= 63U && name[length - 1U] != '-';
}

static bool extract_first_array_string(const char *json, const char *name,
                                       char *output, size_t output_size)
{
    if (json == NULL || name == NULL || output == NULL || output_size < 2U) return false;
    char key[64];
    const int key_len = snprintf(key, sizeof(key), "\"%s\"", name);
    if (key_len < 0 || key_len >= (int)sizeof(key)) return false;
    const char *p = strstr(json, key);
    if (p == NULL) return false;
    p += strlen(key);
    p = skip_ws(p);
    if (*p++ != ':') return false;
    p = skip_ws(p);
    if (*p++ != '[') return false;
    p = skip_ws(p);
    if (*p++ != '"') return false;
    size_t used = 0U;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' || (unsigned char)*p < 0x20U || used + 1U >= output_size) return false;
        output[used++] = *p++;
    }
    if (*p != '"' || used == 0U) return false;
    output[used] = '\0';
    return true;
}

static bool extract_dns01_challenge(const char *json,
                                    char *url, size_t url_size,
                                    char *token, size_t token_size,
                                    char *status, size_t status_size)
{
    if (json == NULL) return false;
    const char *type = strstr(json, "\"type\":\"dns-01\"");
    if (type == NULL) type = strstr(json, "\"type\": \"dns-01\"");
    if (type == NULL) return false;

    const char *start = type;
    while (start > json && *start != '{') --start;
    if (*start != '{') return false;
    const char *end = strchr(type, '}');
    if (end == NULL) return false;
    const size_t length = (size_t)(end - start + 1);
    if (length >= 1536U) return false;

    char object[1536];
    memcpy(object, start, length);
    object[length] = '\0';
    return extract_json_string(object, "url", url, url_size) &&
           extract_json_string(object, "token", token, token_size) &&
           extract_json_string(object, "status", status, status_size);
}

static esp_err_t build_kid_jws(const char *url, const char *nonce,
                               const char *kid, const char *payload_json,
                               const uint8_t private_key[32],
                               char *out_jws, size_t out_jws_size)
{
    if (url == NULL || nonce == NULL || kid == NULL || payload_json == NULL ||
        private_key == NULL || out_jws == NULL) return ESP_ERR_INVALID_ARG;

    char protected_json[ACME_PROTECTED_MAX];
    int n = snprintf(protected_json, sizeof(protected_json),
                     "{\"alg\":\"ES256\",\"kid\":\"%s\","
                     "\"nonce\":\"%s\",\"url\":\"%s\"}",
                     kid, nonce, url);
    if (n < 0 || n >= (int)sizeof(protected_json)) return ESP_ERR_INVALID_SIZE;

    char protected64[1280];
    char payload64[2048];
    esp_err_t err = base64url((const uint8_t *)protected_json, strlen(protected_json),
                              protected64, sizeof(protected64));
    if (err == ESP_OK) {
        err = base64url((const uint8_t *)payload_json, strlen(payload_json),
                        payload64, sizeof(payload64));
    }
    if (err != ESP_OK) return err;

    char *signing_input = calloc(1U, 3584U);
    if (signing_input == NULL) return ESP_ERR_NO_MEM;
    n = snprintf(signing_input, 3584U, "%s.%s", protected64, payload64);
    if (n < 0 || n >= 3584) {
        memset(signing_input, 0, 3584U); free(signing_input); return ESP_ERR_INVALID_SIZE;
    }

    uint8_t digest[32];
    uint8_t signature[64];
    err = sha256_bytes(signing_input, strlen(signing_input), digest);
    memset(signing_input, 0, 3584U);
    free(signing_input);
    if (err == ESP_OK) err = sign_es256(private_key, digest, signature);
    memset(digest, 0, sizeof(digest));
    if (err != ESP_OK) { memset(signature, 0, sizeof(signature)); return err; }

    char signature64[96];
    err = base64url(signature, sizeof(signature), signature64, sizeof(signature64));
    memset(signature, 0, sizeof(signature));
    if (err != ESP_OK) return err;

    n = snprintf(out_jws, out_jws_size,
                 "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
                 protected64, payload64, signature64);
    return (n < 0 || n >= (int)out_jws_size) ? ESP_ERR_INVALID_SIZE : ESP_OK;
}

static esp_err_t acme_post(const char *url, const char *jws,
                           acme_response_buffer_t *response, int *out_http_status)
{
    memset(response, 0, sizeof(*response));
    esp_http_client_config_t config = {
        .url = url, .event_handler = http_event_handler, .user_data = response,
        .crt_bundle_attach = esp_crt_bundle_attach, .timeout_ms = 15000,
        .keep_alive_enable = false,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) return ESP_ERR_NO_MEM;
    esp_err_t err = esp_http_client_set_method(client, HTTP_METHOD_POST);
    if (err == ESP_OK) err = esp_http_client_set_header(client, "Content-Type", "application/jose+json");
    if (err == ESP_OK) err = esp_http_client_set_header(client, "Accept", "application/json");
    if (err == ESP_OK) err = esp_http_client_set_header(client, "User-Agent", "esp32p4-ntp/phase5b8d");
    if (err == ESP_OK) err = esp_http_client_set_post_field(client, jws, (int)strlen(jws));
    if (err == ESP_OK) err = esp_http_client_perform(client);
    const int status = esp_http_client_get_status_code(client);
    if (out_http_status != NULL) *out_http_status = status;
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return err;
    if (response->overflow) return ESP_ERR_INVALID_SIZE;
    return ESP_OK;
}

static esp_err_t signed_request(const char *nonce_url, const char *url,
                                const char *kid, const char *payload_json,
                                const uint8_t private_key[32],
                                acme_response_buffer_t *response,
                                int *out_http_status)
{
    char nonce[ACME_NONCE_MAX];
    int nonce_status = 0;
    esp_err_t err = get_nonce(nonce_url, nonce, &nonce_status);
    if (err != ESP_OK) {
        if (out_http_status != NULL) *out_http_status = nonce_status;
        return err;
    }
    char *jws = calloc(1U, ACME_JWS_MAX);
    if (jws == NULL) { memset(nonce, 0, sizeof(nonce)); return ESP_ERR_NO_MEM; }
    err = build_kid_jws(url, nonce, kid, payload_json, private_key, jws, ACME_JWS_MAX);
    memset(nonce, 0, sizeof(nonce));
    if (err == ESP_OK) err = acme_post(url, jws, response, out_http_status);
    memset(jws, 0, ACME_JWS_MAX);
    free(jws);
    return err;
}

static esp_err_t discover_order_sync(bool production, const char *hostname, acme_order_discovery_t *out)
{
    if (hostname == NULL || out == NULL || !dns_name_is_valid(hostname)) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    snprintf(out->identifier, sizeof(out->identifier), "%s", hostname);

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    uint8_t private_key[32];
    err = acme_storage_load_private_key(private_key);
    if (err != ESP_OK) return err;
    char kid[ACME_URL_MAX_LENGTH];
    err = production ? load_production_account_url(kid, sizeof(kid)) : acme_storage_load_account_url(kid, sizeof(kid));
    if (err != ESP_OK || !is_https_url(kid)) { memset(private_key, 0, sizeof(private_key)); return ESP_ERR_INVALID_STATE; }

    acme_directory_status_t directory;
    err = production ? probe_production_sync(&directory) : probe_staging_sync(&directory);
    if (err != ESP_OK) goto cleanup;

    char payload[ACME_DNS_NAME_MAX_LENGTH + 96U];
    int n = snprintf(payload, sizeof(payload),
                     "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", hostname);
    if (n < 0 || n >= (int)sizeof(payload)) { err = ESP_ERR_INVALID_SIZE; goto cleanup; }

    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) { err = ESP_ERR_NO_MEM; goto cleanup; }
    int status = 0;
    err = signed_request(directory.new_nonce_url, directory.new_order_url, kid, payload,
                         private_key, response, &status);
    out->new_order_http_status = status;
    if (err != ESP_OK) { free(response); goto cleanup; }
    if (status != 201 || !is_https_url(response->location) ||
        !extract_json_string(response->data, "finalize", out->finalize_url, sizeof(out->finalize_url)) ||
        !extract_first_array_string(response->data, "authorizations", out->authorization_url,
                                    sizeof(out->authorization_url))) {
        memset(response, 0, sizeof(*response)); free(response); err = ESP_ERR_INVALID_RESPONSE; goto cleanup;
    }
    snprintf(out->order_url, sizeof(out->order_url), "%s", response->location);
    memset(response, 0, sizeof(*response));

    status = 0;
    err = signed_request(directory.new_nonce_url, out->authorization_url, kid, "",
                         private_key, response, &status);
    out->authorization_http_status = status;
    if (err != ESP_OK) { free(response); goto cleanup; }
    char auth_identifier[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (status != 200 ||
        !extract_dns01_challenge(response->data, out->challenge_url, sizeof(out->challenge_url),
                                 out->challenge_token, sizeof(out->challenge_token),
                                 out->challenge_status, sizeof(out->challenge_status)) ||
        !extract_json_string(response->data, "value", auth_identifier, sizeof(auth_identifier)) ||
        strcmp(auth_identifier, hostname) != 0 || !is_https_url(out->challenge_url)) {
        memset(response, 0, sizeof(*response)); free(response); err = ESP_ERR_INVALID_RESPONSE; goto cleanup;
    }
    memset(response, 0, sizeof(*response)); free(response);

    char jwk[ACME_JWK_MAX];
    char thumbprint[ACME_THUMBPRINT_LENGTH];
    err = build_jwk_and_thumbprint(private_key, jwk, sizeof(jwk), thumbprint);
    memset(jwk, 0, sizeof(jwk));
    if (err != ESP_OK) goto cleanup;
    char key_authorization[ACME_CHALLENGE_TOKEN_MAX_LENGTH + ACME_THUMBPRINT_LENGTH + 2U];
    n = snprintf(key_authorization, sizeof(key_authorization), "%s.%s",
                 out->challenge_token, thumbprint);
    memset(thumbprint, 0, sizeof(thumbprint));
    if (n < 0 || n >= (int)sizeof(key_authorization)) { err = ESP_ERR_INVALID_SIZE; goto cleanup; }
    uint8_t digest[32];
    err = sha256_bytes(key_authorization, strlen(key_authorization), digest);
    memset(key_authorization, 0, sizeof(key_authorization));
    if (err == ESP_OK) err = base64url(digest, sizeof(digest), out->dns01_value, sizeof(out->dns01_value));
    memset(digest, 0, sizeof(digest));
    if (err != ESP_OK) goto cleanup;

    n = snprintf(out->dns01_record_name, sizeof(out->dns01_record_name),
                 "_acme-challenge.%s", hostname);
    if (n < 0 || n >= (int)sizeof(out->dns01_record_name)) { err = ESP_ERR_INVALID_SIZE; goto cleanup; }
    out->discovered = true;
    ESP_LOGI(TAG, "%s ACME order discovered for %s; challenge not triggered", production ? "Production" : "Staging", hostname);

cleanup:
    memset(private_key, 0, sizeof(private_key));
    memset(kid, 0, sizeof(kid));
    return err;
}

static esp_err_t parse_authorization_status(const char *json,
                                                char *authorization_status,
                                                size_t authorization_status_size,
                                                char *challenge_status,
                                                size_t challenge_status_size)
{
    if (!extract_json_string(json, "status", authorization_status,
                             authorization_status_size)) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    char unused_url[ACME_URL_MAX_LENGTH];
    char unused_token[ACME_CHALLENGE_TOKEN_MAX_LENGTH + 1U];
    if (!extract_dns01_challenge(json, unused_url, sizeof(unused_url),
                                 unused_token, sizeof(unused_token),
                                 challenge_status, challenge_status_size)) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    memset(unused_token, 0, sizeof(unused_token));
    return ESP_OK;
}

static esp_err_t validate_dns01_sync(bool production, const acme_order_discovery_t *order,
                                     acme_challenge_validation_t *out)
{
    if (order == NULL || out == NULL || !order->discovered ||
        !is_https_url(order->challenge_url) || !is_https_url(order->authorization_url)) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    uint8_t private_key[32];
    err = acme_storage_load_private_key(private_key);
    if (err != ESP_OK) return err;
    char kid[ACME_URL_MAX_LENGTH];
    err = production ? load_production_account_url(kid, sizeof(kid)) : acme_storage_load_account_url(kid, sizeof(kid));
    if (err != ESP_OK || !is_https_url(kid)) {
        memset(private_key, 0, sizeof(private_key));
        return ESP_ERR_INVALID_STATE;
    }

    acme_directory_status_t directory;
    err = production ? probe_production_sync(&directory) : probe_staging_sync(&directory);
    if (err != ESP_OK) goto cleanup;

    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) { err = ESP_ERR_NO_MEM; goto cleanup; }

    int status = 0;
    err = signed_request(directory.new_nonce_url, order->challenge_url, kid, "{}",
                         private_key, response, &status);
    out->trigger_http_status = status;
    if (err != ESP_OK || (status != 200 && status != 202)) {
        if (err == ESP_OK) err = ESP_ERR_INVALID_RESPONSE;
        memset(response, 0, sizeof(*response)); free(response); goto cleanup;
    }
    out->triggered = true;

    /* Controlled propagation delay occurs before this function is called. */
    for (unsigned attempt = 1U; attempt <= 30U; ++attempt) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        memset(response, 0, sizeof(*response));
        status = 0;
        err = signed_request(directory.new_nonce_url, order->authorization_url, kid, "",
                             private_key, response, &status);
        out->poll_http_status = status;
        out->poll_count = attempt;
        if (err != ESP_OK || status != 200) {
            if (err == ESP_OK) err = ESP_ERR_INVALID_RESPONSE;
            break;
        }
        err = parse_authorization_status(response->data,
                                         out->authorization_status,
                                         sizeof(out->authorization_status),
                                         out->challenge_status,
                                         sizeof(out->challenge_status));
        if (err != ESP_OK) break;
        if (strcmp(out->authorization_status, "valid") == 0) {
            out->valid = true;
            err = ESP_OK;
            break;
        }
        if (strcmp(out->authorization_status, "invalid") == 0 ||
            strcmp(out->challenge_status, "invalid") == 0) {
            err = ESP_ERR_INVALID_RESPONSE;
            break;
        }
        err = ESP_ERR_TIMEOUT;
    }
    memset(response, 0, sizeof(*response));
    free(response);

cleanup:
    memset(private_key, 0, sizeof(private_key));
    memset(kid, 0, sizeof(kid));
    return err;
}


#define ACME_CERT_KEY_NVS_KEY "cert_key"
#define ACME_CERT_PEM_NVS_KEY "cert_pem"
#define ACME_CERT_HOST_NVS_KEY "cert_host"
#define ACME_PROD_CERT_KEY_NVS_KEY "pcert_key"
#define ACME_PROD_CERT_PEM_NVS_KEY "pcert_pem"
#define ACME_PROD_CERT_HOST_NVS_KEY "pcert_host"
#define ACME_TLS_BOOT_NVS_KEY "tls_prod"
#define ACME_CERT_PRIVATE_KEY_LENGTH 32U
#define ACME_CSR_MAX 1024U

static esp_err_t der_put_length(uint8_t *out, size_t out_size, size_t length, size_t *written)
{
    if (out == NULL || written == NULL) return ESP_ERR_INVALID_ARG;
    if (length < 128U) {
        if (out_size < 1U) return ESP_ERR_INVALID_SIZE;
        out[0] = (uint8_t)length; *written = 1U; return ESP_OK;
    }
    if (length <= 255U) {
        if (out_size < 2U) return ESP_ERR_INVALID_SIZE;
        out[0] = 0x81U; out[1] = (uint8_t)length; *written = 2U; return ESP_OK;
    }
    if (length <= 65535U) {
        if (out_size < 3U) return ESP_ERR_INVALID_SIZE;
        out[0] = 0x82U; out[1] = (uint8_t)(length >> 8); out[2] = (uint8_t)length;
        *written = 3U; return ESP_OK;
    }
    return ESP_ERR_INVALID_SIZE;
}

static esp_err_t der_wrap(uint8_t tag, const uint8_t *content, size_t content_len,
                          uint8_t *out, size_t out_size, size_t *out_len)
{
    if (out == NULL || out_len == NULL || (content_len != 0U && content == NULL)) return ESP_ERR_INVALID_ARG;
    size_t ll = 0U;
    if (out_size < 2U) return ESP_ERR_INVALID_SIZE;
    out[0] = tag;
    esp_err_t err = der_put_length(out + 1U, out_size - 1U, content_len, &ll);
    if (err != ESP_OK || 1U + ll + content_len > out_size) return ESP_ERR_INVALID_SIZE;
    if (content_len != 0U) memcpy(out + 1U + ll, content, content_len);
    *out_len = 1U + ll + content_len;
    return ESP_OK;
}

static esp_err_t der_concat2(const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                             uint8_t *out, size_t out_size, size_t *out_len)
{
    if (al + bl > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, a, al); memcpy(out + al, b, bl); *out_len = al + bl; return ESP_OK;
}

static esp_err_t der_concat3(const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                             const uint8_t *c, size_t cl, uint8_t *out, size_t out_size,
                             size_t *out_len)
{
    if (al + bl + cl > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, a, al); memcpy(out + al, b, bl); memcpy(out + al + bl, c, cl);
    *out_len = al + bl + cl; return ESP_OK;
}

static esp_err_t ecdsa_raw_to_der(const uint8_t raw[64], uint8_t *out, size_t out_size, size_t *out_len)
{
    uint8_t ints[80]; size_t used = 0U;
    for (unsigned part = 0U; part < 2U; ++part) {
        const uint8_t *v = raw + part * 32U;
        size_t off = 0U;
        while (off < 31U && v[off] == 0U) ++off;
        const size_t n = 32U - off;
        const bool lead_zero = (v[off] & 0x80U) != 0U;
        const size_t ilen = n + (lead_zero ? 1U : 0U);
        if (used + 2U + ilen > sizeof(ints) || ilen >= 128U) return ESP_ERR_INVALID_SIZE;
        ints[used++] = 0x02U; ints[used++] = (uint8_t)ilen;
        if (lead_zero) ints[used++] = 0U;
        memcpy(ints + used, v + off, n); used += n;
    }
    return der_wrap(0x30U, ints, used, out, out_size, out_len);
}

static esp_err_t generate_certificate_key(uint8_t private_key[32], uint8_t public_key[65])
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256U);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_key_id_t key_id = 0;
    psa_status_t ps = psa_generate_key(&attributes, &key_id);
    psa_reset_key_attributes(&attributes);
    if (ps != PSA_SUCCESS) return ESP_FAIL;
    size_t private_len = 0U, public_len = 0U;
    ps = psa_export_key(key_id, private_key, 32U, &private_len);
    if (ps == PSA_SUCCESS) ps = psa_export_public_key(key_id, public_key, 65U, &public_len);
    (void)psa_destroy_key(key_id);
    if (ps != PSA_SUCCESS || private_len != 32U || public_len != 65U || public_key[0] != 0x04U) {
        memset(private_key, 0, 32U); memset(public_key, 0, 65U); return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t build_csr_der(const char *hostname, const uint8_t private_key[32],
                               const uint8_t public_key[65], uint8_t *out,
                               size_t out_size, size_t *out_len)
{
    if (!dns_name_is_valid(hostname) || private_key == NULL || public_key == NULL ||
        out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;
    /* Fixed DER OIDs. */
    static const uint8_t oid_cn[] = {0x06,0x03,0x55,0x04,0x03};
    static const uint8_t oid_ec_pub[] = {0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01};
    static const uint8_t oid_p256[] = {0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
    static const uint8_t oid_ext_req[] = {0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0E};
    static const uint8_t oid_san[] = {0x06,0x03,0x55,0x1D,0x11};
    static const uint8_t oid_ecdsa_sha256[] = {0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
    uint8_t a[1024], b[1024], c[1024], d[1024]; size_t al, bl, cl, dl;

    /* subject: CN=hostname */
    esp_err_t err = der_wrap(0x0CU, (const uint8_t *)hostname, strlen(hostname), a, sizeof(a), &al);
    if (err != ESP_OK) return err;
    err = der_concat2(oid_cn, sizeof(oid_cn), a, al, b, sizeof(b), &bl);
    if (err == ESP_OK) err = der_wrap(0x30U, b, bl, a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x31U, a, al, b, sizeof(b), &bl);
    if (err == ESP_OK) err = der_wrap(0x30U, b, bl, c, sizeof(c), &cl);
    if (err != ESP_OK) return err;
    uint8_t subject[512]; size_t subject_len = cl; memcpy(subject, c, cl);

    /* SubjectPublicKeyInfo */
    err = der_concat2(oid_ec_pub, sizeof(oid_ec_pub), oid_p256, sizeof(oid_p256), a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x30U, a, al, b, sizeof(b), &bl);
    uint8_t bitpub[66]; bitpub[0] = 0U; memcpy(bitpub + 1U, public_key, 65U);
    if (err == ESP_OK) err = der_wrap(0x03U, bitpub, sizeof(bitpub), c, sizeof(c), &cl);
    if (err == ESP_OK) err = der_concat2(b, bl, c, cl, a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x30U, a, al, d, sizeof(d), &dl);
    if (err != ESP_OK) return err;
    uint8_t spki[256]; size_t spki_len = dl; memcpy(spki, d, dl);

    /* extensionRequest -> subjectAltName dNSName */
    err = der_wrap(0x82U, (const uint8_t *)hostname, strlen(hostname), a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x30U, a, al, b, sizeof(b), &bl); /* GeneralNames */
    if (err == ESP_OK) err = der_wrap(0x04U, b, bl, c, sizeof(c), &cl); /* extnValue */
    if (err == ESP_OK) err = der_concat2(oid_san, sizeof(oid_san), c, cl, a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x30U, a, al, b, sizeof(b), &bl); /* Extension */
    if (err == ESP_OK) err = der_wrap(0x30U, b, bl, c, sizeof(c), &cl); /* Extensions */
    if (err == ESP_OK) err = der_wrap(0x31U, c, cl, d, sizeof(d), &dl); /* SET */
    if (err == ESP_OK) err = der_concat2(oid_ext_req, sizeof(oid_ext_req), d, dl, a, sizeof(a), &al);
    if (err == ESP_OK) err = der_wrap(0x30U, a, al, b, sizeof(b), &bl); /* Attribute */
    if (err == ESP_OK) err = der_wrap(0xA0U, b, bl, c, sizeof(c), &cl); /* attributes [0] */
    if (err != ESP_OK) return err;
    uint8_t attrs[512]; size_t attrs_len = cl; memcpy(attrs, c, cl);

    static const uint8_t version0[] = {0x02,0x01,0x00};
    err = der_concat3(version0, sizeof(version0), subject, subject_len, spki, spki_len,
                      a, sizeof(a), &al);
    if (err == ESP_OK) err = der_concat2(a, al, attrs, attrs_len, b, sizeof(b), &bl);
    if (err == ESP_OK) err = der_wrap(0x30U, b, bl, c, sizeof(c), &cl); /* CRI */
    if (err != ESP_OK) return err;

    uint8_t digest[32], raw_sig[64], der_sig[80]; size_t der_sig_len = 0U;
    err = sha256_bytes(c, cl, digest);
    if (err == ESP_OK) err = sign_es256(private_key, digest, raw_sig);
    memset(digest, 0, sizeof(digest));
    if (err == ESP_OK) err = ecdsa_raw_to_der(raw_sig, der_sig, sizeof(der_sig), &der_sig_len);
    memset(raw_sig, 0, sizeof(raw_sig));
    if (err != ESP_OK) return err;

    err = der_wrap(0x30U, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256), a, sizeof(a), &al);
    uint8_t sigbits[81];
    if (der_sig_len + 1U > sizeof(sigbits)) return ESP_ERR_INVALID_SIZE;
    sigbits[0] = 0U; memcpy(sigbits + 1U, der_sig, der_sig_len);
    if (err == ESP_OK) err = der_wrap(0x03U, sigbits, der_sig_len + 1U, b, sizeof(b), &bl);
    if (err == ESP_OK) err = der_concat3(c, cl, a, al, b, bl, d, sizeof(d), &dl);
    if (err == ESP_OK) err = der_wrap(0x30U, d, dl, out, out_size, out_len);
    memset(der_sig, 0, sizeof(der_sig));
    return err;
}

static esp_err_t validate_certificate_material(const char *hostname, const uint8_t private_key[32], const char *pem, size_t pem_len);

static esp_err_t store_certificate_material(bool production, const char *hostname,
                                            const uint8_t private_key[32],
                                            const char *pem, size_t pem_len)
{
    if (!dns_name_is_valid(hostname) || private_key == NULL || pem == NULL || pem_len == 0U) return ESP_ERR_INVALID_ARG;
    esp_err_t err = validate_certificate_material(hostname, private_key, pem, pem_len);
    if (err != ESP_OK) return err;
    err = acme_storage_init();
    if (err != ESP_OK) return err;
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    const char *key_name = production ? ACME_PROD_CERT_KEY_NVS_KEY : ACME_CERT_KEY_NVS_KEY;
    const char *pem_name = production ? ACME_PROD_CERT_PEM_NVS_KEY : ACME_CERT_PEM_NVS_KEY;
    const char *host_name = production ? ACME_PROD_CERT_HOST_NVS_KEY : ACME_CERT_HOST_NVS_KEY;
    err = nvs_set_blob(handle, key_name, private_key, 32U);
    if (err == ESP_OK) err = nvs_set_blob(handle, pem_name, pem, pem_len + 1U);
    if (err == ESP_OK) err = nvs_set_str(handle, host_name, hostname);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}



static bool der_contains_dns_san(const unsigned char *der, size_t der_len, const char *hostname)
{
    if (der == NULL || hostname == NULL) return false;
    const size_t host_len = strlen(hostname);
    if (host_len == 0U || host_len > 127U || der_len < host_len + 2U) return false;
    for (size_t i = 0U; i + 2U + host_len <= der_len; ++i) {
        if (der[i] == 0x82U && der[i + 1U] == (unsigned char)host_len &&
            memcmp(der + i + 2U, hostname, host_len) == 0) return true;
    }
    return false;
}

static bool bytes_contain(const unsigned char *haystack, size_t haystack_len,
                          const unsigned char *needle, size_t needle_len)
{
    if (haystack == NULL || needle == NULL || needle_len == 0U || haystack_len < needle_len) return false;
    for (size_t i = 0U; i + needle_len <= haystack_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return true;
    }
    return false;
}

static esp_err_t validate_certificate_material(const char *hostname, const uint8_t private_key[32],
                                               const char *pem, size_t pem_len)
{
    if (!dns_name_is_valid(hostname) || private_key == NULL || pem == NULL || pem_len < 64U)
        return ESP_ERR_INVALID_ARG;
    mbedtls_x509_crt chain; mbedtls_x509_crt_init(&chain);
    const int rc = mbedtls_x509_crt_parse(&chain, (const unsigned char *)pem, pem_len + 1U);
    if (rc != 0 || chain.raw.p == NULL || chain.raw.len == 0U) { mbedtls_x509_crt_free(&chain); return ESP_ERR_INVALID_RESPONSE; }
    if (!der_contains_dns_san(chain.raw.p, chain.raw.len, hostname)) { mbedtls_x509_crt_free(&chain); return ESP_ERR_INVALID_RESPONSE; }
    psa_key_id_t key_id = 0;
    esp_err_t err = import_account_key(private_key, PSA_KEY_USAGE_EXPORT, &key_id);
    if (err != ESP_OK) { mbedtls_x509_crt_free(&chain); return err; }
    uint8_t public_key[65]; size_t public_len = 0U;
    const psa_status_t ps = psa_export_public_key(key_id, public_key, sizeof(public_key), &public_len);
    (void)psa_destroy_key(key_id);
    const bool match = ps == PSA_SUCCESS && public_len == sizeof(public_key) && public_key[0] == 0x04U &&
                       bytes_contain(chain.raw.p, chain.raw.len, public_key, sizeof(public_key));
    memset(public_key,0,sizeof(public_key)); mbedtls_x509_crt_free(&chain);
    return match ? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}

static void fingerprint_hex(const uint8_t digest[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < 32U; ++i) {
        out[i * 2U] = hex[digest[i] >> 4];
        out[i * 2U + 1U] = hex[digest[i] & 0x0FU];
    }
    out[64] = '\0';
}

esp_err_t acme_client_inspect_stored_certificate(acme_certificate_inspection_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;

    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;

    size_t key_len = 0U, pem_len = 0U, host_len = 0U;
    esp_err_t key_err = nvs_get_blob(handle, ACME_CERT_KEY_NVS_KEY, NULL, &key_len);
    esp_err_t pem_err = nvs_get_blob(handle, ACME_CERT_PEM_NVS_KEY, NULL, &pem_len);
    esp_err_t host_err = nvs_get_str(handle, ACME_CERT_HOST_NVS_KEY, NULL, &host_len);
    if (key_err == ESP_ERR_NVS_NOT_FOUND || pem_err == ESP_ERR_NVS_NOT_FOUND ||
        host_err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return ESP_ERR_NOT_FOUND;
    }
    if (key_err != ESP_OK || pem_err != ESP_OK || host_err != ESP_OK ||
        key_len != ACME_CERT_PRIVATE_KEY_LENGTH || pem_len < 64U || pem_len > ACME_RESPONSE_MAX ||
        host_len < 2U || host_len > ACME_DNS_NAME_MAX_LENGTH + 1U) {
        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t private_key[ACME_CERT_PRIVATE_KEY_LENGTH];
    char *pem = calloc(1U, pem_len + 1U);
    if (pem == NULL) { nvs_close(handle); return ESP_ERR_NO_MEM; }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    size_t read_key_len = sizeof(private_key), read_pem_len = pem_len, read_host_len = sizeof(hostname);
    err = nvs_get_blob(handle, ACME_CERT_KEY_NVS_KEY, private_key, &read_key_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, ACME_CERT_PEM_NVS_KEY, pem, &read_pem_len);
    if (err == ESP_OK) err = nvs_get_str(handle, ACME_CERT_HOST_NVS_KEY, hostname, &read_host_len);
    nvs_close(handle);
    if (err != ESP_OK) goto cleanup;
    pem[pem_len] = '\0';

    out_status->key_present = true;
    out_status->certificate_present = true;
    out_status->hostname_present = true;
    out_status->certificate_pem_length = pem_len > 0U && pem[pem_len - 1U] == '\0' ? pem_len - 1U : pem_len;
    snprintf(out_status->hostname, sizeof(out_status->hostname), "%s", hostname);

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    const int parse_rc = mbedtls_x509_crt_parse(&chain, (const unsigned char *)pem, pem_len);
    if (parse_rc != 0) {
        mbedtls_x509_crt_free(&chain);
        err = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }
    out_status->certificate_parse_valid = true;

    unsigned count = 0U;
    for (const mbedtls_x509_crt *crt = &chain; crt != NULL && crt->raw.p != NULL; crt = crt->next) ++count;
    out_status->chain_certificate_count = count;

    out_status->hostname_matches_certificate =
        der_contains_dns_san(chain.raw.p, chain.raw.len, hostname);

    uint8_t digest[32];
    err = sha256_bytes(chain.raw.p, chain.raw.len, digest);
    if (err == ESP_OK) fingerprint_hex(digest, out_status->leaf_sha256);
    memset(digest, 0, sizeof(digest));
    if (err != ESP_OK) { mbedtls_x509_crt_free(&chain); goto cleanup; }

    snprintf(out_status->valid_from, sizeof(out_status->valid_from),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             chain.valid_from.year, chain.valid_from.mon, chain.valid_from.day,
             chain.valid_from.hour, chain.valid_from.min, chain.valid_from.sec);
    snprintf(out_status->valid_to, sizeof(out_status->valid_to),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             chain.valid_to.year, chain.valid_to.mon, chain.valid_to.day,
             chain.valid_to.hour, chain.valid_to.min, chain.valid_to.sec);

    psa_key_id_t key_id = 0;
    err = import_account_key(private_key, PSA_KEY_USAGE_EXPORT, &key_id);
    if (err == ESP_OK) {
        uint8_t public_key[65]; size_t public_len = 0U;
        const psa_status_t ps = psa_export_public_key(key_id, public_key, sizeof(public_key), &public_len);
        (void)psa_destroy_key(key_id);
        if (ps == PSA_SUCCESS && public_len == sizeof(public_key) && public_key[0] == 0x04U) {
            out_status->private_key_matches_certificate =
                bytes_contain(chain.raw.p, chain.raw.len, public_key, sizeof(public_key));
        } else {
            err = ESP_FAIL;
        }
        memset(public_key, 0, sizeof(public_key));
    }
    mbedtls_x509_crt_free(&chain);
    if (err == ESP_OK && (!out_status->hostname_matches_certificate ||
                          !out_status->private_key_matches_certificate)) {
        err = ESP_ERR_INVALID_STATE;
    }

cleanup:
    memset(private_key, 0, sizeof(private_key));
    if (pem != NULL) { memset(pem, 0, pem_len + 1U); free(pem); }
    return err;
}

esp_err_t acme_client_inspect_stored_production_certificate(acme_certificate_inspection_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;

    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;

    size_t key_len = 0U, pem_len = 0U, host_len = 0U;
    esp_err_t key_err = nvs_get_blob(handle, ACME_PROD_CERT_KEY_NVS_KEY, NULL, &key_len);
    esp_err_t pem_err = nvs_get_blob(handle, ACME_PROD_CERT_PEM_NVS_KEY, NULL, &pem_len);
    esp_err_t host_err = nvs_get_str(handle, ACME_PROD_CERT_HOST_NVS_KEY, NULL, &host_len);
    if (key_err == ESP_ERR_NVS_NOT_FOUND || pem_err == ESP_ERR_NVS_NOT_FOUND ||
        host_err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return ESP_ERR_NOT_FOUND;
    }
    if (key_err != ESP_OK || pem_err != ESP_OK || host_err != ESP_OK ||
        key_len != ACME_CERT_PRIVATE_KEY_LENGTH || pem_len < 64U || pem_len > ACME_RESPONSE_MAX ||
        host_len < 2U || host_len > ACME_DNS_NAME_MAX_LENGTH + 1U) {
        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t private_key[ACME_CERT_PRIVATE_KEY_LENGTH];
    char *pem = calloc(1U, pem_len + 1U);
    if (pem == NULL) { nvs_close(handle); return ESP_ERR_NO_MEM; }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    size_t read_key_len = sizeof(private_key), read_pem_len = pem_len, read_host_len = sizeof(hostname);
    err = nvs_get_blob(handle, ACME_PROD_CERT_KEY_NVS_KEY, private_key, &read_key_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, ACME_PROD_CERT_PEM_NVS_KEY, pem, &read_pem_len);
    if (err == ESP_OK) err = nvs_get_str(handle, ACME_PROD_CERT_HOST_NVS_KEY, hostname, &read_host_len);
    nvs_close(handle);
    if (err != ESP_OK) goto cleanup;
    pem[pem_len] = '\0';

    out_status->key_present = true;
    out_status->certificate_present = true;
    out_status->hostname_present = true;
    out_status->certificate_pem_length = pem_len > 0U && pem[pem_len - 1U] == '\0' ? pem_len - 1U : pem_len;
    snprintf(out_status->hostname, sizeof(out_status->hostname), "%s", hostname);

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    const int parse_rc = mbedtls_x509_crt_parse(&chain, (const unsigned char *)pem, pem_len);
    if (parse_rc != 0) {
        mbedtls_x509_crt_free(&chain);
        err = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }
    out_status->certificate_parse_valid = true;

    unsigned count = 0U;
    for (const mbedtls_x509_crt *crt = &chain; crt != NULL && crt->raw.p != NULL; crt = crt->next) ++count;
    out_status->chain_certificate_count = count;

    out_status->hostname_matches_certificate =
        der_contains_dns_san(chain.raw.p, chain.raw.len, hostname);

    uint8_t digest[32];
    err = sha256_bytes(chain.raw.p, chain.raw.len, digest);
    if (err == ESP_OK) fingerprint_hex(digest, out_status->leaf_sha256);
    memset(digest, 0, sizeof(digest));
    if (err != ESP_OK) { mbedtls_x509_crt_free(&chain); goto cleanup; }

    snprintf(out_status->valid_from, sizeof(out_status->valid_from),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             chain.valid_from.year, chain.valid_from.mon, chain.valid_from.day,
             chain.valid_from.hour, chain.valid_from.min, chain.valid_from.sec);
    snprintf(out_status->valid_to, sizeof(out_status->valid_to),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             chain.valid_to.year, chain.valid_to.mon, chain.valid_to.day,
             chain.valid_to.hour, chain.valid_to.min, chain.valid_to.sec);

    psa_key_id_t key_id = 0;
    err = import_account_key(private_key, PSA_KEY_USAGE_EXPORT, &key_id);
    if (err == ESP_OK) {
        uint8_t public_key[65]; size_t public_len = 0U;
        const psa_status_t ps = psa_export_public_key(key_id, public_key, sizeof(public_key), &public_len);
        (void)psa_destroy_key(key_id);
        if (ps == PSA_SUCCESS && public_len == sizeof(public_key) && public_key[0] == 0x04U) {
            out_status->private_key_matches_certificate =
                bytes_contain(chain.raw.p, chain.raw.len, public_key, sizeof(public_key));
        } else {
            err = ESP_FAIL;
        }
        memset(public_key, 0, sizeof(public_key));
    }
    mbedtls_x509_crt_free(&chain);
    if (err == ESP_OK && (!out_status->hostname_matches_certificate ||
                          !out_status->private_key_matches_certificate)) {
        err = ESP_ERR_INVALID_STATE;
    }

cleanup:
    memset(private_key, 0, sizeof(private_key));
    if (pem != NULL) { memset(pem, 0, pem_len + 1U); free(pem); }
    return err;
}

static const char s_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static esp_err_t pem_encode_ec_private_key(const uint8_t private_key[32],
                                           char **out_pem,
                                           size_t *out_length)
{
    if (private_key == NULL || out_pem == NULL || out_length == NULL) return ESP_ERR_INVALID_ARG;
    *out_pem = NULL; *out_length = 0U;

    uint8_t der[51] = {
        0x30,0x31,0x02,0x01,0x01,0x04,0x20,
        /* 32-byte private scalar follows */
    };
    memcpy(der + 7U, private_key, 32U);
    static const uint8_t suffix[] = {0xA0,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
    memcpy(der + 39U, suffix, sizeof(suffix));

    char b64[69];
    size_t o = 0U;
    for (size_t i = 0U; i < sizeof(der); i += 3U) {
        const uint32_t a = der[i];
        const uint32_t b = i + 1U < sizeof(der) ? der[i + 1U] : 0U;
        const uint32_t c = i + 2U < sizeof(der) ? der[i + 2U] : 0U;
        const uint32_t v = (a << 16) | (b << 8) | c;
        b64[o++] = s_b64[(v >> 18) & 63U];
        b64[o++] = s_b64[(v >> 12) & 63U];
        b64[o++] = i + 1U < sizeof(der) ? s_b64[(v >> 6) & 63U] : '=';
        b64[o++] = i + 2U < sizeof(der) ? s_b64[v & 63U] : '=';
    }
    b64[o] = '\0';
    memset(der, 0, sizeof(der));

    const char *begin = "-----BEGIN EC PRIVATE KEY-----\n";
    const char *end = "-----END EC PRIVATE KEY-----\n";
    const size_t total = strlen(begin) + o + 1U + strlen(end) + 1U;
    char *pem = calloc(1U, total);
    if (pem == NULL) { memset(b64,0,sizeof(b64)); return ESP_ERR_NO_MEM; }
    const int n = snprintf(pem, total, "%s%s\n%s", begin, b64, end);
    memset(b64, 0, sizeof(b64));
    if (n < 0 || (size_t)n >= total) { memset(pem,0,total); free(pem); return ESP_ERR_INVALID_SIZE; }
    *out_pem = pem;
    *out_length = (size_t)n + 1U;
    return ESP_OK;
}

void acme_client_free_tls_credentials(acme_tls_credentials_t *credentials)
{
    if (credentials == NULL) return;
    if (credentials->certificate_pem != NULL) {
        memset(credentials->certificate_pem, 0, credentials->certificate_pem_length);
        free(credentials->certificate_pem);
    }
    if (credentials->private_key_pem != NULL) {
        memset(credentials->private_key_pem, 0, credentials->private_key_pem_length);
        free(credentials->private_key_pem);
    }
    memset(credentials, 0, sizeof(*credentials));
}

static esp_err_t load_tls_credentials(bool production, acme_tls_credentials_t *out_credentials)
{
    if (out_credentials == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_credentials, 0, sizeof(*out_credentials));

    acme_certificate_inspection_t inspection;
    esp_err_t err = production ? acme_client_inspect_stored_production_certificate(&inspection)
                               : acme_client_inspect_stored_certificate(&inspection);
    if (err != ESP_OK || !inspection.certificate_parse_valid ||
        !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }

    err = acme_storage_init();
    if (err != ESP_OK) return err;
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;

    const char *key_name = production ? ACME_PROD_CERT_KEY_NVS_KEY : ACME_CERT_KEY_NVS_KEY;
    const char *pem_name = production ? ACME_PROD_CERT_PEM_NVS_KEY : ACME_CERT_PEM_NVS_KEY;
    const char *host_name = production ? ACME_PROD_CERT_HOST_NVS_KEY : ACME_CERT_HOST_NVS_KEY;
    size_t key_len = 0U, pem_len = 0U, host_len = sizeof(out_credentials->hostname);
    err = nvs_get_blob(handle, key_name, NULL, &key_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, pem_name, NULL, &pem_len);
    if (err != ESP_OK || key_len != ACME_CERT_PRIVATE_KEY_LENGTH || pem_len < 64U || pem_len > ACME_RESPONSE_MAX) {
        nvs_close(handle); return err == ESP_OK ? ESP_ERR_INVALID_SIZE : err;
    }

    uint8_t private_key[ACME_CERT_PRIVATE_KEY_LENGTH];
    size_t read_key_len = sizeof(private_key);
    char *certificate = calloc(1U, pem_len + 1U);
    if (certificate == NULL) { nvs_close(handle); return ESP_ERR_NO_MEM; }
    size_t read_pem_len = pem_len;
    err = nvs_get_blob(handle, key_name, private_key, &read_key_len);
    if (err == ESP_OK) err = nvs_get_blob(handle, pem_name, certificate, &read_pem_len);
    if (err == ESP_OK) err = nvs_get_str(handle, host_name, out_credentials->hostname, &host_len);
    nvs_close(handle);
    certificate[pem_len] = '\0';
    if (err != ESP_OK) { memset(private_key,0,sizeof(private_key)); memset(certificate,0,pem_len+1U); free(certificate); return err; }

    char *key_pem = NULL; size_t key_pem_len = 0U;
    err = pem_encode_ec_private_key(private_key, &key_pem, &key_pem_len);
    memset(private_key, 0, sizeof(private_key));
    if (err != ESP_OK) { memset(certificate,0,pem_len+1U); free(certificate); return err; }

    out_credentials->certificate_pem = certificate;
    out_credentials->certificate_pem_length = pem_len;
    out_credentials->private_key_pem = key_pem;
    out_credentials->private_key_pem_length = key_pem_len;
    return ESP_OK;
}

esp_err_t acme_client_load_stored_tls_credentials(acme_tls_credentials_t *out_credentials)
{
    return load_tls_credentials(false, out_credentials);
}

esp_err_t acme_client_load_production_tls_credentials(acme_tls_credentials_t *out_credentials)
{
    return load_tls_credentials(true, out_credentials);
}

esp_err_t acme_client_get_production_boot_selected(bool *out_selected)
{
    if (out_selected == NULL) return ESP_ERR_INVALID_ARG;
    *out_selected = false;
    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;
    uint8_t value = 0U;
    err = nvs_get_u8(handle, ACME_TLS_BOOT_NVS_KEY, &value);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (value > 1U) return ESP_ERR_INVALID_STATE;
    *out_selected = value == 1U;
    return ESP_OK;
}

esp_err_t acme_client_set_production_boot_selected(bool selected)
{
    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    if (selected) {
        acme_certificate_inspection_t inspection;
        err = acme_client_inspect_stored_production_certificate(&inspection);
        if (err != ESP_OK || !inspection.certificate_parse_valid ||
            !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
            return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
        }
    }
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(handle, ACME_TLS_BOOT_NVS_KEY, selected ? 1U : 0U);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

static esp_err_t finalize_order_sync(bool production, const acme_order_discovery_t *order,
                                     acme_certificate_issue_status_t *out)
{
    if (order == NULL || out == NULL || !order->discovered || !is_https_url(order->order_url) ||
        !is_https_url(order->finalize_url) || !dns_name_is_valid(order->identifier)) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    snprintf(out->identifier, sizeof(out->identifier), "%s", order->identifier);

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) return err;
    uint8_t account_key[32];
    err = acme_storage_load_private_key(account_key);
    if (err != ESP_OK) return err;
    char kid[ACME_URL_MAX_LENGTH];
    err = production ? load_production_account_url(kid, sizeof(kid)) : acme_storage_load_account_url(kid, sizeof(kid));
    if (err != ESP_OK || !is_https_url(kid)) { memset(account_key,0,sizeof(account_key)); return ESP_ERR_INVALID_STATE; }

    uint8_t cert_key[32], public_key[65], csr[ACME_CSR_MAX]; size_t csr_len = 0U;
    memset(cert_key,0,sizeof(cert_key)); memset(public_key,0,sizeof(public_key));
    err = generate_certificate_key(cert_key, public_key);
    if (err != ESP_OK) goto cleanup;
    err = build_csr_der(order->identifier, cert_key, public_key, csr, sizeof(csr), &csr_len);
    memset(public_key,0,sizeof(public_key));
    if (err != ESP_OK) goto cleanup;
    char csr64[1536];
    err = base64url(csr, csr_len, csr64, sizeof(csr64));
    memset(csr,0,sizeof(csr));
    if (err != ESP_OK) goto cleanup;

    char payload[1664];
    int n = snprintf(payload, sizeof(payload), "{\"csr\":\"%s\"}", csr64);
    memset(csr64,0,sizeof(csr64));
    if (n < 0 || n >= (int)sizeof(payload)) { err = ESP_ERR_INVALID_SIZE; goto cleanup; }

    acme_directory_status_t directory;
    err = production ? probe_production_sync(&directory) : probe_staging_sync(&directory);
    if (err != ESP_OK) goto cleanup;
    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) { err = ESP_ERR_NO_MEM; goto cleanup; }
    int status = 0;
    err = signed_request(directory.new_nonce_url, order->finalize_url, kid, payload,
                         account_key, response, &status);
    memset(payload,0,sizeof(payload));
    out->finalize_http_status = status;
    if (err != ESP_OK || status != 200) {
        if (err == ESP_OK) err = ESP_ERR_INVALID_RESPONSE;
        goto response_cleanup;
    }
    out->finalized = true;

    err = ESP_ERR_TIMEOUT;
    for (unsigned attempt = 1U; attempt <= 30U; ++attempt) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        memset(response, 0, sizeof(*response)); status = 0;
        esp_err_t poll_err = signed_request(directory.new_nonce_url, order->order_url, kid, "",
                                            account_key, response, &status);
        out->order_poll_http_status = status; out->order_poll_count = attempt;
        if (poll_err != ESP_OK || status != 200 ||
            !extract_json_string(response->data, "status", out->order_status, sizeof(out->order_status))) {
            err = poll_err != ESP_OK ? poll_err : ESP_ERR_INVALID_RESPONSE; break;
        }
        if (strcmp(out->order_status, "valid") == 0) {
            if (!extract_json_string(response->data, "certificate", out->certificate_url,
                                     sizeof(out->certificate_url)) || !is_https_url(out->certificate_url)) {
                err = ESP_ERR_INVALID_RESPONSE;
            } else err = ESP_OK;
            break;
        }
        if (strcmp(out->order_status, "invalid") == 0) { err = ESP_ERR_INVALID_RESPONSE; break; }
    }
    if (err != ESP_OK) goto response_cleanup;

    memset(response, 0, sizeof(*response)); status = 0;
    err = signed_request(directory.new_nonce_url, out->certificate_url, kid, "",
                         account_key, response, &status);
    out->certificate_http_status = status;
    if (err != ESP_OK || status != 200 || response->used == 0U ||
        strstr(response->data, "-----BEGIN CERTIFICATE-----") == NULL) {
        if (err == ESP_OK) err = ESP_ERR_INVALID_RESPONSE;
        goto response_cleanup;
    }
    out->certificate_retrieved = true;
    out->certificate_pem_length = response->used;
    err = store_certificate_material(production, order->identifier, cert_key, response->data, response->used);
    if (err == ESP_OK) {
        out->stored = true;
        ESP_LOGI(TAG, "Stored %s certificate/key for %s in protected nvs_certs", production ? "production" : "staging", order->identifier);
    }

response_cleanup:
    memset(response,0,sizeof(*response)); free(response);
cleanup:
    memset(account_key,0,sizeof(account_key)); memset(cert_key,0,sizeof(cert_key));
    memset(kid,0,sizeof(kid));
    return err;
}

static void acme_worker(void *argument)
{
    acme_worker_context_t *context =
        (acme_worker_context_t *)argument;

    if (context->type == ACME_WORK_PROBE) {
        context->result = probe_staging_sync(&context->directory);
    } else if (context->type == ACME_WORK_PROVISION_ACCOUNT) {
        context->result = provision_account_sync(context->production, &context->account);
    } else if (context->type == ACME_WORK_DISCOVER_ORDER) {
        context->result = discover_order_sync(context->production, context->requested_hostname, &context->order);
    } else if (context->type == ACME_WORK_VALIDATE_DNS01) {
        context->result = validate_dns01_sync(context->production, &context->order, &context->validation);
    } else if (context->type == ACME_WORK_FINALIZE_ORDER) {
        context->result = finalize_order_sync(context->production, &context->order, &context->certificate);
    } else {
        context->result = ESP_ERR_INVALID_ARG;
    }

    xTaskNotifyGive(context->caller);
    vTaskDelete(NULL);
}

static esp_err_t run_worker(acme_worker_context_t *context)
{
    context->caller = xTaskGetCurrentTaskHandle();

    BaseType_t created =
        xTaskCreate(acme_worker, "acme_api",
                    ACME_WORKER_STACK_SIZE,
                    context, ACME_WORKER_PRIORITY, NULL);
    if (created != pdPASS) return ESP_ERR_NO_MEM;

    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return context->result;
}

esp_err_t acme_client_probe_staging(acme_directory_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_PROBE;

    esp_err_t result = run_worker(context);
    *out_status = context->directory;
    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}

esp_err_t acme_client_get_account_status(acme_account_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    return account_status_local(out_status);
}

esp_err_t acme_client_provision_staging_account(acme_account_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_PROVISION_ACCOUNT;

    esp_err_t result = run_worker(context);
    *out_status = context->account;
    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}


esp_err_t acme_client_discover_staging_order(const char *hostname,
                                             acme_order_discovery_t *out_status)
{
    if (hostname == NULL || out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    if (!dns_name_is_valid(hostname)) return ESP_ERR_INVALID_ARG;

    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_DISCOVER_ORDER;
    snprintf(context->requested_hostname, sizeof(context->requested_hostname), "%s", hostname);
    esp_err_t result = run_worker(context);
    *out_status = context->order;
    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}


esp_err_t acme_client_validate_staging_dns01(const acme_order_discovery_t *order,
                                             acme_challenge_validation_t *out_status)
{
    if (order == NULL || out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_VALIDATE_DNS01;
    context->order = *order;
    esp_err_t result = run_worker(context);
    *out_status = context->validation;
    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}


esp_err_t acme_client_finalize_staging_order(const acme_order_discovery_t *order,
                                             acme_certificate_issue_status_t *out_status)
{
    if (order == NULL || out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_FINALIZE_ORDER;
    context->order = *order;
    esp_err_t result = run_worker(context);
    *out_status = context->certificate;
    memset(context, 0, sizeof(*context));
    free(context);
    return result;
}


esp_err_t acme_client_provision_production_account(acme_account_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    acme_worker_context_t *context = calloc(1U, sizeof(*context));
    if (context == NULL) return ESP_ERR_NO_MEM;
    context->type = ACME_WORK_PROVISION_ACCOUNT; context->production = true;
    esp_err_t result = run_worker(context); *out_status = context->account;
    memset(context,0,sizeof(*context)); free(context); return result;
}

esp_err_t acme_client_discover_production_order(const char *hostname, acme_order_discovery_t *out_status)
{
    if (hostname == NULL || out_status == NULL || !dns_name_is_valid(hostname)) return ESP_ERR_INVALID_ARG;
    memset(out_status,0,sizeof(*out_status));
    acme_worker_context_t *context=calloc(1U,sizeof(*context)); if (!context) return ESP_ERR_NO_MEM;
    context->type=ACME_WORK_DISCOVER_ORDER; context->production=true;
    snprintf(context->requested_hostname,sizeof(context->requested_hostname),"%s",hostname);
    esp_err_t result=run_worker(context); *out_status=context->order; memset(context,0,sizeof(*context)); free(context); return result;
}

esp_err_t acme_client_validate_production_dns01(const acme_order_discovery_t *order, acme_challenge_validation_t *out_status)
{
    if (order == NULL || out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    acme_worker_context_t *context=calloc(1U,sizeof(*context)); if (!context) return ESP_ERR_NO_MEM;
    context->type=ACME_WORK_VALIDATE_DNS01; context->production=true; context->order=*order;
    esp_err_t result=run_worker(context); *out_status=context->validation; memset(context,0,sizeof(*context)); free(context); return result;
}

esp_err_t acme_client_finalize_production_order(const acme_order_discovery_t *order, acme_certificate_issue_status_t *out_status)
{
    if (order == NULL || out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));
    acme_worker_context_t *context=calloc(1U,sizeof(*context)); if (!context) return ESP_ERR_NO_MEM;
    context->type=ACME_WORK_FINALIZE_ORDER; context->production=true; context->order=*order;
    esp_err_t result=run_worker(context); *out_status=context->certificate; memset(context,0,sizeof(*context)); free(context); return result;
}
