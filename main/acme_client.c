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
#include "psa/crypto.h"

static const char *TAG = "ACME";

#define ACME_STAGING_DIRECTORY_URL \
    "https://acme-staging-v02.api.letsencrypt.org/directory"

#define ACME_RESPONSE_MAX       8192U
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
} acme_work_type_t;

typedef struct {
    TaskHandle_t caller;
    acme_work_type_t type;
    acme_directory_status_t directory;
    acme_account_status_t account;
    acme_order_discovery_t order;
    acme_challenge_validation_t validation;
    char requested_hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
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

static esp_err_t probe_staging_sync(acme_directory_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_status, 0, sizeof(*out_status));

    acme_response_buffer_t *response = calloc(1U, sizeof(*response));
    if (response == NULL) return ESP_ERR_NO_MEM;

    esp_http_client_config_t config = {
        .url = ACME_STAGING_DIRECTORY_URL,
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

static esp_err_t provision_account_sync(acme_account_status_t *out_status)
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
    err = acme_storage_load_account_url(existing_url,
                                        sizeof(existing_url));
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
    err = probe_staging_sync(&directory);
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
        err = acme_storage_store_account_url(response->location);
        if (err == ESP_OK) {
            out_status->registered = true;
            snprintf(out_status->account_url,
                     sizeof(out_status->account_url),
                     "%s", response->location);
            ESP_LOGI(TAG,
                     "Let's Encrypt staging ACME account registered/recovered");
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

static esp_err_t discover_order_sync(const char *hostname, acme_order_discovery_t *out)
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
    err = acme_storage_load_account_url(kid, sizeof(kid));
    if (err != ESP_OK || !is_https_url(kid)) { memset(private_key, 0, sizeof(private_key)); return ESP_ERR_INVALID_STATE; }

    acme_directory_status_t directory;
    err = probe_staging_sync(&directory);
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
    ESP_LOGI(TAG, "Staging ACME order discovered for %s; challenge not triggered", hostname);

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

static esp_err_t validate_dns01_sync(const acme_order_discovery_t *order,
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
    err = acme_storage_load_account_url(kid, sizeof(kid));
    if (err != ESP_OK || !is_https_url(kid)) {
        memset(private_key, 0, sizeof(private_key));
        return ESP_ERR_INVALID_STATE;
    }

    acme_directory_status_t directory;
    err = probe_staging_sync(&directory);
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

static void acme_worker(void *argument)
{
    acme_worker_context_t *context =
        (acme_worker_context_t *)argument;

    if (context->type == ACME_WORK_PROBE) {
        context->result = probe_staging_sync(&context->directory);
    } else if (context->type == ACME_WORK_PROVISION_ACCOUNT) {
        context->result = provision_account_sync(&context->account);
    } else if (context->type == ACME_WORK_DISCOVER_ORDER) {
        context->result = discover_order_sync(context->requested_hostname, &context->order);
    } else if (context->type == ACME_WORK_VALIDATE_DNS01) {
        context->result = validate_dns01_sync(&context->order, &context->validation);
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
