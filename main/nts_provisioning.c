#include "nts_provisioning.h"

#include <string.h>

#include "app_state.h"
#include "key_store.h"
#include "ntp_types.h"

#include "esp_random.h"
#include "nvs.h"

#include "psa/crypto.h"

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

#define NTS_COOKIE_KEY_VALIDITY_SECONDS \
    (30ULL * 24ULL * 3600ULL)

static bool contains_text(
    const uint8_t *buffer,
    size_t buffer_len,
    const char *text)
{
    if (buffer == NULL ||
        text == NULL ||
        buffer_len == 0U) {
        return false;
    }

    size_t text_len = strlen(text);

    if (text_len == 0U ||
        text_len > buffer_len) {
        return false;
    }

    for (size_t i = 0U;
         i <= buffer_len - text_len;
         i++) {
        if (memcmp(&buffer[i],
                   text,
                   text_len) == 0) {
            return true;
        }
    }

    return false;
}

static bool is_pem_certificate(
    const uint8_t *certificate,
    size_t certificate_len)
{
    return contains_text(
        certificate,
        certificate_len,
        "-----BEGIN CERTIFICATE-----");
}

static bool is_pem_private_key(
    const uint8_t *private_key,
    size_t private_key_len)
{
    return contains_text(
               private_key,
               private_key_len,
               "-----BEGIN PRIVATE KEY-----") ||
           contains_text(
               private_key,
               private_key_len,
               "-----BEGIN EC PRIVATE KEY-----") ||
           contains_text(
               private_key,
               private_key_len,
               "-----BEGIN RSA PRIVATE KEY-----");
}

static uint64_t current_ntp_seconds(void)
{
    ntp_timestamp_t timestamp;

    app_state_get_ntp_timestamp(&timestamp);

    return timestamp.seconds;
}

esp_err_t nts_provisioning_store_certificate(
    const uint8_t *certificate_pem,
    size_t certificate_pem_len)
{
    if (certificate_pem == NULL ||
        certificate_pem_len == 0U ||
        !is_pem_certificate(
            certificate_pem,
            certificate_pem_len)) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_status_t psa_result =
        psa_crypto_init();

    if (psa_result != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    mbedtls_x509_crt certificate_chain;
    mbedtls_x509_crt_init(&certificate_chain);

    int result = mbedtls_x509_crt_parse(
        &certificate_chain,
        certificate_pem,
        certificate_pem_len);

    mbedtls_x509_crt_free(
        &certificate_chain);

    if (result != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = key_store_init();

    if (err != ESP_OK) {
        return err;
    }

    return key_store_save_tls_certificate(
        certificate_pem,
        certificate_pem_len);
}

esp_err_t nts_provisioning_store_private_key(
    const uint8_t *private_key_pem,
    size_t private_key_pem_len)
{
    if (private_key_pem == NULL ||
        private_key_pem_len == 0U ||
        !is_pem_private_key(
            private_key_pem,
            private_key_pem_len)) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_status_t psa_result =
        psa_crypto_init();

    if (psa_result != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    mbedtls_pk_context private_key;
    mbedtls_pk_init(&private_key);

    int result = mbedtls_pk_parse_key(
        &private_key,
        private_key_pem,
        private_key_pem_len,
        NULL,
        0U);

    mbedtls_pk_free(&private_key);

    if (result != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    esp_err_t err = key_store_init();

    if (err != ESP_OK) {
        return err;
    }

    return key_store_save_tls_private_key(
        private_key_pem,
        private_key_pem_len);
}

esp_err_t nts_provisioning_ensure_cookie_ring(void)
{
    esp_err_t err = key_store_init();

    if (err != ESP_OK) {
        return err;
    }

    key_store_cookie_keyring_t keyring;

    err = key_store_load_cookie_keyring(
        &keyring);

    if (err == ESP_OK) {
        bool active_valid =
            keyring.slots[
                KEY_STORE_SLOT_ACTIVE].valid != 0U;

        bool next_valid =
            keyring.slots[
                KEY_STORE_SLOT_NEXT].valid != 0U;

        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        if (active_valid && next_valid) {
            return ESP_OK;
        }
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    memset(&keyring, 0, sizeof(keyring));

    uint64_t now_ntp =
        current_ntp_seconds();

    key_store_cookie_key_t *active =
        &keyring.slots[
            KEY_STORE_SLOT_ACTIVE];

    active->key_id = 1U;
    active->not_before_ntp = now_ntp;
    active->not_after_ntp =
        now_ntp +
        NTS_COOKIE_KEY_VALIDITY_SECONDS;

    esp_fill_random(
        active->key,
        sizeof(active->key));

    active->valid = 1U;

    key_store_cookie_key_t *next =
        &keyring.slots[
            KEY_STORE_SLOT_NEXT];

    next->key_id = 2U;

    next->not_before_ntp =
        now_ntp +
        NTS_COOKIE_KEY_VALIDITY_SECONDS;

    next->not_after_ntp =
        now_ntp +
        (2ULL * NTS_COOKIE_KEY_VALIDITY_SECONDS);

    esp_fill_random(
        next->key,
        sizeof(next->key));

    next->valid = 1U;

    err = key_store_save_cookie_keyring(
        &keyring);

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    return err;
}

esp_err_t nts_provisioning_finalize(void)
{
    nts_provisioning_status_t status;

    esp_err_t err =
        nts_provisioning_get_status(&status);

    if (err != ESP_OK) {
        return err;
    }

    if (!status.certificate_present ||
        !status.private_key_present) {
        return ESP_ERR_INVALID_STATE;
    }

    return nts_provisioning_ensure_cookie_ring();
}

esp_err_t nts_provisioning_get_status(
    nts_provisioning_status_t *status)
{
    if (status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(status, 0, sizeof(*status));

    esp_err_t err = key_store_init();

    if (err != ESP_OK) {
        return err;
    }

    size_t certificate_length = 0U;

    err = key_store_load_tls_certificate(
        NULL,
        &certificate_length);

    if (err == ESP_OK) {
        status->certificate_present = true;
        status->certificate_length =
            certificate_length;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    size_t private_key_length = 0U;

    err = key_store_load_tls_private_key(
        NULL,
        &private_key_length);

    if (err == ESP_OK) {
        status->private_key_present = true;
        status->private_key_length =
            private_key_length;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    key_store_cookie_keyring_t keyring;
    memset(&keyring, 0, sizeof(keyring));

    err = key_store_load_cookie_keyring(
        &keyring);

    if (err == ESP_OK) {
        status->cookie_ring_present =
            keyring.slots[
                KEY_STORE_SLOT_ACTIVE].valid != 0U;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return err;
    }

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    return ESP_OK;
}