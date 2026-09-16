#include "key_store.h"
#include <string.h>
#include "app_config.h"
#include "app_state.h"
#include "ntp_types.h"
#include "esp_random.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "KEY_STORE";

#define KEY_STORE_COOKIE_RING_NAME     "nts_cookie_ring"
#define KEY_STORE_TLS_CERT_NAME        "tls_server_cert"
#define KEY_STORE_TLS_KEY_NAME         "tls_server_key"
#define KEY_STORE_GATEWAY_KEY_NAME     "gateway_pubkey"

static esp_err_t key_store_open(
    nvs_open_mode_t mode,
    nvs_handle_t *handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    return nvs_open_from_partition(
        APP_CERT_PARTITION_LABEL,
        APP_NVS_NAMESPACE,
        mode,
        handle);
}

void key_store_zeroize(
    void *buffer,
    size_t length)
{
    if (buffer == NULL || length == 0U) {
        return;
    }

    volatile uint8_t *ptr =
        (volatile uint8_t *)buffer;

    while (length-- > 0U) {
        *ptr++ = 0U;
    }
}

esp_err_t key_store_init(void)
{
    ESP_LOGI(TAG,
             "Initializing protected NVS partition '%s'",
             APP_CERT_PARTITION_LABEL);

    const esp_partition_t *partition =
        esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA,
            ESP_PARTITION_SUBTYPE_DATA_NVS,
            APP_CERT_PARTITION_LABEL);

    if (partition == NULL) {
        ESP_LOGE(TAG,
                 "Partition '%s' not found",
                 APP_CERT_PARTITION_LABEL);

        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG,
             "Found '%s': offset=0x%lx size=0x%lx",
             partition->label,
             (unsigned long)partition->address,
             (unsigned long)partition->size);

    esp_err_t err =
        nvs_flash_init_partition(
            APP_CERT_PARTITION_LABEL);

    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG,
                 "Protected NVS needs maintenance: %s",
                 esp_err_to_name(err));

        return err;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Protected NVS init failed: %s",
                 esp_err_to_name(err));

        return err;
    }

    nvs_handle_t handle;

    err = key_store_open(
        NVS_READWRITE,
        &handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Protected NVS open failed: %s",
                 esp_err_to_name(err));

        return err;
    }

    nvs_close(handle);

    ESP_LOGI(TAG,
             "Protected NVS ready");

    return ESP_OK;
}

esp_err_t key_store_load_blob(
    const char *name,
    void *buffer,
    size_t *buffer_len)
{
    if (name == NULL || buffer_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;

    esp_err_t err = key_store_open(
        NVS_READONLY,
        &handle);

    if (err != ESP_OK) {
        return err;
    }

    size_t required_len = 0U;

    err = nvs_get_blob(
        handle,
        name,
        NULL,
        &required_len);

    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (buffer == NULL) {
        *buffer_len = required_len;

        nvs_close(handle);

        return ESP_OK;
    }

    if (*buffer_len < required_len) {
        *buffer_len = required_len;

        nvs_close(handle);

        return ESP_ERR_NVS_INVALID_LENGTH;
    }

    err = nvs_get_blob(
        handle,
        name,
        buffer,
        &required_len);

    if (err == ESP_OK) {
        *buffer_len = required_len;
    }

    nvs_close(handle);

    return err;
}

esp_err_t key_store_save_blob(
    const char *name,
    const void *buffer,
    size_t buffer_len)
{
    if (name == NULL ||
        buffer == NULL ||
        buffer_len == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;

    esp_err_t err = key_store_open(
        NVS_READWRITE,
        &handle);

    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(
        handle,
        name,
        buffer,
        buffer_len);

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    return err;
}

esp_err_t key_store_erase_blob(
    const char *name)
{
    if (name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;

    esp_err_t err = key_store_open(
        NVS_READWRITE,
        &handle);

    if (err != ESP_OK) {
        return err;
    }

    err = nvs_erase_key(handle, name);

    if (err == ESP_OK ||
        err == ESP_ERR_NVS_NOT_FOUND) {
        esp_err_t commit_err =
            nvs_commit(handle);

        if (commit_err != ESP_OK) {
            err = commit_err;
        }
    }

    nvs_close(handle);

    return err;
}

esp_err_t key_store_load_cookie_keyring(
    key_store_cookie_keyring_t *keyring)
{
    if (keyring == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t length = sizeof(*keyring);

    esp_err_t err = key_store_load_blob(
        KEY_STORE_COOKIE_RING_NAME,
        keyring,
        &length);

    if (err != ESP_OK) {
        return err;
    }

    if (length != sizeof(*keyring)) {
        key_store_zeroize(
            keyring,
            sizeof(*keyring));

        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

esp_err_t key_store_save_cookie_keyring(
    const key_store_cookie_keyring_t *keyring)
{
    if (keyring == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    return key_store_save_blob(
        KEY_STORE_COOKIE_RING_NAME,
        keyring,
        sizeof(*keyring));
}

esp_err_t key_store_load_tls_certificate(
    uint8_t *buffer,
    size_t *buffer_len)
{
    return key_store_load_blob(
        KEY_STORE_TLS_CERT_NAME,
        buffer,
        buffer_len);
}

esp_err_t key_store_load_tls_private_key(
    uint8_t *buffer,
    size_t *buffer_len)
{
    return key_store_load_blob(
        KEY_STORE_TLS_KEY_NAME,
        buffer,
        buffer_len);
}

esp_err_t key_store_load_gateway_public_key(
    uint8_t *buffer,
    size_t *buffer_len)
{
    return key_store_load_blob(
        KEY_STORE_GATEWAY_KEY_NAME,
        buffer,
        buffer_len);
}

esp_err_t key_store_save_tls_certificate(
    const uint8_t *buffer,
    size_t buffer_len)
{
    return key_store_save_blob(
        KEY_STORE_TLS_CERT_NAME,
        buffer,
        buffer_len);
}

esp_err_t key_store_save_tls_private_key(
    const uint8_t *buffer,
    size_t buffer_len)
{
    return key_store_save_blob(
        KEY_STORE_TLS_KEY_NAME,
        buffer,
        buffer_len);
}

esp_err_t key_store_ensure_cookie_keyring(void)
{
    key_store_cookie_keyring_t keyring;

    esp_err_t err = key_store_load_cookie_keyring(
        &keyring);

    if (err == ESP_OK) {
        key_store_zeroize(
            &keyring,
            sizeof(keyring));

        return ESP_OK;
    }

    if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    memset(&keyring, 0, sizeof(keyring));

    ntp_timestamp_t now;
    app_state_get_ntp_timestamp(&now);

    keyring.slots[KEY_STORE_SLOT_ACTIVE].key_id = 1U;
    keyring.slots[KEY_STORE_SLOT_ACTIVE].not_before_ntp =
        now.seconds;

    keyring.slots[KEY_STORE_SLOT_ACTIVE].not_after_ntp =
        now.seconds + (30ULL * 24ULL * 3600ULL);

    esp_fill_random(
        keyring.slots[KEY_STORE_SLOT_ACTIVE].key,
        KEY_STORE_COOKIE_KEY_LEN);

    keyring.slots[KEY_STORE_SLOT_ACTIVE].valid = 1U;

    keyring.slots[KEY_STORE_SLOT_NEXT].key_id = 2U;
    keyring.slots[KEY_STORE_SLOT_NEXT].not_before_ntp =
        now.seconds + (30ULL * 24ULL * 3600ULL);

    keyring.slots[KEY_STORE_SLOT_NEXT].not_after_ntp =
        now.seconds + (60ULL * 24ULL * 3600ULL);

    esp_fill_random(
        keyring.slots[KEY_STORE_SLOT_NEXT].key,
        KEY_STORE_COOKIE_KEY_LEN);

    keyring.slots[KEY_STORE_SLOT_NEXT].valid = 1U;

    err = key_store_save_cookie_keyring(&keyring);

    key_store_zeroize(
        &keyring,
        sizeof(keyring));

    return err;
}