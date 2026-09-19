#include "acme_storage.h"

#include <stdbool.h>
#include <string.h>

#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "ACME_STORE";

#define ACME_NVS_PARTITION "nvs_certs"
#define ACME_NVS_NAMESPACE "acme"
#define ACME_NVS_KEY_PRIV  "acct_key"
#define ACME_NVS_KEY_KID   "acct_url"

static SemaphoreHandle_t s_lock;
static bool s_initialized;

static esp_err_t ensure_lock(void)
{
    if (s_lock != NULL) {
        return ESP_OK;
    }

    s_lock = xSemaphoreCreateMutex();
    return s_lock != NULL ? ESP_OK : ESP_ERR_NO_MEM;
}

static esp_err_t init_locked(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    /*
     * The flash-encryption based NVS scheme stores its XTS keys in nvs_keys.
     * Without hardware flash encryption those keys would not be protected.
     * Fail closed instead of silently creating plaintext long-term secrets.
     */
    if (!esp_flash_encryption_enabled()) {
        ESP_LOGE(TAG,
                 "Refusing ACME key-store initialization: flash encryption is not active");
        return ESP_ERR_INVALID_STATE;
    }

    const esp_partition_t *keys =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                 ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS,
                                 "nvs_keys");
    if (keys == NULL) {
        ESP_LOGE(TAG, "nvs_keys partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    nvs_sec_cfg_t security = {0};
    esp_err_t err = nvs_flash_read_security_cfg(keys, &security);

    if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
        ESP_LOGI(TAG, "Generating NVS encryption keys for ACME secret storage");
        err = nvs_flash_generate_keys(keys, &security);
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to obtain NVS encryption keys: %s",
                 esp_err_to_name(err));
        memset(&security, 0, sizeof(security));
        return err;
    }

    err = nvs_flash_secure_init_partition(ACME_NVS_PARTITION, &security);
    memset(&security, 0, sizeof(security));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to initialize encrypted %s partition: %s",
                 ACME_NVS_PARTITION, esp_err_to_name(err));
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READWRITE,
                                  &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Unable to open ACME NVS namespace: %s",
                 esp_err_to_name(err));
        return err;
    }
    nvs_close(handle);

    s_initialized = true;
    ESP_LOGI(TAG, "Encrypted ACME secret store ready in %s", ACME_NVS_PARTITION);
    return ESP_OK;
}

esp_err_t acme_storage_init(void)
{
    esp_err_t err = ensure_lock();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    err = init_locked();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t acme_storage_get_status(acme_storage_status_t *out_status)
{
    if (out_status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out_status, 0, sizeof(*out_status));

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);

    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READONLY,
                                  &handle);
    if (err == ESP_OK) {
        size_t key_size = 0U;
        esp_err_t key_err = nvs_get_blob(handle, ACME_NVS_KEY_PRIV,
                                         NULL, &key_size);
        out_status->private_key_present =
            key_err == ESP_OK &&
            key_size == ACME_ACCOUNT_PRIVATE_KEY_LENGTH;

        size_t url_size = sizeof(out_status->account_url);
        esp_err_t url_err = nvs_get_str(handle, ACME_NVS_KEY_KID,
                                        out_status->account_url, &url_size);
        out_status->account_url_present =
            url_err == ESP_OK &&
            out_status->account_url[0] != '\0';

        out_status->initialized = true;
        nvs_close(handle);
    }

    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t acme_storage_load_private_key(
    uint8_t private_key[ACME_ACCOUNT_PRIVATE_KEY_LENGTH])
{
    if (private_key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READONLY,
                                  &handle);
    if (err == ESP_OK) {
        size_t size = ACME_ACCOUNT_PRIVATE_KEY_LENGTH;
        err = nvs_get_blob(handle, ACME_NVS_KEY_PRIV, private_key, &size);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_ERR_NOT_FOUND;
        }
        if (err == ESP_OK && size != ACME_ACCOUNT_PRIVATE_KEY_LENGTH) {
            memset(private_key, 0, ACME_ACCOUNT_PRIVATE_KEY_LENGTH);
            err = ESP_ERR_INVALID_SIZE;
        }
        nvs_close(handle);
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t acme_storage_store_private_key(
    const uint8_t private_key[ACME_ACCOUNT_PRIVATE_KEY_LENGTH])
{
    if (private_key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READWRITE,
                                  &handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, ACME_NVS_KEY_PRIV, private_key,
                           ACME_ACCOUNT_PRIVATE_KEY_LENGTH);
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t acme_storage_load_account_url(char *account_url,
                                        size_t account_url_size)
{
    if (account_url == NULL || account_url_size < 2U) {
        return ESP_ERR_INVALID_ARG;
    }
    account_url[0] = '\0';

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READONLY,
                                  &handle);
    if (err == ESP_OK) {
        size_t size = account_url_size;
        err = nvs_get_str(handle, ACME_NVS_KEY_KID, account_url, &size);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_ERR_NOT_FOUND;
        }
        nvs_close(handle);
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t acme_storage_store_account_url(const char *account_url)
{
    if (account_url == NULL ||
        strncmp(account_url, "https://", 8U) != 0 ||
        strlen(account_url) >= ACME_ACCOUNT_URL_MAX_LENGTH) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    nvs_handle_t handle;
    err = nvs_open_from_partition(ACME_NVS_PARTITION,
                                  ACME_NVS_NAMESPACE,
                                  NVS_READWRITE,
                                  &handle);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, ACME_NVS_KEY_KID, account_url);
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
    }
    xSemaphoreGive(s_lock);
    return err;
}
