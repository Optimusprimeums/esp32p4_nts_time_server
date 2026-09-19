#include "nts_storage.h"

#include <stdbool.h>
#include <string.h>

#include "acme_storage.h"
#include "clock_discipline.h"

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"

static const char *TAG = "NTS_STORE";

#define NTS_STORAGE_NVS_PARTITION   "nvs_certs"
#define NTS_STORAGE_NVS_NAMESPACE   "nts"
#define NTS_STORAGE_COOKIE_RING_KEY "cookie_ring"

#define NTS_STORAGE_KEY_PERIOD_SECONDS \
    (30ULL * 24ULL * 3600ULL)

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
     * acme_storage_init() is the production owner of secure initialization
     * for the encrypted nvs_certs partition. Reuse that established path
     * rather than independently initializing the partition here.
     */
    esp_err_t err = acme_storage_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Protected partition initialization failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open_from_partition(NTS_STORAGE_NVS_PARTITION,
                                  NTS_STORAGE_NVS_NAMESPACE,
                                  NVS_READWRITE,
                                  &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Unable to open NTS NVS namespace: %s",
                 esp_err_to_name(err));
        return err;
    }

    nvs_close(handle);

    s_initialized = true;
    ESP_LOGI(TAG,
             "Encrypted NTS secret store ready in %s/%s",
             NTS_STORAGE_NVS_PARTITION,
             NTS_STORAGE_NVS_NAMESPACE);

    return ESP_OK;
}

static bool slot_valid_value(
    const nts_storage_cookie_key_t *slot)
{
    return slot != NULL &&
           (slot->valid == 0U || slot->valid == 1U);
}

static bool populated_slot_valid(
    const nts_storage_cookie_key_t *slot)
{
    return slot != NULL &&
           slot->valid == 1U &&
           slot->key_id != 0U &&
           slot->not_before_ntp < slot->not_after_ntp;
}

static bool key_ids_distinct(
    const nts_storage_cookie_keyring_t *keyring)
{
    for (size_t i = 0U;
         i < NTS_STORAGE_COOKIE_KEY_SLOTS;
         i++) {
        if (keyring->slots[i].valid == 0U) {
            continue;
        }

        for (size_t j = i + 1U;
             j < NTS_STORAGE_COOKIE_KEY_SLOTS;
             j++) {
            if (keyring->slots[j].valid != 0U &&
                keyring->slots[i].key_id ==
                    keyring->slots[j].key_id) {
                return false;
            }
        }
    }

    return true;
}

static esp_err_t validate_cookie_keyring(
    const nts_storage_cookie_keyring_t *keyring)
{
    if (keyring == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    static const char *slot_names[
        NTS_STORAGE_COOKIE_KEY_SLOTS] = {
        "PREVIOUS",
        "ACTIVE",
        "NEXT"
    };

    for (size_t i = 0U;
         i < NTS_STORAGE_COOKIE_KEY_SLOTS;
         i++) {
        const nts_storage_cookie_key_t *slot =
            &keyring->slots[i];

        ESP_LOGI(
            TAG,
            "Cookie ring %s: valid=%u id=%lu not_before=%llu not_after=%llu",
            slot_names[i],
            (unsigned int)slot->valid,
            (unsigned long)slot->key_id,
            (unsigned long long)slot->not_before_ntp,
            (unsigned long long)slot->not_after_ntp);

        if (!slot_valid_value(slot)) {
            ESP_LOGE(
                TAG,
                "Cookie ring validation: %s valid flag is not 0/1",
                slot_names[i]);
            return ESP_ERR_INVALID_STATE;
        }

        if (slot->valid != 0U &&
            !populated_slot_valid(slot)) {
            ESP_LOGE(
                TAG,
                "Cookie ring validation: %s populated slot is invalid",
                slot_names[i]);
            return ESP_ERR_INVALID_STATE;
        }
    }

    const nts_storage_cookie_key_t *previous =
        &keyring->slots[NTS_STORAGE_SLOT_PREVIOUS];
    const nts_storage_cookie_key_t *active =
        &keyring->slots[NTS_STORAGE_SLOT_ACTIVE];
    const nts_storage_cookie_key_t *next =
        &keyring->slots[NTS_STORAGE_SLOT_NEXT];

    if (!populated_slot_valid(active)) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: ACTIVE slot unavailable");
        return ESP_ERR_INVALID_STATE;
    }

    if (!populated_slot_valid(next)) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: NEXT slot unavailable");
        return ESP_ERR_INVALID_STATE;
    }

    if (!key_ids_distinct(keyring)) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: duplicate key IDs");
        return ESP_ERR_INVALID_STATE;
    }

    if (next->not_before_ntp != active->not_after_ntp) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: NEXT.not_before (%llu) != ACTIVE.not_after (%llu)",
            (unsigned long long)next->not_before_ntp,
            (unsigned long long)active->not_after_ntp);
        return ESP_ERR_INVALID_STATE;
    }

    if (next->not_after_ntp <= next->not_before_ntp) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: NEXT validity interval is invalid");
        return ESP_ERR_INVALID_STATE;
    }

    if (previous->valid != 0U &&
        previous->not_after_ntp != active->not_before_ntp) {
        ESP_LOGE(
            TAG,
            "Cookie ring validation: PREVIOUS.not_after (%llu) != ACTIVE.not_before (%llu)",
            (unsigned long long)previous->not_after_ntp,
            (unsigned long long)active->not_before_ntp);
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_OK;
}

static uint32_t next_key_id(uint32_t current_key_id)
{
    uint32_t result = current_key_id + 1U;

    if (result == 0U) {
        result = 1U;
    }

    return result;
}

static void generate_next_slot(
    nts_storage_cookie_key_t *slot,
    uint32_t key_id,
    uint64_t not_before_ntp)
{
    memset(slot, 0, sizeof(*slot));

    slot->key_id = key_id;
    slot->not_before_ntp = not_before_ntp;
    slot->not_after_ntp =
        not_before_ntp + NTS_STORAGE_KEY_PERIOD_SECONDS;

    esp_fill_random(slot->key,
                    NTS_STORAGE_COOKIE_KEY_LEN);

    slot->valid = 1U;
}

esp_err_t nts_storage_init(void)
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

void nts_storage_zeroize(void *buffer,
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

esp_err_t nts_storage_load_cookie_keyring(
    nts_storage_cookie_keyring_t *keyring)
{
    if (keyring == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nts_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);

    nvs_handle_t handle;
    err = nvs_open_from_partition(NTS_STORAGE_NVS_PARTITION,
                                  NTS_STORAGE_NVS_NAMESPACE,
                                  NVS_READONLY,
                                  &handle);
    if (err == ESP_OK) {
        size_t length = sizeof(*keyring);
        err = nvs_get_blob(handle,
                           NTS_STORAGE_COOKIE_RING_KEY,
                           keyring,
                           &length);

        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_ERR_NOT_FOUND;
        } else if (err == ESP_OK &&
                   length != sizeof(*keyring)) {
            nts_storage_zeroize(
                keyring,
                sizeof(*keyring));
            err = ESP_ERR_INVALID_SIZE;
        }

        nvs_close(handle);
    }

    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t nts_storage_save_cookie_keyring(
    const nts_storage_cookie_keyring_t *keyring)
{
    if (keyring == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nts_storage_init();
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);

    nvs_handle_t handle;
    err = nvs_open_from_partition(NTS_STORAGE_NVS_PARTITION,
                                  NTS_STORAGE_NVS_NAMESPACE,
                                  NVS_READWRITE,
                                  &handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle,
                           NTS_STORAGE_COOKIE_RING_KEY,
                           keyring,
                           sizeof(*keyring));
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }

        nvs_close(handle);
    }

    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t nts_storage_ensure_cookie_keyring(void)
{
    nts_storage_cookie_keyring_t keyring;

    esp_err_t err =
        nts_storage_load_cookie_keyring(&keyring);

    if (err == ESP_OK) {
        err = validate_cookie_keyring(&keyring);
        nts_storage_zeroize(
            &keyring,
            sizeof(keyring));
        return err;
    }

    if (err != ESP_ERR_NOT_FOUND) {
        return err;
    }

    memset(&keyring, 0, sizeof(keyring));

    clock_ntp_timestamp_t now;

    if (!clock_discipline_get_ntp_timestamp(&now)) {
        return ESP_ERR_INVALID_STATE;
    }

    generate_next_slot(
        &keyring.slots[NTS_STORAGE_SLOT_ACTIVE],
        1U,
        (uint64_t)now.seconds);

    generate_next_slot(
        &keyring.slots[NTS_STORAGE_SLOT_NEXT],
        2U,
        keyring.slots[
            NTS_STORAGE_SLOT_ACTIVE].not_after_ntp);

    err = nts_storage_save_cookie_keyring(&keyring);

    nts_storage_zeroize(
        &keyring,
        sizeof(keyring));

    return err;
}

esp_err_t nts_storage_maintain_cookie_keyring(void)
{
    nts_storage_cookie_keyring_t keyring;

    esp_err_t err =
        nts_storage_load_cookie_keyring(&keyring);

    if (err != ESP_OK) {
        return err;
    }

    err = validate_cookie_keyring(&keyring);
    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Cookie keyring validation failed");
        nts_storage_zeroize(
            &keyring,
            sizeof(keyring));
        return err;
    }

    clock_ntp_timestamp_t now;

    if (!clock_discipline_get_ntp_timestamp(&now)) {
        nts_storage_zeroize(
            &keyring,
            sizeof(keyring));
        return ESP_ERR_INVALID_STATE;
    }

    const uint64_t now_ntp =
        (uint64_t)now.seconds;

    bool changed = false;

    while (now_ntp >=
           keyring.slots[
               NTS_STORAGE_SLOT_ACTIVE].not_after_ntp) {
        const nts_storage_cookie_key_t old_active =
            keyring.slots[NTS_STORAGE_SLOT_ACTIVE];

        const nts_storage_cookie_key_t old_next =
            keyring.slots[NTS_STORAGE_SLOT_NEXT];

        keyring.slots[NTS_STORAGE_SLOT_PREVIOUS] =
            old_active;

        keyring.slots[NTS_STORAGE_SLOT_ACTIVE] =
            old_next;

        generate_next_slot(
            &keyring.slots[NTS_STORAGE_SLOT_NEXT],
            next_key_id(old_next.key_id),
            old_next.not_after_ntp);

        changed = true;

        ESP_LOGI(
            TAG,
            "Cookie master key rotated: previous=%lu active=%lu next=%lu",
            (unsigned long)
                keyring.slots[
                    NTS_STORAGE_SLOT_PREVIOUS].key_id,
            (unsigned long)
                keyring.slots[
                    NTS_STORAGE_SLOT_ACTIVE].key_id,
            (unsigned long)
                keyring.slots[
                    NTS_STORAGE_SLOT_NEXT].key_id);
    }

    if (changed) {
        err =
            nts_storage_save_cookie_keyring(
                &keyring);

        if (err != ESP_OK) {
            ESP_LOGE(
                TAG,
                "Cookie keyring rotation persistence failed: %s",
                esp_err_to_name(err));
        }
    }

    nts_storage_zeroize(
        &keyring,
        sizeof(keyring));

    return err;
}
